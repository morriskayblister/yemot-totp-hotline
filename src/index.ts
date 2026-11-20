import { Hono } from "hono";

// Environment: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, PORT (optional)
const SUPABASE_URL = process.env.SUPABASE_URL ?? "";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const MAX_PIN_FAILURES = 3;
const LOCK_MINUTES = 15;

const app = new Hono();

// ---------- Supabase REST helpers (service role, bypasses RLS) ----------
async function sb(path: string, init: RequestInit = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: SUPABASE_KEY,
      Authorization: `Bearer ${SUPABASE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
      ...(init.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`supabase ${res.status}: ${await res.text()}`);
  return res.json();
}

// ---------- PIN hashing (SHA-256 with salt; use a KDF in production) ----------
async function hashPin(pin: string, salt: string): Promise<string> {
  const data = new TextEncoder().encode(`${salt}:${pin}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return `${salt}$${Buffer.from(digest).toString("hex")}`;
}

async function verifyPin(pin: string, stored: string): Promise<boolean> {
  const salt = stored.split("$")[0];
  return (await hashPin(pin, salt)) === stored;
}

// ---------- RFC 6238 TOTP ----------
function base32Decode(input: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.replace(/[\s=-]/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error("invalid base32 secret");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

async function totp(secret: string, digits = 6, period = 30, nowMs = Date.now()): Promise<string> {
  const counter = Math.floor(nowMs / 1000 / period);
  const msg = new ArrayBuffer(8);
  new DataView(msg).setBigUint64(0, BigInt(counter));
  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  const offset = h[h.length - 1] & 0x0f;
  const code =
    ((h[offset] & 0x7f) << 24) |
    ((h[offset + 1] & 0xff) << 16) |
    ((h[offset + 2] & 0xff) << 8) |
    (h[offset + 3] & 0xff);
  return (code % 10 ** digits).toString().padStart(digits, "0");
}

// ---------- DTMF decoding ----------
// Yemot passes keypad input as a string of digits; "*" and "#" are control keys.
export function decodeDtmf(raw: string | undefined): { digits: string; terminator: "#" | null } {
  const value = (raw ?? "").trim();
  const terminator = value.endsWith("#") ? "#" : null;
  const digits = value.replace(/[^0-9]/g, "");
  return { digits, terminator };
}

// ---------- Yemot response helpers ----------
// Yemot expects plain-text lines; each line is one IVR instruction.
function ivr(...lines: string[]) {
  return new Response(lines.join("\n"), { headers: { "Content-Type": "text/plain; charset=utf-8" } });
}

function say(text: string) {
  return `id_list_message=t-${text}`;
}

// ---------- IVR flow ----------
// Query params from Yemot: ApiPhone (caller), val (DTMF input), step (flow step), slot (account slot)
app.get("/yemot", async (c) => {
  const phone = (c.req.query("ApiPhone") ?? "").replace(/\D/g, "");
  const step = c.req.query("step") ?? "menu";
  const { digits, terminator } = decodeDtmf(c.req.query("val"));

  if (!phone) return ivr(say("Caller ID missing, goodbye"), "hangup=yes");

  const users = await sb(`auth_users?phone_number=eq.${phone}&select=*`);
  let user = users[0];

  // First call: register caller and ask them to set a PIN.
  if (!user) {
    const created = await sb("auth_users", {
      method: "POST",
      body: JSON.stringify({ phone_number: phone }),
    });
    user = created[0];
    return ivr(say("Welcome. Enter a PIN of 4 digits followed by the pound key"), `read=pin_set=sec_pin_set,,,4,4,7,no,,yes,,`);
  }

  if (step === "pin_set") {
    if (digits.length !== 4 || terminator !== "#") return ivr(say("Invalid PIN"), "go_to_folder=/");
    const salt = crypto.randomUUID().slice(0, 8);
    await sb(`auth_users?id=eq.${user.id}`, {
      method: "PATCH",
      body: JSON.stringify({ pin_hash: await hashPin(digits, salt), pin_failures: 0 }),
    });
    return ivr(say("PIN saved"), "go_to_folder=/");
  }

  if (!user.pin_hash) return ivr(say("Please set a PIN first"), "go_to_folder=/");

  if (user.pin_locked_until && new Date(user.pin_locked_until) > new Date()) {
    return ivr(say("Too many attempts, try again later"), "hangup=yes");
  }

  if (step === "pin") {
    if (!(await verifyPin(digits, user.pin_hash))) {
      const failures = (user.pin_failures ?? 0) + 1;
      const lock = failures >= MAX_PIN_FAILURES ? new Date(Date.now() + LOCK_MINUTES * 60_000).toISOString() : null;
      await sb(`auth_users?id=eq.${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({ pin_failures: lock ? 0 : failures, pin_locked_until: lock }),
      });
      return ivr(say("Wrong PIN"), "go_to_folder=/");
    }
    await sb(`auth_users?id=eq.${user.id}`, { method: "PATCH", body: JSON.stringify({ pin_failures: 0 }) });
    return ivr(say("Press 1 for codes, 2 to add an account"), "read=menu=sec_menu,,,1,1,7,no,,yes,,");
  }

  // Menu / code flow
  if (step === "menu") {
    return ivr(say("Enter your PIN followed by the pound key"), "read=pin=sec_pin,,,4,4,7,no,,yes,,");
  }

  if (step === "code") {
    const slot = Number(c.req.query("slot") ?? "");
    const accounts = await sb(`totp_accounts?user_id=eq.${user.id}&slot_number=eq.${slot}&select=*`);
    if (!accounts[0]) return ivr(say("No account in that slot"), "go_to_folder=/");
    const code = await totp(accounts[0].totp_secret, accounts[0].digits, accounts[0].period);
    return ivr(say(`Your code is ${code.split("").join(" ")}`), "go_to_folder=/");
  }

  return ivr(say("Goodbye"), "hangup=yes");
});

app.get("/health", (c) => c.json({ ok: true }));

export default {
  port: Number(process.env.PORT ?? 3000),
  fetch: app.fetch,
};
