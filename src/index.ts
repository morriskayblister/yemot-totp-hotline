import { Hono, type Context } from "hono";

// Environment: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, PORT (optional)
const SUPABASE_URL = process.env.SUPABASE_URL ?? "";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const MAX_PIN_FAILURES = 3;
const LOCK_MINUTES = 15;

const app = new Hono();

// ---------- Request logging ----------
app.use("*", async (c, next) => {
  const started = Date.now();
  await next();
  console.log(
    JSON.stringify({
      ev: "request",
      method: c.req.method,
      path: c.req.path,
      query: c.req.queries(),
      status: c.res.status,
      ms: Date.now() - started,
      ip: c.req.header("x-forwarded-for") ?? null,
      ua: c.req.header("user-agent") ?? null,
    }),
  );
});

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
  const body = lines.join("\n");
  console.log(JSON.stringify({ ev: "yemot_response", body }));
  return new Response(body, { headers: { "Content-Type": "text/plain; charset=utf-8" } });
}

function say(text: string) {
  return `id_list_message=t-${text}`;
}

// Yemot read command:
// read=t-<prompt>=<varName>,<timeout>,<min>,<max>,<digits_type>,<voice>,<file>,<enter_if_empty>
// Yemot calls this same URL again with the entered digits in a query parameter named <varName>.
function readCmd(prompt: string, varName: string, min: number, max: number, timeout = 10) {
  const safePrompt = prompt.replace(/[,=]/g, " ");
  return `read=t-${safePrompt}=${varName},${timeout},${min},${max},SecDigits,no,,yes`;
}

// ---------- IVR flow ----------
// Query params from Yemot: ApiPhone (caller). Read results come back as params named after the read variable:
// pin_set (new PIN), pin (login PIN), menu (menu choice), slot (account slot).
async function handleYemot(c: Context) {
  const phone = (c.req.query("ApiPhone") ?? "").replace(/\D/g, "");
  if (!phone) return ivr(say("Caller ID missing, goodbye"), "hangup=yes");

  const users = await sb(`auth_users?phone_number=eq.${phone}&select=*`);
  let user = users[0];
  if (!user) {
    const created = await sb("auth_users", {
      method: "POST",
      body: JSON.stringify({ phone_number: phone }),
    });
    user = created[0];
  }

  // PIN not set yet (new caller, or existing row with empty pin_hash): set it right here.
  if (!user.pin_hash) {
    const entered = c.req.query("pin_set");
    if (entered !== undefined) {
      const { digits } = decodeDtmf(entered);
      if (digits.length !== 4) {
        return ivr(say("Invalid PIN"), readCmd("Please choose a 4 digit PIN followed by pound", "pin_set", 4, 4));
      }
      const salt = crypto.randomUUID().slice(0, 8);
      await sb(`auth_users?id=eq.${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({ pin_hash: await hashPin(digits, salt), pin_failures: 0, pin_locked_until: null }),
      });
      return ivr(say("PIN saved"), readCmd("Press 1 for codes, 2 to add an account", "menu", 1, 1));
    }
    return ivr(readCmd("Welcome. Please choose a 4 digit PIN followed by pound", "pin_set", 4, 4));
  }

  if (user.pin_locked_until && new Date(user.pin_locked_until) > new Date()) {
    return ivr(say("Too many attempts, try again later"), "hangup=yes");
  }

  // Login PIN entered
  const pinIn = c.req.query("pin");
  if (pinIn !== undefined) {
    const { digits } = decodeDtmf(pinIn);
    if (!(await verifyPin(digits, user.pin_hash))) {
      const failures = (user.pin_failures ?? 0) + 1;
      const lock = failures >= MAX_PIN_FAILURES ? new Date(Date.now() + LOCK_MINUTES * 60_000).toISOString() : null;
      await sb(`auth_users?id=eq.${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({ pin_failures: lock ? 0 : failures, pin_locked_until: lock }),
      });
      if (lock) return ivr(say("Too many attempts, try again later"), "hangup=yes");
      return ivr(say("Wrong PIN"), readCmd("Enter your PIN followed by pound", "pin", 4, 4));
    }
    await sb(`auth_users?id=eq.${user.id}`, { method: "PATCH", body: JSON.stringify({ pin_failures: 0 }) });
    return ivr(readCmd("Press 1 for codes, 2 to add an account", "menu", 1, 1));
  }

  // Menu choice
  const menuIn = c.req.query("menu");
  if (menuIn !== undefined) {
    const choice = decodeDtmf(menuIn).digits;
    if (choice === "1") return ivr(readCmd("Enter the account slot", "slot", 1, 2));
    if (choice === "2") return ivr(say("Adding accounts by phone is not available yet"), "hangup=yes");
    return ivr(say("Invalid choice"), "hangup=yes");
  }

  // Account slot chosen: read the TOTP code
  const slotIn = c.req.query("slot");
  if (slotIn !== undefined) {
    const slot = Number(decodeDtmf(slotIn).digits);
    const accounts = await sb(`totp_accounts?user_id=eq.${user.id}&slot_number=eq.${slot}&select=*`);
    if (!accounts[0]) return ivr(say("No account in that slot"), "hangup=yes");
    const code = await totp(accounts[0].totp_secret, accounts[0].digits, accounts[0].period);
    return ivr(say(`Your code is ${code.split("").join(" ")}`), "hangup=yes");
  }

  // Default: ask for PIN
  return ivr(readCmd("Enter your PIN followed by pound", "pin", 4, 4));
}

app.get("/yemot", async (c) => {
  try {
    return await handleYemot(c);
  } catch (err) {
    console.error(JSON.stringify({ ev: "error", message: String(err) }));
    return ivr(say("System error, please try again later"), "hangup=yes");
  }
});

app.get("/health", (c) => c.json({ ok: true }));

export default {
  port: Number(process.env.PORT ?? 3000),
  fetch: app.fetch,
};
