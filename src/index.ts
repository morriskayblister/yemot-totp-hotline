import { Hono, type Context } from "hono";

// Environment: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, PORT (optional)
const SUPABASE_URL = process.env.SUPABASE_URL ?? "";
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const MAX_PIN_FAILURES = 3;
const LOCK_MINUTES = 15;
const SESSION_TTL_MS = 15 * 60_000;

type Row = Record<string, any>;

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
    }),
  );
});

// ---------- In-memory call sessions (keyed by Yemot ApiCallId; lost on restart) ----------
type CallSession = { phone: string; authed: boolean; time: number };
const callSessions = new Map<string, CallSession>();

function sweepSessions(now: number): void {
  for (const [id, s] of callSessions) {
    if (now - s.time > SESSION_TTL_MS) callSessions.delete(id);
  }
}

function callId(c: Context): string {
  return c.req.query("ApiCallId") ?? "";
}

// True when this call was authenticated and its session has not expired. Each check slides the expiry.
function isAuthed(c: Context): boolean {
  const now = Date.now();
  sweepSessions(now);
  const s = callSessions.get(callId(c));
  if (!s || !s.authed) return false;
  s.time = now;
  return true;
}

function markAuthed(c: Context, phone: string): void {
  callSessions.set(callId(c), { phone, authed: true, time: Date.now() });
}

// ---------- Supabase REST helpers (service role, bypasses RLS) ----------
async function sb(path: string, init: RequestInit = {}): Promise<any> {
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

// Loads the caller's row, creating it on first contact.
async function loadUser(phone: string): Promise<Row> {
  const users: Row[] = await sb(`auth_users?phone_number=eq.${phone}&select=*`);
  if (users[0]) return users[0];
  const created: Row[] = await sb("auth_users", {
    method: "POST",
    body: JSON.stringify({ phone_number: phone }),
  });
  return created[0];
}

// ---------- PIN hashing (SHA-256 with salt; use a KDF in production) ----------
async function hashPin(pin: string, salt: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${salt}:${pin}`));
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
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, [
    "sign",
  ]);
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  const offset = h[h.length - 1] & 0x0f;
  const code =
    ((h[offset] & 0x7f) << 24) | ((h[offset + 1] & 0xff) << 16) | ((h[offset + 2] & 0xff) << 8) | (h[offset + 3] & 0xff);
  return (code % 10 ** digits).toString().padStart(digits, "0");
}

// ---------- DTMF decoding ----------
export function decodeDtmf(raw: string | undefined): { digits: string; terminator: "#" | null } {
  const value = (raw ?? "").trim();
  return { digits: value.replace(/[^0-9]/g, ""), terminator: value.endsWith("#") ? "#" : null };
}

// ---------- Yemot response helpers ----------
// Yemot chains instructions in one response with "&".
function ivr(...lines: string[]): Response {
  const body = lines.join("&");
  console.log(JSON.stringify({ ev: "yemot_response", body }));
  return new Response(body, { headers: { "Content-Type": "text/plain; charset=utf-8" } });
}

function say(text: string): string {
  return `id_list_message=t-${text}`;
}

function hangup(): string {
  return "hangup=yes";
}

// Yemot read command. Field order from the official API doc:
// 1 val_name, 2 re_enter_if_exists, 3 max, 4 min, 5 timeout, 6 typing_playback_mode,
// 7 block_asterisk, 8 block_zero, 9-14 defaults, 15 request_confirmation (no).
// Yemot calls the same URL again with the entered digits in a param named <val_name>.
function readCmd(prompt: string, valName: string, opts: { min: number; max: number; timeout?: number }): string {
  const safePrompt = prompt.replace(/[,=&]/g, " ");
  return `read=t-${safePrompt}=${valName},no,${opts.max},${opts.min},${opts.timeout ?? 10},No,no,no,,,,,,,no`;
}

// Yemot accumulates earlier answers in later requests, so a param can be an array. The last element is newest.
function all(c: Context, name: string): string[] {
  return c.req.queries(name) ?? [];
}

function latest(c: Context, name: string): string | undefined {
  const list = all(c, name);
  return list.length ? list[list.length - 1] : undefined;
}

function callerPhone(c: Context): string {
  return (c.req.query("ApiPhone") ?? "").replace(/\D/g, "");
}

const TEXT_HEADERS = { "Content-Type": "text/plain; charset=utf-8" };

// Wraps every Yemot route: handles hangup, catches errors, and never leaves the caller without a reply.
function yemotRoute(path: string, handler: (c: Context) => Promise<Response>): void {
  app.get(path, async (c) => {
    try {
      if (c.req.query("hangup") === "yes") {
        callSessions.delete(callId(c));
        console.log(JSON.stringify({ ev: "hangup", path }));
        return new Response("", { headers: TEXT_HEADERS });
      }
      return await handler(c);
    } catch (err) {
      console.error(JSON.stringify({ ev: "error", path, message: String(err) }));
      return ivr(say("שגיאת מערכת, נסו שוב מאוחר יותר"), hangup());
    }
  });
}

// ---------- Root /yemot: gate into the system ----------
yemotRoute("/yemot", async (c) => {
  return ivr(isAuthed(c) ? "go_to_folder=/1" : "go_to_folder=/99");
});

// ---------- Extension 99: router by PIN state ----------
yemotRoute("/yemot/ext99", async (c) => {
  const phone = callerPhone(c);
  if (!phone) return ivr(say("מספר המתקשר אינו זמין, להתראות"), hangup());
  const user = await loadUser(phone);
  return ivr(user.pin_hash ? "go_to_folder=/998" : "go_to_folder=/999");
});

// ---------- Extension 998: verify existing PIN ----------
yemotRoute("/yemot/ext998", async (c) => {
  const phone = callerPhone(c);
  if (!phone) return ivr(say("מספר המתקשר אינו זמין, להתראות"), hangup());
  const user = await loadUser(phone);
  if (!user.pin_hash) return ivr("go_to_folder=/999");

  if (user.pin_locked_until && new Date(user.pin_locked_until) > new Date()) {
    return ivr(say("יותר מדי ניסיונות, נסו שוב מאוחר יותר"), hangup());
  }

  const entered = latest(c, "val_pin");
  if (entered === undefined) {
    return ivr(readCmd("אנא הקש קוד סודי", "val_pin", { min: 4, max: 4 }));
  }

  const { digits } = decodeDtmf(entered);
  if (digits.length === 4 && (await verifyPin(digits, user.pin_hash))) {
    await sb(`auth_users?id=eq.${user.id}`, {
      method: "PATCH",
      body: JSON.stringify({ pin_failures: 0, pin_locked_until: null }),
    });
    markAuthed(c, phone);
    return ivr("go_to_folder=/1");
  }

  const failures = (user.pin_failures ?? 0) + 1;
  const lock = failures >= MAX_PIN_FAILURES ? new Date(Date.now() + LOCK_MINUTES * 60_000).toISOString() : null;
  await sb(`auth_users?id=eq.${user.id}`, {
    method: "PATCH",
    body: JSON.stringify({ pin_failures: lock ? 0 : failures, pin_locked_until: lock }),
  });
  if (lock) return ivr(say("יותר מדי ניסיונות, נסו שוב מאוחר יותר"), hangup());
  return ivr(say("הקוד שגוי"), readCmd("אנא הקש קוד סודי", "val_pin", { min: 4, max: 4 }));
});

// ---------- Extension 999: set up a new PIN ----------
yemotRoute("/yemot/ext999", async (c) => {
  const phone = callerPhone(c);
  if (!phone) return ivr(say("מספר המתקשר אינו זמין, להתראות"), hangup());
  const user = await loadUser(phone);
  if (user.pin_hash) return ivr("go_to_folder=/998");

  const entered = latest(c, "val_pin");
  if (entered === undefined) {
    return ivr(readCmd("שלום אנא בחר קוד סודי בן 4 ספרות", "val_pin", { min: 4, max: 4 }));
  }

  const { digits } = decodeDtmf(entered);
  if (digits.length !== 4) {
    return ivr(say("קוד לא תקין"), readCmd("אנא בחר קוד סודי בן 4 ספרות", "val_pin", { min: 4, max: 4 }));
  }

  const salt = crypto.randomUUID().slice(0, 8);
  await sb(`auth_users?id=eq.${user.id}`, {
    method: "PATCH",
    body: JSON.stringify({ pin_hash: await hashPin(digits, salt), pin_failures: 0, pin_locked_until: null }),
  });
  markAuthed(c, phone);
  return ivr(say("הקוד נשמר בהצלחה"), "go_to_folder=/1");
});

// ---------- Extension 1: main menu fallback (native Yemot menu /1 normally handles this) ----------
const MENU_PROMPT = "לקבלת קוד הקש 1, להזנת חשבון חדש הקש 2, למחיקת חשבון הקש 3";

yemotRoute("/yemot/ext1", async (c) => {
  if (!isAuthed(c)) return ivr("go_to_folder=/99");

  const raw = latest(c, "val_menu");
  if (raw === undefined) return ivr(readCmd(MENU_PROMPT, "val_menu", { min: 1, max: 1 }));

  const choice = decodeDtmf(raw).digits;
  if (choice === "1") return ivr("go_to_folder=/1/1");
  if (choice === "2") return ivr("go_to_folder=/1/2");
  if (choice === "3") return ivr("go_to_folder=/1/3");
  return ivr(say("בחירה לא חוקית"), readCmd(MENU_PROMPT, "val_menu", { min: 1, max: 1 }));
});

// ---------- Folder 1/1: code playback (menu 1) ----------
// Post-code menu: 1 repeat, 2 another slot, 9 back to main menu (/1).
// Params: val_slot (first slot), val_slot2 (another slot), val_after (post-code menu answers).
async function speakCode(user: Row, slot: number): Promise<Response> {
  const accounts: Row[] = await sb(`totp_accounts?user_id=eq.${user.id}&slot_number=eq.${slot}&select=*`);
  if (!accounts[0]) return ivr(say("אין חשבון במשבצת זו"), hangup());
  const code = await totp(accounts[0].totp_secret, accounts[0].digits, accounts[0].period);
  return ivr(
    say("הקוד שלך הוא"),
    `id_list_message=d-${code}`,
    readCmd("לשמיעה חוזרת הקש 1, למשבצת אחרת הקש 2, לחזרה לתפריט הראשי הקש 9", "val_after", { min: 1, max: 1 }),
  );
}

yemotRoute("/yemot/ext11", async (c) => {
  if (!isAuthed(c)) return ivr("go_to_folder=/99");
  const phone = callerPhone(c);
  if (!phone) return ivr(say("מספר המתקשר אינו זמין, להתראות"), hangup());
  const user = await loadUser(phone);

  const slotAll = all(c, "val_slot");
  const slot2All = all(c, "val_slot2");
  const afterAll = all(c, "val_after");
  const entered = slotAll.length + slot2All.length;
  const answers = afterAll.length;
  const twos = afterAll.filter((v) => decodeDtmf(v).digits === "2").length;

  // First request: ask which slot.
  if (entered === 0) {
    return ivr(readCmd("הקש מספר משבצת", "val_slot", { min: 1, max: 2 }));
  }
  // Caller pressed 2 on the post-code menu: ask for another slot.
  if (twos > slot2All.length) {
    return ivr(readCmd("הקש מספר משבצת", "val_slot2", { min: 1, max: 2 }));
  }
  const currentSlot = Number(decodeDtmf(slot2All.length > 0 ? latest(c, "val_slot2") : latest(c, "val_slot")).digits);

  // A new slot was entered and its code has not been spoken yet.
  if (entered > answers) return speakCode(user, currentSlot);

  // Answer to the post-code menu.
  const after = decodeDtmf(latest(c, "val_after")).digits;
  if (after === "1") return speakCode(user, currentSlot);
  if (after === "9") return ivr("go_to_folder=/1");
  return ivr(say("להתראות"), hangup());
});

// ---------- Keypad text decoding (shared by seed and account name) ----------
// Pairs: 00-09 = digits 0-9, 21-23 = A-C, 31-33 = D-F, 41-43 = G-I, 51-53 = J-L,
//        61-63 = M-O, 71-74 = P-S, 81-83 = T-V, 91-94 = W-Z.
// "*" = space (a single "**" also gives one space). "#" at the end terminates input.
const DTMF_LETTERS: Record<string, string> = {
  "21": "A", "22": "B", "23": "C",
  "31": "D", "32": "E", "33": "F",
  "41": "G", "42": "H", "43": "I",
  "51": "J", "52": "K", "53": "L",
  "61": "M", "62": "N", "63": "O",
  "71": "P", "72": "Q", "73": "R", "74": "S",
  "81": "T", "82": "U", "83": "V",
  "91": "W", "92": "X", "93": "Y", "94": "Z",
};

// Returns the decoded text (uppercase letters, digits, single spaces, trimmed), or null if any pair is invalid.
function decodeDtmfText(raw: string): string | null {
  const s = raw.replace(/\s/g, "").replace(/#+$/, "");
  let out = "";
  for (let i = 0; i < s.length; ) {
    if (s[i] === "*") {
      out += " ";
      i += 1;
      continue;
    }
    const pair = s.slice(i, i + 2);
    if (!/^\d\d$/.test(pair)) return null;
    if (pair[0] === "0") {
      out += pair[1];
    } else {
      const letter = DTMF_LETTERS[pair];
      if (!letter) return null;
      out += letter;
    }
    i += 2;
  }
  return out.replace(/ +/g, " ").trim();
}

// ---------- Folder 1/2: add account (seed, then name) ----------
const MIN_SEED_LENGTH = 16;
const SEED_PROMPT = "אנא הקש את מפתח האימות ולאחריו סולמית";
const SEED_READ = { min: 2, max: 100, timeout: 30 };
const NAME_PROMPT = "אנא הקש את שם החשבון ולאחריו סולמית";
const NAME_READ = { min: 1, max: 80, timeout: 30 };
const MAX_NAME_LENGTH = 40;

// Converts the raw seed keypad input into a validated base32 seed (spaces removed), or null.
async function decodeSeed(raw: string): Promise<string | null> {
  const text = decodeDtmfText(raw);
  if (text === null) return null;
  const seed = text.replace(/ /g, "").toUpperCase();
  if (seed.length < MIN_SEED_LENGTH || !/^[A-Z2-7]+$/.test(seed)) return null;
  try {
    await totp(seed);
  } catch {
    return null;
  }
  return seed;
}

// Converts the raw name keypad input into a display name, or null if empty, invalid, or too long.
function decodeAccountName(raw: string): string | null {
  const text = decodeDtmfText(raw);
  if (text === null || text.length < 1 || text.length > MAX_NAME_LENGTH) return null;
  return text;
}

yemotRoute("/yemot/ext12", async (c) => {
  if (!isAuthed(c)) return ivr("go_to_folder=/99");
  const phone = callerPhone(c);
  if (!phone) return ivr(say("מספר המתקשר אינו זמין, להתראות"), hangup());

  // Step 1: seed.
  const rawSeed = latest(c, "val_seed_raw");
  if (rawSeed === undefined) return ivr(readCmd(SEED_PROMPT, "val_seed_raw", SEED_READ));

  const seed = await decodeSeed(rawSeed);
  if (!seed) {
    return ivr(say("המפתח שהוקש אינו תקין"), readCmd(SEED_PROMPT, "val_seed_raw", SEED_READ));
  }

  const user = await loadUser(phone);
  const existing: Row[] = await sb(`totp_accounts?user_id=eq.${user.id}&select=slot_number,totp_secret`);
  if (existing.some((a) => a.totp_secret === seed)) {
    return ivr(say("המפתח כבר שמור במערכת"), "go_to_folder=/1");
  }

  const used = new Set(existing.map((a) => Number(a.slot_number)));
  let slot = 0;
  for (let n = 1; n <= 9; n++) {
    if (!used.has(n)) {
      slot = n;
      break;
    }
  }
  if (!slot) return ivr(say("אין משבצת פנויה"), "go_to_folder=/1");

  // Step 2: account name.
  const rawName = latest(c, "val_name_raw");
  if (rawName === undefined) return ivr(readCmd(NAME_PROMPT, "val_name_raw", NAME_READ));

  const name = decodeAccountName(rawName);
  if (!name) {
    return ivr(say("שם החשבון אינו תקין"), readCmd(NAME_PROMPT, "val_name_raw", NAME_READ));
  }

  await sb("totp_accounts", {
    method: "POST",
    body: JSON.stringify({
      user_id: user.id,
      slot_number: slot,
      totp_secret: seed,
      account_label: name,
      digits: 6,
      period: 30,
      algorithm: "SHA1",
    }),
  });
  return ivr(say("המפתח נשמר בהצלחה במשבצת"), `id_list_message=d-${slot}`, "go_to_folder=/1");
});

// ---------- Folder 1/3: delete account by slot ----------
const DELETE_PROMPT = "הקש את מספר המשבצת למחיקה";
const DELETE_READ = { min: 1, max: 1, timeout: 15 };

yemotRoute("/yemot/ext13", async (c) => {
  if (!isAuthed(c)) return ivr("go_to_folder=/99");
  const phone = callerPhone(c);
  if (!phone) return ivr(say("מספר המתקשר אינו זמין, להתראות"), hangup());

  const raw = latest(c, "val_del_slot");
  if (raw === undefined) return ivr(readCmd(DELETE_PROMPT, "val_del_slot", DELETE_READ));

  const digits = decodeDtmf(raw).digits;
  const slot = Number(digits);
  if (!/^[1-9]$/.test(digits) || slot < 1 || slot > 9) {
    return ivr(say("מספר משבצת לא תקין"), readCmd(DELETE_PROMPT, "val_del_slot", DELETE_READ));
  }

  const user = await loadUser(phone);
  const owned: Row[] = await sb(`totp_accounts?user_id=eq.${user.id}&slot_number=eq.${slot}&select=id`);
  if (!owned[0]) return ivr(say("אין חשבון במשבצת זו"), "go_to_folder=/1");

  await sb(`totp_accounts?id=eq.${owned[0].id}&user_id=eq.${user.id}`, { method: "DELETE" });
  return ivr(say("החשבון נמחק בהצלחה"), "go_to_folder=/1");
});

app.get("/health", (c) => c.json({ ok: true }));

export default {
  port: Number(process.env.PORT ?? 3000),
  fetch: app.fetch,
};
