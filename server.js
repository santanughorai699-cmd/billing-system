"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { promisify } = require("util");

const express = require("express");
const cors = require("cors");
const he = require("he");
const { z } = require("zod");

const pbkdf2 = promisify(crypto.pbkdf2);

const timestamp = () => new Date().toISOString().replace("T", " ").slice(0, 19);
const log = {
  info: (msg) => console.log(`${timestamp()} [INFO] ${msg}`),
  warn: (msg) => console.warn(`${timestamp()} [WARNING] ${msg}`),
  error: (msg) => console.error(`${timestamp()} [ERROR] ${msg}`),
};

const splitList = (value) => value.split(",").map((s) => s.trim()).filter(Boolean);

const DATABASE_URL = process.env.DATABASE_URL;
const ALLOWED_ORIGINS = splitList(
  process.env.ALLOWED_ORIGINS ?? "http://localhost:8000,http://127.0.0.1:8000,null"
);
const ALLOWED_HOSTS = splitList(process.env.ALLOWED_HOSTS ?? "*");

const MAX_BODY_SIZE = 1 * 1024 * 1024;
const RATE_LIMIT_WINDOW = 60;
const MAX_REQUESTS_PER_WINDOW = 120;
const LOGIN_RATE_LIMIT_WINDOW = 300;
const MAX_LOGIN_ATTEMPTS = 5;
const WAF_STRIKE_LIMIT = 5;
const IP_BAN_DURATION = 1800;
const SESSION_TTL_HOURS = 24;
const WORK_ACTIVITY_RETENTION_HOURS = 24;
const PBKDF2_ITERATIONS = 260_000;
const MEASUREMENT_FIELDS = ["ঝুল", "ছাতি", "কোমর", "পুট", "হাতা", "মহরী", "মহড়া", "পে", "কছ"];

const nowSec = () => Date.now() / 1000;

class HttpError extends Error {
  constructor(status, detail) {
    super(typeof detail === "string" ? detail : "HTTP error");
    this.status = status;
    this.detail = detail;
  }
}

const SQLI_PATTERNS = [
  /\b(union\s+(all\s+)?select|select\s+[\w*,\s]+\s+from|insert\s+into|delete\s+from|update\s+\w+\s+set|drop\s+(table|database)|alter\s+table|truncate\s+table)\b/i,
  /\b(or|and)\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?/i,
  /(--|#|\/\*[\s\S]*?\*\/|;\s*(shutdown|xp_cmdshell|exec|execute))/i,
  /\b(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay|information_schema|sqlite_master)\b/i,
];

const XSS_PATTERNS = [
  /<\s*script[^>]*>/i,
  /<\s*\/\s*script\s*>/i,
  /(javascript|vbscript|data)\s*:/i,
  /\bon(load|error|click|dblclick|mouseover|mouseout|keydown|keyup|focus|blur|submit|change|input|toggle|wheel)\s*=/i,
  /<\s*(iframe|object|embed|applet|meta|link|style|base|form|svg|math)[^>]*>/i,
  /(document\.(cookie|domain|write|location)|window\.location|eval\s*\(|setTimeout\s*\(|setInterval\s*\()/i,
];

const PATH_TRAVERSAL_AND_CMD_PATTERNS = [
  /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f)/i,
  /(\/etc\/passwd|\/etc\/shadow|\/proc\/self|c:\\windows|cmd\.exe|\/bin\/sh|\/bin\/bash)/i,
  /(\|\||&&|;\s*(ls|cat|rm|wget|curl|nc|bash|sh|python|perl|php|whoami|id)\b|\$\([^)]+\)|`[^`]+`)/i,
  /(<!ENTITY|SYSTEM\s+['"]file:\/\/)/i,
];

const SUSPICIOUS_USER_AGENTS =
  /(sqlmap|nikto|nmap|masscan|nessus|acunetix|burpsuite|dirbuster|gobuster|wfuzz|nuclei|zgrab|havij)/i;

const ALL_WAF_PATTERNS = [
  ...SQLI_PATTERNS,
  ...XSS_PATTERNS,
  ...PATH_TRAVERSAL_AND_CMD_PATTERNS,
];

const ipRequestLog = new Map();
const ipLoginLog = new Map();
const ipStrikes = new Map();
const bannedIps = new Map();

const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com https://unpkg.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
  "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
  "img-src 'self' data: https:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
].join("; ");

function getClientIp(req) {
  if ((process.env.TRUST_PROXY_HEADERS || "false").toLowerCase() === "true") {
    const forwarded = req.headers["x-forwarded-for"];
    if (forwarded) return forwarded.split(",")[0].trim();
  }
  return req.socket.remoteAddress || "unknown";
}

function safeUnquotePlus(value) {
  const spaced = value.replace(/\+/g, " ");
  try {
    return decodeURIComponent(spaced);
  } catch {
    return spaced.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
      try {
        return decodeURIComponent(run);
      } catch {
        return run;
      }
    });
  }
}

function normalizePayload(payload) {
  let decoded = payload;
  for (let i = 0; i < 3; i++) {
    const unescaped = he.decode(safeUnquotePlus(decoded));
    if (unescaped === decoded) break;
    decoded = unescaped;
  }
  return decoded;
}

function checkMaliciousPayload(payload) {
  if (!payload) return null;
  if (payload.includes("\x00") || payload.toLowerCase().includes("%00")) {
    return "Null-byte injection";
  }
  const normalized = normalizePayload(payload);
  const hit = ALL_WAF_PATTERNS.find((re) => re.test(normalized));
  return hit ? `Signature match (${hit.source.slice(0, 35)}...)` : null;
}

function recordStrike(ip, reason) {
  const strikes = (ipStrikes.get(ip) || 0) + 1;
  ipStrikes.set(ip, strikes);
  log.warn(`WAF Strike [${strikes}/${WAF_STRIKE_LIMIT}] IP=${ip} Reason=${reason}`);
  if (strikes >= WAF_STRIKE_LIMIT) {
    bannedIps.set(ip, nowSec() + IP_BAN_DURATION);
    log.error(`IP BANNED for ${IP_BAN_DURATION}s: ${ip}`);
  }
}

function isRateLimited(ip, tracker, windowSec, limit) {
  const now = nowSec();
  const stamps = (tracker.get(ip) || []).filter((t) => now - t < windowSec);
  tracker.set(ip, stamps);
  if (stamps.length >= limit) return true;
  stamps.push(now);
  return false;
}

function setSecurityHeaders(req, res) {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
  });
  if (req.path.startsWith("/api/")) {
    res.set({
      "Cache-Control": "no-store, no-cache, must-revalidate, private",
      Pragma: "no-cache",
    });
  }
}

function securityFirewall(req, res, next) {
  const ip = getClientIp(req);
  const now = nowSec();

  setSecurityHeaders(req, res);

  const banExpires = bannedIps.get(ip);
  if (banExpires !== undefined) {
    if (now < banExpires) {
      return res.status(403).json({
        detail: "Firewall Blocked: Your IP is temporarily banned due to suspicious activity.",
      });
    }
    bannedIps.delete(ip);
    ipStrikes.set(ip, 0);
  }

  if (isRateLimited(ip, ipRequestLog, RATE_LIMIT_WINDOW, MAX_REQUESTS_PER_WINDOW)) {
    recordStrike(ip, "Rate limit exceeded");
    return res.status(429).json({ detail: "Too many requests. Please slow down." });
  }

  const cleanPath = req.path.replace(/\/+$/, "");
  if (cleanPath === "/api/login" && req.method === "POST") {
    if (isRateLimited(ip, ipLoginLog, LOGIN_RATE_LIMIT_WINDOW, MAX_LOGIN_ATTEMPTS)) {
      recordStrike(ip, "Login brute-force limit exceeded");
      return res.status(429).json({
        detail: "Too many login attempts. Try again in 5 minutes.",
      });
    }
  }

  const userAgent = req.headers["user-agent"] || "";
  if (SUSPICIOUS_USER_AGENTS.test(userAgent) || checkMaliciousPayload(userAgent)) {
    recordStrike(ip, `Malicious User-Agent: ${userAgent.slice(0, 50)}`);
    return res.status(403).json({
      detail: "Firewall Blocked: Suspicious User-Agent detected",
    });
  }

  const urlThreat = checkMaliciousPayload(req.originalUrl);
  if (urlThreat) {
    recordStrike(ip, `Malicious URL (${urlThreat})`);
    return res.status(403).json({
      detail: "Firewall Blocked: Suspicious URL parameters detected",
    });
  }

  return next();
}

const rawBodyParser = express.raw({ type: () => true, limit: MAX_BODY_SIZE });

function bodyGuard(req, res, next) {
  if (!["POST", "PUT", "PATCH"].includes(req.method)) return next();

  rawBodyParser(req, res, (err) => {
    if (err) return next(err);

    const buffer = req.body;
    req.body = undefined;

    if (buffer && buffer.length > 0) {
      const text = buffer.toString("utf8");
      const threat = checkMaliciousPayload(text);
      if (threat) {
        recordStrike(getClientIp(req), `Malicious Body (${threat})`);
        return res.status(403).json({
          detail: "Firewall Blocked: Malicious payload detected",
        });
      }
      try {
        req.body = JSON.parse(text);
      } catch {
        req.jsonError = true;
      }
    }
    return next();
  });
}

function trustedHost(req, res, next) {
  if (ALLOWED_HOSTS.includes("*")) return next();
  const host = (req.headers.host || "").split(":")[0].toLowerCase();
  const allowed = ALLOWED_HOSTS.some((pattern) => {
    const p = pattern.toLowerCase();
    return p.startsWith("*.") ? host.endsWith(p.slice(1)) : host === p;
  });
  if (allowed) return next();
  return res.status(400).type("text/plain").send("Invalid host header");
}

const app = express();
app.disable("x-powered-by");

app.use(securityFirewall);
app.use(bodyGuard);
app.use(
  cors({
    origin: ALLOWED_ORIGINS,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Authorization", "Content-Type", "Accept"],
  })
);
app.use(trustedHost);

const DUMMY_HASH = "pbkdf2_sha256$" + PBKDF2_ITERATIONS + "$0000000000000000$" + "0".repeat(64);

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const dk = await pbkdf2(password, salt, PBKDF2_ITERATIONS, 32, "sha256");
  return "pbkdf2_sha256$" + PBKDF2_ITERATIONS + "$" + salt + "$" + dk.toString("hex");
}

async function verifyPassword(plainPassword, storedHash) {
  if (storedHash.startsWith("pbkdf2_sha256$")) {
    const parts = storedHash.split("$");
    if (parts.length < 4) return { valid: false, needsRehash: false };
    const iterations = Number.parseInt(parts[1], 10);
    const salt = parts[2];
    const expectedHex = parts.slice(3).join("$");
    try {
      const dk = await pbkdf2(plainPassword, salt, iterations, 32, "sha256");
      return {
        valid: safeEqual(dk.toString("hex"), expectedHex),
        needsRehash: iterations < PBKDF2_ITERATIONS,
      };
    } catch {
      return { valid: false, needsRehash: false };
    }
  }

  const legacy = crypto.createHash("sha256").update(plainPassword, "utf8").digest("hex");
  return { valid: safeEqual(legacy, storedHash), needsRehash: true };
}

const hashSessionToken = (token) =>
  crypto.createHash("sha256").update(token, "utf8").digest("hex");

let DB_TYPE = "sqlite";
let pool = null;
let sqlite = null;

function connectDatabase() {
  if (DATABASE_URL && DATABASE_URL.startsWith("postgres")) {
    const { Pool } = require("pg");
    DB_TYPE = "postgres";
    pool = new Pool({ connectionString: DATABASE_URL.split("?")[0] });
  } else {
    const Database = require("better-sqlite3");
    sqlite = new Database("billing_system.db", { timeout: 10000 });
  }
}

function translateSql(sql) {
  if (DB_TYPE !== "postgres") return sql;
  let n = 0;
  return sql
    .replace(/INTEGER PRIMARY KEY AUTOINCREMENT/g, "SERIAL PRIMARY KEY")
    .replace(/\?/g, () => "$" + ++n);
}

async function query(sql, params = [], client = null) {
  if (DB_TYPE === "postgres") {
    const result = await (client || pool).query(translateSql(sql), params);
    return result.rows;
  }
  const statement = sqlite.prepare(sql);
  if (statement.reader) return statement.all(...params);
  statement.run(...params);
  return [];
}

async function recordWorkActivity(eventType, actorName, customerName, billNo, previousWorkerName, targetWorkerName) {
  await query(
    `INSERT INTO work_activity
       (event_type, actor_name, customer_name, bill_no, previous_worker_name, target_worker_name, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [eventType, actorName, customerName, billNo, previousWorkerName, targetWorkerName, new Date().toISOString()]
  );
}

async function recordUserActivity(req, eventType, subject, detail = "") {
  const [actor] = await query("SELECT name FROM users WHERE user_id = ?", [req.userId]);
  if (!actor) throw new HttpError(401, "User not found");
  await recordWorkActivity(eventType, actor.name, subject, "", null, detail || subject);
}

async function deleteExpiredWorkActivity() {
  const cutoff = new Date(Date.now() - WORK_ACTIVITY_RETENTION_HOURS * 60 * 60 * 1000).toISOString();
  await query("DELETE FROM work_activity WHERE created_at < ?", [cutoff]);
}

async function withTransaction(work) {
  if (DB_TYPE === "postgres") {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await work((sql, params) => query(sql, params, client));
      await client.query("COMMIT");
      return result;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  sqlite.exec("BEGIN");
  try {
    const result = await work((sql, params) => query(sql, params));
    sqlite.exec("COMMIT");
    return result;
  } catch (err) {
    sqlite.exec("ROLLBACK");
    throw err;
  }
}

async function initDatabase() {
  await query(`CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL
  )`);

  await query(`CREATE TABLE IF NOT EXISTS bills (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    billNo TEXT NOT NULL,
    orderTrack TEXT,
    item TEXT,
    amount REAL NOT NULL,
    down REAL NOT NULL,
    pending REAL NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT
  )`);

  const billColumns = DB_TYPE === "postgres"
    ? await query(
        "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'bills'"
      )
    : await query("PRAGMA table_info(bills)");
  const billColumnNames = new Set(
    billColumns.map((column) => DB_TYPE === "postgres" ? column.column_name : column.name)
  );
  if (!billColumnNames.has("delivery_date")) {
    await query("ALTER TABLE bills ADD COLUMN delivery_date TEXT");
  }
  if (!billColumnNames.has("delivery_alert_accepted")) {
    await query("ALTER TABLE bills ADD COLUMN delivery_alert_accepted INTEGER NOT NULL DEFAULT 0");
  }
  if (!billColumnNames.has("delivery_remind_on")) {
    await query("ALTER TABLE bills ADD COLUMN delivery_remind_on TEXT");
  }
  if (!billColumnNames.has("measurements")) {
    await query("ALTER TABLE bills ADD COLUMN measurements TEXT NOT NULL DEFAULT '{}'");
  }
  if (!billColumnNames.has("work_completed_by")) {
    await query("ALTER TABLE bills ADD COLUMN work_completed_by TEXT");
  }
  if (!billColumnNames.has("work_completed_at")) {
    await query("ALTER TABLE bills ADD COLUMN work_completed_at TEXT");
  }
  if (!billColumnNames.has("work_change_requested_by")) {
    await query("ALTER TABLE bills ADD COLUMN work_change_requested_by TEXT");
  }
  if (!billColumnNames.has("work_change_requested_to")) {
    await query("ALTER TABLE bills ADD COLUMN work_change_requested_to TEXT");
  }
  if (!billColumnNames.has("work_change_requested_at")) {
    await query("ALTER TABLE bills ADD COLUMN work_change_requested_at TEXT");
  }

  await query(`CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT
  )`);

  await query(`CREATE TABLE IF NOT EXISTS work_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    actor_name TEXT NOT NULL,
    customer_name TEXT NOT NULL,
    bill_no TEXT NOT NULL,
    previous_worker_name TEXT,
    target_worker_name TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`);

  const userPhoneColumn = DB_TYPE === "postgres"
    ? await query(
        "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'phone'"
      )
    : (await query("PRAGMA table_info(users)")).filter((column) => column.name === "phone");
  if (userPhoneColumn.length === 0) {
    await query("ALTER TABLE users ADD COLUMN phone TEXT");
  }

  await query(`CREATE TABLE IF NOT EXISTS password_resets (
    user_id TEXT PRIMARY KEY,
    otp_hash TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL
  )`);

  const [{ count }] = await query("SELECT COUNT(*) AS count FROM users");
  if (Number(count) === 0) {
    const seeds = [
      ["samaresh", process.env.ADMIN_DEFAULT_PASS ?? "s1", "admin"],
      ["bimal", process.env.EMP1_DEFAULT_PASS ?? "b2", "employee"],
      ["susama", process.env.EMP2_DEFAULT_PASS ?? "s3", "employee"],
    ];
    for (const [userId, password, role] of seeds) {
      await query(
        "INSERT INTO users (user_id, password, name, role) VALUES (?, ?, ?, ?)",
        [userId, await hashPassword(password), userId, role]
      );
    }
  }
}

const NAME_RE = /^[a-zA-Z\s]{1,80}$/;
const USER_ID_RE = /^[a-zA-Z]{2,32}$/;
const PHONE_RE = /^[6-9][0-9]{9}$/;

const escapeHtml = (s) =>
  s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");

function sanitizeText(value, maxLen = 120) {
  const cleaned = value.trim().replace(/[\x00-\x1f\x7f]/g, "").slice(0, maxLen);
  return escapeHtml(cleaned);
}

function normalizePhoneDigits(raw) {
  let digits = raw.replace(/[^0-9]/g, "");
  if (digits.length === 12 && digits.startsWith("91")) digits = digits.slice(2);
  return digits;
}

const money = z.preprocess(
  (v) => (typeof v === "string" && v.trim() !== "" ? Number(v) : v),
  z.number().min(0).max(100_000_000)
);

const userIdField = z
  .string()
  .min(2)
  .max(32)
  .refine((v) => USER_ID_RE.test(v.trim()), "User ID must contain only alphabets (2-32 chars)")
  .transform((v) => v.trim().toLowerCase());

const LoginData = z.object({
  user_id: userIdField,
  password: z.string().min(1).max(128),
});

const BillInput = z.object({
  name: z
    .string()
    .min(1)
    .max(80)
    .refine((v) => NAME_RE.test(v.trim()), "Name must contain only alphabets and spaces")
    .transform((v) => v.trim()),
  phone: z
    .string()
    .min(10)
    .max(15)
    .refine(
      (v) => PHONE_RE.test(normalizePhoneDigits(v)),
      "Phone must be a valid 10-digit Indian mobile number"
    )
    .transform((v) => "91" + normalizePhoneDigits(v).slice(-10)),
  // Bill No: trim korar pore khali hole reject korbe (shudhu space diye save hoy na)
  billNo: z
    .string()
    .max(50)
    .transform((v) => sanitizeText(v, 150))
    .refine((v) => v.length > 0, "Bill No is required"),
  orderTrack: z.string().max(100).default("").transform((v) => sanitizeText(v, 150)),
  item: z.string().min(1).max(150).transform((v) => sanitizeText(v, 150)),
  deliveryDate: z.string().length(10).refine((value) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const date = new Date(`${value}T00:00:00.000Z`);
    return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
  }, "Delivery date must be a valid calendar date in YYYY-MM-DD format"),
  measurements: z.object(
    Object.fromEntries(MEASUREMENT_FIELDS.map((field) => [field, z.string().max(40).default("")]))
  ).default({}),
  amount: money,
  down: money,
});

function parseMeasurements(value) {
  const measurements = JSON.parse(value || "{}");
  return Object.fromEntries(MEASUREMENT_FIELDS.map((field) => [field, measurements[field] || ""]));
}

const DeliveryReminderInput = z.object({
  remindOn: z.string().max(10).refine((value) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const date = new Date(`${value}T00:00:00.000Z`);
    if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value) return false;
    const today = new Date();
    const todayValue = [
      today.getFullYear(),
      String(today.getMonth() + 1).padStart(2, "0"),
      String(today.getDate()).padStart(2, "0"),
    ].join("-");
    return value > todayValue;
  }, "Reminder date must be a valid future date"),
});

const phoneField = z
  .string()
  .min(10, "Mobile number must be a valid 10-digit Indian number")
  .max(15, "Mobile number must be a valid 10-digit Indian number")
  .refine(
    (v) => PHONE_RE.test(normalizePhoneDigits(v)),
    "Mobile number must be a valid 10-digit Indian number"
  )
  .transform((v) => normalizePhoneDigits(v).slice(-10));

const UserCreate = z.object({
  user_id: userIdField,
  password: z.string().min(6).max(128),
  name: z
    .string()
    .min(1)
    .max(80)
    .refine((v) => NAME_RE.test(v.trim()), "Name must contain only alphabets and spaces")
    .transform((v) => v.trim())
    .optional(),
  role: z.string().default("employee"),
  phone: phoneField.optional(),
});

const PasswordReset = z.object({
  password: z.string().min(6).max(128),
});

const RoleUpdate = z.object({
  role: z.string(),
});

function validate(schema) {
  return (req, res, next) => {
    if (req.jsonError) {
      return res.status(422).json({
        detail: [{ type: "json_invalid", loc: ["body"], msg: "JSON decode error" }],
      });
    }
    const result = schema.safeParse(req.body ?? {});
    if (!result.success) {
      return res.status(422).json({
        detail: result.error.issues.map((issue) => ({
          type: "value_error",
          loc: ["body", ...issue.path],
          msg: issue.message,
        })),
      });
    }
    req.body = result.data;
    return next();
  };
}

function parseId(raw) {
  if (!/^-?\d+$/.test(raw)) {
    throw new HttpError(422, [
      { type: "int_parsing", loc: ["path", "bill_id"], msg: "Input should be a valid integer" },
    ]);
  }
  return Number(raw);
}

const round2 = (n) => Math.round((n + Number.EPSILON) * 100) / 100;

function parseStoredTimestamp(value) {
  let s = String(value).trim().replace(/(\.\d{3})\d+/, "$1");
  if (!/(Z|[+-]\d{2}:?\d{2})$/i.test(s)) s += "Z";
  const date = new Date(s);
  return Number.isNaN(date.getTime()) ? null : date;
}

async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) throw new HttpError(401, "Not authenticated");

  const rawToken = header.slice(7).trim();
  if (!rawToken || rawToken.length > 128) {
    throw new HttpError(401, "Invalid session token format");
  }

  const [row] = await query(
    "SELECT user_id, created_at, token FROM sessions WHERE token = ? OR token = ?",
    [hashSessionToken(rawToken), rawToken]
  );
  if (!row) throw new HttpError(401, "Invalid or expired session");

  const created = row.created_at ? parseStoredTimestamp(row.created_at) : null;
  if (created && Date.now() - created.getTime() > SESSION_TTL_HOURS * 3600_000) {
    await query("DELETE FROM sessions WHERE token = ?", [row.token]);
    throw new HttpError(401, "Session expired. Please log in again.");
  }

  req.userId = row.user_id;
  return next();
}

async function requireAdmin(req, res, next) {
  const [row] = await query("SELECT role FROM users WHERE user_id = ?", [req.userId]);
  if (!row || row.role !== "admin") throw new HttpError(403, "Admin access required");
  return next();
}

app.post("/api/login", validate(LoginData), async (req, res) => {
  const { user_id, password } = req.body;
  const [row] = await query(
    "SELECT user_id, password, role, name FROM users WHERE lower(user_id) = ?",
    [user_id]
  );

  if (!row) {
    await verifyPassword(password, DUMMY_HASH);
    throw new HttpError(401, "Invalid user ID or password");
  }

  const { valid, needsRehash } = await verifyPassword(password, row.password);
  if (!valid) throw new HttpError(401, "Invalid user ID or password");

  if (needsRehash) {
    await query("UPDATE users SET password = ? WHERE user_id = ?", [
      await hashPassword(password),
      row.user_id,
    ]);
  }

  const rawToken = crypto.randomBytes(32).toString("base64url");
  await query("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", [
    hashSessionToken(rawToken),
    row.user_id,
    new Date().toISOString(),
  ]);

  res.json({ token: rawToken, user_id: row.user_id, role: row.role, name: row.name });
});

app.post("/api/logout", async (req, res) => {
  const header = req.headers.authorization || "";
  if (header.startsWith("Bearer ")) {
    const rawToken = header.slice(7).trim();
    await query("DELETE FROM sessions WHERE token = ? OR token = ?", [
      hashSessionToken(rawToken),
      rawToken,
    ]);
  }
  res.json({ message: "Logged out" });
});

app.get("/api/me", requireAuth, async (req, res) => {
  const [row] = await query("SELECT role, name, phone FROM users WHERE user_id = ?", [req.userId]);
  if (!row) throw new HttpError(401, "User not found");
  res.json({
    user_id: req.userId,
    role: row.role,
    name: row.name,
    phone: row.phone || "9093209840",
  });
});

app.get("/api/bills", requireAuth, async (req, res) => {
  const rows = await query(
    `SELECT bills.id, bills.name, bills.phone, bills.billNo AS "billNo", bills.orderTrack, bills.item, bills.amount, bills.down, bills.pending,
            bills.created_at, bills.created_by, COALESCE(creator.name, bills.created_by) AS created_by_name,
            bills.work_completed_by, worker.name AS work_completed_by_name, worker.role AS work_completed_by_role, bills.work_completed_at,
            bills.work_change_requested_by, requester.name AS work_change_requested_by_name,
            bills.work_change_requested_to, target.name AS work_change_requested_to_name, bills.work_change_requested_at,
            bills.delivery_date, bills.delivery_alert_accepted, bills.delivery_remind_on, bills.measurements
     FROM bills
     LEFT JOIN users AS creator ON creator.user_id = bills.created_by
     LEFT JOIN users AS worker ON worker.user_id = bills.work_completed_by
     LEFT JOIN users AS requester ON requester.user_id = bills.work_change_requested_by
     LEFT JOIN users AS target ON target.user_id = bills.work_change_requested_to
     ORDER BY bills.id DESC`
  );
  res.json(rows.map((row) => ({ ...row, measurements: parseMeasurements(row.measurements) })));
});

app.post("/api/bills", requireAuth, validate(BillInput), async (req, res) => {
  const bill = req.body;
  const pending = round2(Math.max(bill.amount - bill.down, 0));
  const createdAt = new Date().toISOString();

  const [row] = await query(
    `INSERT INTO bills (name, phone, billNo, orderTrack, item, amount, down, pending, created_by, created_at, delivery_date, delivery_alert_accepted, delivery_remind_on, measurements)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?) RETURNING id`,
    [
      bill.name,
      bill.phone,
      bill.billNo,
      bill.orderTrack,
      bill.item,
      bill.amount,
      bill.down,
      pending,
      req.userId,
      createdAt,
      bill.deliveryDate || null,
      JSON.stringify(bill.measurements),
    ]
  );
  await recordUserActivity(req, "bill_created", bill.name, `Bill #${bill.billNo}`);

  res.json({
    id: row.id,
    name: bill.name,
    phone: bill.phone,
    billNo: bill.billNo,
    orderTrack: bill.orderTrack,
    item: bill.item,
    amount: bill.amount,
    down: bill.down,
    pending,
    created_at: createdAt,
    created_by: req.userId,
    delivery_date: bill.deliveryDate || null,
    delivery_alert_accepted: 0,
    delivery_remind_on: null,
    measurements: bill.measurements,
  });
});

app.put("/api/bills/:id", requireAuth, validate(BillInput), async (req, res) => {
  const billId = parseId(req.params.id);
  const [existing] = await query("SELECT created_by, created_at, delivery_date, delivery_alert_accepted, delivery_remind_on FROM bills WHERE id = ?", [billId]);
  if (!existing) throw new HttpError(404, "Bill not found");

  const bill = req.body;
  const pending = round2(Math.max(bill.amount - bill.down, 0));
  const deliveryDate = bill.deliveryDate || null;
  const deliveryAlertAccepted = existing.delivery_date === deliveryDate
    ? existing.delivery_alert_accepted
    : 0;
  const deliveryRemindOn = existing.delivery_date === deliveryDate
    ? existing.delivery_remind_on
    : null;

  await query(
    `UPDATE bills SET name = ?, phone = ?, billNo = ?, orderTrack = ?, item = ?, amount = ?, down = ?, pending = ?, delivery_date = ?, delivery_alert_accepted = ?, delivery_remind_on = ?, measurements = ?
     WHERE id = ?`,
    [bill.name, bill.phone, bill.billNo, bill.orderTrack, bill.item, bill.amount, bill.down, pending, deliveryDate, deliveryAlertAccepted, deliveryRemindOn, JSON.stringify(bill.measurements), billId]
  );
  await recordUserActivity(req, "bill_updated", bill.name, `Bill #${bill.billNo}`);

  res.json({
    id: billId,
    name: bill.name,
    phone: bill.phone,
    billNo: bill.billNo,
    orderTrack: bill.orderTrack,
    item: bill.item,
    amount: bill.amount,
    down: bill.down,
    pending,
    created_at: existing.created_at,
    created_by: existing.created_by,
    delivery_date: deliveryDate,
    delivery_alert_accepted: deliveryAlertAccepted,
    delivery_remind_on: deliveryRemindOn,
    measurements: bill.measurements,
  });
});

app.post("/api/bills/:id/delivery-alert/accept", requireAuth, async (req, res) => {
  const billId = parseId(req.params.id);
  const [existing] = await query("SELECT id, name, billNo FROM bills WHERE id = ?", [billId]);
  if (!existing) throw new HttpError(404, "Bill not found");
  await query("UPDATE bills SET delivery_alert_accepted = 1, delivery_remind_on = NULL WHERE id = ?", [billId]);
  await recordUserActivity(req, "delivery_reminder_accepted", existing.name, `Bill #${existing.billNo}`);
  res.json({ message: "Delivery alert accepted" });
});

app.post("/api/bills/:id/work-complete", requireAuth, async (req, res) => {
  const billId = parseId(req.params.id);
  const [user] = await query("SELECT name, role FROM users WHERE user_id = ?", [req.userId]);
  if (!user) throw new HttpError(401, "User not found");
  const [billDetails] = await query("SELECT name, billNo FROM bills WHERE id = ?", [billId]);
  if (!billDetails) throw new HttpError(404, "Bill not found");

  const completedAt = new Date().toISOString();
  const updated = await query(
    "UPDATE bills SET work_completed_by = ?, work_completed_at = ? WHERE id = ? AND work_completed_by IS NULL RETURNING id",
    [
    req.userId,
    completedAt,
    billId,
    ]
  );
  if (updated.length === 0) {
    const [bill] = await query("SELECT id FROM bills WHERE id = ?", [billId]);
    if (!bill) throw new HttpError(404, "Bill not found");
    throw new HttpError(409, "Work has already been marked complete");
  }
  await recordWorkActivity("work_completed", user.name, billDetails.name, billDetails.billNo, null, user.name);
  res.json({
    work_completed_by: req.userId,
    work_completed_by_name: user.name,
    work_completed_by_role: user.role,
    work_completed_at: completedAt,
    work_change_requested_by: null,
    work_change_requested_to: null,
    work_change_requested_at: null,
  });
});

app.put("/api/bills/:id/work-complete", requireAuth, requireAdmin, validate(z.object({
  workerId: z.string().min(2).max(32).regex(USER_ID_RE),
})), async (req, res) => {
  const billId = parseId(req.params.id);
  const [bill] = await query(
    `SELECT bills.work_completed_at, bills.name, bills.billNo, bills.work_completed_by,
            previous_worker.name AS previous_worker_name
     FROM bills LEFT JOIN users AS previous_worker ON previous_worker.user_id = bills.work_completed_by
     WHERE bills.id = ?`,
    [billId]
  );
  if (!bill) throw new HttpError(404, "Bill not found");
  if (!bill.work_completed_at) throw new HttpError(409, "Work must be marked complete before changing its employee");

  const [employee] = await query("SELECT user_id, name, role FROM users WHERE user_id = ? AND role IN ('employee', 'admin')", [
    req.body.workerId,
  ]);
  if (!employee) throw new HttpError(400, "Select a valid employee or admin");
  const [actor] = await query("SELECT name FROM users WHERE user_id = ?", [req.userId]);

  await query(
    "UPDATE bills SET work_completed_by = ?, work_change_requested_by = NULL, work_change_requested_to = NULL, work_change_requested_at = NULL WHERE id = ?",
    [employee.user_id, billId]
  );
  if (bill.work_completed_by !== employee.user_id) {
    await recordWorkActivity("work_assigned", actor.name, bill.name, bill.billNo, bill.previous_worker_name, employee.name);
  }
  res.json({
    work_completed_by: employee.user_id,
    work_completed_by_name: employee.name,
    work_completed_by_role: employee.role,
    work_completed_at: bill.work_completed_at,
    work_change_requested_by: null,
    work_change_requested_to: null,
    work_change_requested_at: null,
  });
});

const WorkChangeRequestInput = z.object({
  workerId: z.string().min(2).max(32).regex(USER_ID_RE),
});

const WorkChangeResponseInput = z.object({
  accept: z.boolean(),
});

app.get("/api/workers", requireAuth, async (req, res) => {
  const rows = await query("SELECT user_id, name, role FROM users WHERE role IN ('employee', 'admin') ORDER BY role, name");
  res.json(rows);
});

app.post("/api/bills/:id/work-change-request", requireAuth, validate(WorkChangeRequestInput), async (req, res) => {
  const billId = parseId(req.params.id);
  const [target] = await query("SELECT user_id, name FROM users WHERE user_id = ? AND role IN ('employee', 'admin')", [
    req.body.workerId,
  ]);
  if (!target) throw new HttpError(400, "Select a valid employee or admin");

  const requestedAt = new Date().toISOString();
  const [requester] = await query("SELECT name FROM users WHERE user_id = ?", [req.userId]);
  const [billDetails] = await query(
    `SELECT bills.name, bills.billNo, current_worker.name AS current_worker_name
     FROM bills LEFT JOIN users AS current_worker ON current_worker.user_id = bills.work_completed_by
     WHERE bills.id = ?`,
    [billId]
  );
  const updated = await query(
    `UPDATE bills SET work_change_requested_by = ?, work_change_requested_to = ?, work_change_requested_at = ?
     WHERE id = ? AND work_completed_by IS NOT NULL AND work_completed_by != ?
       AND work_change_requested_to IS NULL
     RETURNING id`,
    [req.userId, target.user_id, requestedAt, billId, target.user_id]
  );
  if (updated.length === 0) {
    const [bill] = await query("SELECT work_completed_by, work_change_requested_to FROM bills WHERE id = ?", [billId]);
    if (!bill) throw new HttpError(404, "Bill not found");
    if (!bill.work_completed_by) throw new HttpError(409, "Work must be completed before changing its worker");
    if (bill.work_completed_by === target.user_id) throw new HttpError(400, "This worker is already assigned");
    throw new HttpError(409, "Another work change request is already pending");
  }

  await recordWorkActivity(
    "work_change_requested",
    requester.name,
    billDetails.name,
    billDetails.billNo,
    billDetails.current_worker_name,
    target.name
  );
  res.json({
    message: "Work change request sent",
    work_change_requested_by: req.userId,
    work_change_requested_by_name: requester.name,
    work_change_requested_to: target.user_id,
    work_change_requested_to_name: target.name,
    work_change_requested_at: requestedAt,
  });
});

app.get("/api/work-change-requests", requireAuth, async (req, res) => {
  const [user] = await query("SELECT role FROM users WHERE user_id = ?", [req.userId]);
  if (!user) throw new HttpError(401, "User not found");
  const rows = await query(
    `SELECT bills.id AS bill_id, bills.name AS customer_name, bills.billNo, bills.work_change_requested_by,
            requester.name AS requester_name, bills.work_change_requested_to, target.name AS target_name, bills.work_change_requested_at,
            bills.work_completed_by, current_worker.name AS current_worker_name
     FROM bills
     JOIN users AS requester ON requester.user_id = bills.work_change_requested_by
     JOIN users AS current_worker ON current_worker.user_id = bills.work_completed_by
     JOIN users AS target ON target.user_id = bills.work_change_requested_to
     WHERE (? = 'admin' OR bills.work_completed_by = ?)
     ORDER BY bills.work_change_requested_at`,
    [user.role, req.userId]
  );
  res.json(rows);
});

app.post("/api/bills/:id/work-change-response", requireAuth, validate(WorkChangeResponseInput), async (req, res) => {
  const billId = parseId(req.params.id);
  const [bill] = await query(
    `SELECT bills.work_change_requested_by, bills.work_change_requested_to, bills.work_change_requested_at,
            bills.work_completed_by, bills.work_completed_at, target.name AS target_name, target.role AS target_role,
            current_worker.name AS current_worker_name, current_worker.role AS current_worker_role,
            bills.name, bills.billNo
     FROM bills
     LEFT JOIN users AS target ON target.user_id = bills.work_change_requested_to
     LEFT JOIN users AS current_worker ON current_worker.user_id = bills.work_completed_by
     WHERE bills.id = ?`,
    [billId]
  );
  if (!bill) throw new HttpError(404, "Bill not found");
  if (!bill.work_change_requested_to) throw new HttpError(409, "Work change request is no longer pending");
  if (bill.work_completed_by !== req.userId) {
    const [user] = await query("SELECT role FROM users WHERE user_id = ?", [req.userId]);
    if (!user || user.role !== "admin") {
      throw new HttpError(403, "Only the current worker or an admin can respond to this request");
    }
  }

  if (req.body.accept && !bill.target_name) throw new HttpError(409, "The assigned user no longer exists");
  const [actor] = await query("SELECT name FROM users WHERE user_id = ?", [req.userId]);
  const changed = req.body.accept
    ? await query(
        `UPDATE bills SET work_completed_by = ?, work_change_requested_by = NULL, work_change_requested_to = NULL, work_change_requested_at = NULL
         WHERE id = ? AND work_completed_by = ? AND work_change_requested_by = ? AND work_change_requested_to = ? RETURNING id`,
        [bill.work_change_requested_to, billId, bill.work_completed_by, bill.work_change_requested_by, bill.work_change_requested_to]
      )
    : await query(
        `UPDATE bills SET work_change_requested_by = NULL, work_change_requested_to = NULL, work_change_requested_at = NULL
         WHERE id = ? AND work_completed_by = ? AND work_change_requested_by = ? AND work_change_requested_to = ? RETURNING id`,
        [billId, bill.work_completed_by, bill.work_change_requested_by, bill.work_change_requested_to]
      );
  if (changed.length === 0) throw new HttpError(409, "Work change request is no longer pending");
  await recordWorkActivity(
      req.body.accept ? "work_change_accepted" : "work_change_rejected",
      actor.name,
      bill.name,
      bill.billNo,
      bill.current_worker_name,
      bill.target_name
  );

  res.json({
    bill_id: billId,
    accepted: req.body.accept,
    work_completed_by: req.body.accept ? bill.work_change_requested_to : bill.work_completed_by,
    work_completed_by_name: req.body.accept ? bill.target_name : bill.current_worker_name,
    work_completed_by_role: req.body.accept ? bill.target_role : bill.current_worker_role,
    work_completed_at: bill.work_completed_at,
    work_change_requested_by: null,
    work_change_requested_to: null,
    work_change_requested_at: null,
  });
});

app.get("/api/work-activity", requireAuth, async (_req, res) => {
  const cutoff = new Date(Date.now() - WORK_ACTIVITY_RETENTION_HOURS * 60 * 60 * 1000).toISOString();
  const rows = await query(
    `SELECT id, event_type, actor_name, customer_name, bill_no, previous_worker_name,
            target_worker_name, created_at
     FROM work_activity WHERE created_at >= ? ORDER BY id DESC LIMIT 50`,
    [cutoff]
  );
  res.json(rows);
});

app.get("/api/work-stats", requireAuth, requireAdmin, async (req, res) => {
  const rows = DB_TYPE === "postgres"
    ? await query(
        `SELECT (bills.work_completed_at::timestamptz AT TIME ZONE 'Asia/Kolkata')::date::text AS work_date,
                bills.work_completed_by AS worker_id, COALESCE(users.name, bills.work_completed_by) AS worker_name,
                COALESCE(users.role, 'unknown') AS worker_role, COUNT(*) AS job_count
         FROM bills LEFT JOIN users ON users.user_id = bills.work_completed_by
         WHERE bills.work_completed_at IS NOT NULL
         GROUP BY work_date, worker_id, worker_name, worker_role
         ORDER BY work_date DESC, worker_name`
      )
    : await query(
        `SELECT strftime('%Y-%m-%d', bills.work_completed_at, '+5 hours', '+30 minutes') AS work_date,
                bills.work_completed_by AS worker_id, COALESCE(users.name, bills.work_completed_by) AS worker_name,
                COALESCE(users.role, 'unknown') AS worker_role, COUNT(*) AS job_count
         FROM bills LEFT JOIN users ON users.user_id = bills.work_completed_by
         WHERE bills.work_completed_at IS NOT NULL
         GROUP BY work_date, worker_id, worker_name, worker_role
         ORDER BY work_date DESC, worker_name`
      );
  res.json(rows);
});

app.post("/api/bills/:id/delivery-alert/remind", requireAuth, validate(DeliveryReminderInput), async (req, res) => {
  const billId = parseId(req.params.id);
  const [existing] = await query("SELECT id, name, billNo FROM bills WHERE id = ?", [billId]);
  if (!existing) throw new HttpError(404, "Bill not found");
  await query("UPDATE bills SET delivery_remind_on = ? WHERE id = ?", [req.body.remindOn, billId]);
  await recordUserActivity(req, "delivery_reminder_rescheduled", existing.name, `Bill #${existing.billNo}`);
  res.json({ message: "Delivery reminder rescheduled", delivery_remind_on: req.body.remindOn });
});

app.delete("/api/bills/:id", requireAuth, requireAdmin, async (req, res) => {
  const billId = parseId(req.params.id);
  const [bill] = await query("SELECT name, billNo FROM bills WHERE id = ?", [billId]);
  if (!bill) throw new HttpError(404, "Bill not found");
  await query("DELETE FROM bills WHERE id = ?", [billId]);
  await recordUserActivity(req, "bill_deleted", bill.name, `Bill #${bill.billNo}`);
  res.json({ message: "Bill deleted" });
});

app.get("/api/users", requireAuth, requireAdmin, async (req, res) => {
  const rows = await query("SELECT user_id, name, role, phone FROM users");
  res.json(rows);
});

app.post("/api/users", requireAuth, requireAdmin, validate(UserCreate), async (req, res) => {
  const data = req.body;
  if (!["admin", "employee"].includes(data.role)) {
    throw new HttpError(400, "Role must be admin or employee");
  }

  const [existing] = await query("SELECT user_id FROM users WHERE user_id = ?", [data.user_id]);
  if (existing) throw new HttpError(400, "User ID already exists");

  await query("INSERT INTO users (user_id, password, name, role, phone) VALUES (?, ?, ?, ?, ?)", [
    data.user_id,
    await hashPassword(data.password),
    data.name || data.user_id,
    data.role,
    data.phone,
  ]);
  await recordUserActivity(req, "user_created", data.name || data.user_id, `${data.role} account · ${data.user_id}`);

  res.json({ message: `User ${data.user_id} created` });
});

app.put("/api/users/:user_id", requireAuth, requireAdmin, validate(RoleUpdate), async (req, res) => {
  const userId = req.params.user_id;
  const { role } = req.body;
  if (!["admin", "employee"].includes(role)) throw new HttpError(400, "Invalid role");

  const [existing] = await query("SELECT user_id FROM users WHERE user_id = ?", [userId]);
  if (!existing) throw new HttpError(404, "User not found");

  await query("UPDATE users SET role = ? WHERE user_id = ?", [role, userId]);
  await recordUserActivity(req, "user_role_updated", userId, `Role: ${role}`);
  res.json({ message: `Role updated for ${userId}` });
});

app.put(
  "/api/users/:user_id/password",
  requireAuth,
  requireAdmin,
  validate(PasswordReset),
  async (req, res) => {
    const userId = req.params.user_id;
    const [existing] = await query("SELECT user_id FROM users WHERE user_id = ?", [userId]);
    if (!existing) throw new HttpError(404, "User not found");

    const hash = await hashPassword(req.body.password);
    await withTransaction(async (tx) => {
      await tx("UPDATE users SET password = ? WHERE user_id = ?", [hash, userId]);
      await tx("DELETE FROM sessions WHERE user_id = ?", [userId]);
    });
    await recordUserActivity(req, "user_password_updated", userId, "Password reset");

    res.json({ message: `Password updated and active sessions revoked for ${userId}` });
  }
);

app.delete("/api/users/:user_id", requireAuth, requireAdmin, async (req, res) => {
  const userId = req.params.user_id;
  if (userId === req.userId) throw new HttpError(400, "You cannot delete yourself");

  const [existing] = await query("SELECT user_id FROM users WHERE user_id = ?", [userId]);
  if (!existing) throw new HttpError(404, "User not found");

  await withTransaction(async (tx) => {
    await tx("DELETE FROM users WHERE user_id = ?", [userId]);
    await tx("DELETE FROM sessions WHERE user_id = ?", [userId]);
  });
  await recordUserActivity(req, "user_deleted", userId, "Account deleted");

  res.json({ message: `User ${userId} deleted` });
});

const SMS_API_KEY = process.env.SMS_API_KEY || "";
const OTP_TTL_MS = 5 * 60 * 1000;
const OTP_COOLDOWN_MS = 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;
const OTP_RE = /^[0-9]{6}$/;

const hashOtp = (userId, otp) =>
  crypto.createHash("sha256").update(`${userId}:${otp}`, "utf8").digest("hex");

const maskPhone = (phone) => `******${phone.slice(-4)}`;

async function sendOtpSms(phone, otp) {
  if (!SMS_API_KEY) {
    log.warn(`SMS_API_KEY not set. OTP for ${maskPhone(phone)} is ${otp} (testing only)`);
    return;
  }
  const res = await fetch("https://www.fast2sms.com/dev/bulkV2", {
    method: "POST",
    headers: {
      authorization: SMS_API_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      route: "otp",
      variables_values: otp,
      numbers: phone,
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.return === false) {
    throw new Error(`SMS provider error: ${JSON.stringify(data)}`);
  }
}

const ForgotSend = z.object({
  user_id: userIdField,
});

const ForgotReset = z.object({
  user_id: userIdField,
  otp: z.string().regex(OTP_RE, "OTP must be 6 digits"),
  password: z.string().min(6, "Password must be at least 6 characters").max(128),
});

const PhoneUpdate = z.object({
  phone: phoneField,
});

app.post("/api/forgot-password/send", validate(ForgotSend), async (req, res) => {
  const { user_id } = req.body;
  const genericReply = {
    message: "If this User ID has a registered mobile number, an OTP has been sent to it.",
  };

  const [user] = await query("SELECT user_id, phone FROM users WHERE lower(user_id) = ?", [user_id]);
  if (!user || !user.phone) return res.json(genericReply);

  const [pending] = await query("SELECT created_at FROM password_resets WHERE user_id = ?", [user.user_id]);
  if (pending && Date.now() - Number(pending.created_at) < OTP_COOLDOWN_MS) {
    return res.json(genericReply);
  }

  const otp = String(crypto.randomInt(100000, 1000000));
  const now = Date.now();
  await query(
    `INSERT INTO password_resets (user_id, otp_hash, expires_at, attempts, created_at)
     VALUES (?, ?, ?, 0, ?)
     ON CONFLICT (user_id) DO UPDATE SET
       otp_hash = excluded.otp_hash,
       expires_at = excluded.expires_at,
       attempts = 0,
       created_at = excluded.created_at`,
    [user.user_id, hashOtp(user.user_id, otp), now + OTP_TTL_MS, now]
  );

  try {
    await sendOtpSms(user.phone, otp);
  } catch (err) {
    log.error(`OTP SMS failed for ${user.user_id}: ${err.message}`);
    await query("DELETE FROM password_resets WHERE user_id = ?", [user.user_id]);
    throw new HttpError(502, "OTP could not be sent right now. Please try again later.");
  }

  res.json(genericReply);
});

app.post("/api/forgot-password/reset", validate(ForgotReset), async (req, res) => {
  const { user_id, otp, password } = req.body;

  const [row] = await query(
    "SELECT user_id, otp_hash, expires_at, attempts FROM password_resets WHERE user_id = ?",
    [user_id]
  );

  if (!row || Date.now() > Number(row.expires_at)) {
    throw new HttpError(400, "OTP is invalid or has expired. Please request a new one.");
  }

  if (Number(row.attempts) >= OTP_MAX_ATTEMPTS) {
    await query("DELETE FROM password_resets WHERE user_id = ?", [row.user_id]);
    throw new HttpError(429, "Too many wrong attempts. Please request a new OTP.");
  }

  if (!safeEqual(hashOtp(row.user_id, otp), row.otp_hash)) {
    await query("UPDATE password_resets SET attempts = attempts + 1 WHERE user_id = ?", [row.user_id]);
    throw new HttpError(400, "Incorrect OTP.");
  }

  const hash = await hashPassword(password);
  await withTransaction(async (tx) => {
    await tx("UPDATE users SET password = ? WHERE user_id = ?", [hash, row.user_id]);
    await tx("DELETE FROM sessions WHERE user_id = ?", [row.user_id]);
    await tx("DELETE FROM password_resets WHERE user_id = ?", [row.user_id]);
  });

  res.json({ message: "Password reset successful. Please log in with your new password." });
});

app.put("/api/users/:user_id/phone", requireAuth, validate(PhoneUpdate), async (req, res) => {
  const userId = req.params.user_id;

  if (userId !== req.userId) {
    const [me] = await query("SELECT role FROM users WHERE user_id = ?", [req.userId]);
    if (!me || me.role !== "admin") {
      throw new HttpError(403, "You can only change your own mobile number");
    }
  }

  const [existing] = await query("SELECT user_id, name FROM users WHERE user_id = ?", [userId]);
  if (!existing) throw new HttpError(404, "User not found");

  await query("UPDATE users SET phone = ? WHERE user_id = ?", [req.body.phone, userId]);
  await recordUserActivity(req, "user_phone_updated", existing.name, `Mobile updated · ${userId}`);
  res.json({ message: "Mobile number updated" });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

const INDEX_PATH = path.join(__dirname, "index.html");

async function serveFrontend(req, res) {
  try {
    const html = await fs.promises.readFile(INDEX_PATH, "utf8");
    res.type("html").send(html);
  } catch {
    res.status(404).type("html").send("<h1>index.html not found</h1>");
  }
}

app.get(["/", "/index.html", "/billing"], serveFrontend);

app.use((req, res) => {
  res.status(404).json({ detail: "Not Found" });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err instanceof HttpError) {
    return res.status(err.status).json({ detail: err.detail });
  }
  if (err.type === "entity.too.large") {
    return res.status(413).json({ detail: "Firewall Blocked: Payload too large" });
  }
  if (err.type && err.status === 400) {
    return res.status(400).json({ detail: "Malformed request payload" });
  }

  log.error(err.stack || String(err));
  return res.status(500).json({ detail: "Internal Server Error" });
});

async function start() {
  connectDatabase();
  await initDatabase();
  await deleteExpiredWorkActivity();
  const workActivityCleanupTimer = setInterval(() => {
    deleteExpiredWorkActivity().catch((err) => {
      log.error(`Failed to delete expired work notifications: ${err.message}`);
    });
  }, 5 * 60 * 1000);
  workActivityCleanupTimer.unref();

  const PORT = Number(process.env.PORT) || 8000;
  app.listen(PORT, "0.0.0.0", () => {
    log.info(`Billing API listening on http://0.0.0.0:${PORT}`);
  });
}

start().catch((err) => {
  log.error(`Startup failed: ${err.message}`);
  process.exit(1);
});
