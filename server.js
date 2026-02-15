const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const AUTH_WINDOW_MS = 15 * 60 * 1000;
const AUTH_MAX_ATTEMPTS = 12;
const AUTH_FAILURE_DELAY_MS = 250;
const AUTH_FAILURE_JITTER_MS = 250;
const AUTH_GENERIC_ERROR = "Invalid email or password.";
const DATABASE_URL =
  process.env.POSTGRES_URL ||
  process.env.DATABASE_URL ||
  process.env.POSTGRES_PRISMA_URL ||
  process.env.POSTGRES_URL_NON_POOLING ||
  "";

const staticFiles = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/index.html": { file: "index.html", type: "text/html; charset=utf-8" },
  "/styles.css": { file: "styles.css", type: "text/css; charset=utf-8" },
  "/app.js": { file: "app.js", type: "application/javascript; charset=utf-8" },
};

let pool = null;
let schemaReadyPromise = null;
const authAttempts = new Map();
const DUMMY_PASSWORD_HASH = hashPassword("dummy-password-value");

function hasDatabaseConfig() {
  return Boolean(DATABASE_URL);
}

function getPool() {
  if (!hasDatabaseConfig()) {
    return null;
  }

  if (!pool) {
    const shouldUseSSL = !DATABASE_URL.includes("localhost") && process.env.PGSSLMODE !== "disable";
    pool = new Pool({
      connectionString: DATABASE_URL,
      ssl: shouldUseSSL ? { rejectUnauthorized: false } : false,
      max: 10,
    });
  }

  return pool;
}

async function ensureSchema() {
  if (!hasDatabaseConfig()) {
    return;
  }

  if (!schemaReadyPromise) {
    schemaReadyPromise = (async () => {
      const db = getPool();
      await db.query(`
        CREATE TABLE IF NOT EXISTS users (
          id BIGSERIAL PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          painting TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          CONSTRAINT email_lowercase CHECK (email = LOWER(email))
        );
      `);

      await db.query(`
        CREATE TABLE IF NOT EXISTS sessions (
          sid TEXT PRIMARY KEY,
          user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await db.query(`
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
        ON sessions (expires_at);
      `);
    })().catch((error) => {
      schemaReadyPromise = null;
      throw error;
    });
  }

  await schemaReadyPromise;
}

function sendJSON(res, statusCode, payload, headers = {}) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    ...headers,
  });
  res.end(JSON.stringify(payload));
}

function sendText(res, statusCode, text) {
  res.writeHead(statusCode, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(text);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseJSONBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 6 * 1024 * 1024) {
        reject(new Error("Request too large"));
      }
    });

    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });

    req.on("error", reject);
  });
}

function parseCookies(req) {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return {};

  return cookieHeader.split(";").reduce((acc, item) => {
    const [rawKey, ...rest] = item.trim().split("=");
    acc[rawKey] = decodeURIComponent(rest.join("="));
    return acc;
  }, {});
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, passwordHash) {
  const [salt, storedHash] = String(passwordHash).split(":");
  if (!salt || !storedHash) return false;
  const computed = crypto.scryptSync(password, salt, 64).toString("hex");
  const a = Buffer.from(storedHash, "hex");
  const b = Buffer.from(computed, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function createSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

function buildSessionCookie(req, sid, maxAgeSeconds) {
  const isSecure =
    req.headers["x-forwarded-proto"] === "https" ||
    process.env.NODE_ENV === "production";
  return `sid=${sid}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAgeSeconds}${isSecure ? "; Secure" : ""}`;
}

function buildExpiredSessionCookie(req) {
  const isSecure =
    req.headers["x-forwarded-proto"] === "https" ||
    process.env.NODE_ENV === "production";
  return `sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${isSecure ? "; Secure" : ""}`;
}

async function createSession(db, userId) {
  const sid = createSessionId();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  await db.query(
    "INSERT INTO sessions (sid, user_id, expires_at) VALUES ($1, $2, $3)",
    [sid, userId, expiresAt]
  );
  return sid;
}

async function getAuthenticatedUser(req) {
  const sid = parseCookies(req).sid;
  if (!sid) return null;

  const db = getPool();
  if (!db) return null;

  await db.query("DELETE FROM sessions WHERE expires_at <= NOW()");

  const result = await db.query(
    `
      SELECT u.id, u.email
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.sid = $1 AND s.expires_at > NOW()
      LIMIT 1
    `,
    [sid]
  );

  if (!result.rows[0]) {
    return null;
  }

  return result.rows[0];
}

async function clearSession(req) {
  const sid = parseCookies(req).sid;
  if (!sid) return;

  const db = getPool();
  if (!db) return;

  await db.query("DELETE FROM sessions WHERE sid = $1", [sid]);
}

function isEmail(value) {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isValidPassword(value) {
  return typeof value === "string" && value.length >= 8;
}

function hasValidPngDataUrl(value) {
  return (
    typeof value === "string" &&
    value.startsWith("data:image/png;base64,") &&
    value.length <= 5 * 1024 * 1024
  );
}

function getClientIp(req) {
  const forwardedFor = req.headers["x-forwarded-for"];
  if (typeof forwardedFor === "string" && forwardedFor.length > 0) {
    return forwardedFor.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "unknown";
}

function getAuthAttemptState(ip) {
  const now = Date.now();
  const current = authAttempts.get(ip);

  if (!current || now - current.windowStart > AUTH_WINDOW_MS) {
    const reset = { count: 0, windowStart: now };
    authAttempts.set(ip, reset);
    return reset;
  }

  return current;
}

function isRateLimited(ip) {
  const state = getAuthAttemptState(ip);
  return state.count >= AUTH_MAX_ATTEMPTS;
}

function recordAuthFailure(ip) {
  const state = getAuthAttemptState(ip);
  state.count += 1;
  authAttempts.set(ip, state);
}

function clearAuthFailures(ip) {
  authAttempts.delete(ip);
}

async function applyAuthFailureDelay() {
  const jitter = Math.floor(Math.random() * AUTH_FAILURE_JITTER_MS);
  await sleep(AUTH_FAILURE_DELAY_MS + jitter);
}

function ensureDatabaseOrFail(res) {
  if (hasDatabaseConfig()) {
    return true;
  }

  sendJSON(res, 500, {
    error: "Database is not configured. Set POSTGRES_URL (or DATABASE_URL).",
  });
  return false;
}

async function handleRequest(req, res) {
  try {
    const rawUrl = req.url || "/";
    const url = rawUrl.split("?")[0];
    const { method } = req;

    if (method === "GET" && staticFiles[url]) {
      const filePath = path.join(__dirname, staticFiles[url].file);
      if (!fs.existsSync(filePath)) {
        sendText(res, 404, "Not found");
        return;
      }

      res.writeHead(200, { "Content-Type": staticFiles[url].type });
      fs.createReadStream(filePath).pipe(res);
      return;
    }

    if (url.startsWith("/api/")) {
      if (!ensureDatabaseOrFail(res)) {
        return;
      }

      await ensureSchema();
    }

    if (method === "POST" && url === "/api/signup") {
      const clientIp = getClientIp(req);
      if (isRateLimited(clientIp)) {
        sendJSON(res, 429, { error: "Too many attempts. Please try again later." });
        return;
      }

      const { email, password } = await parseJSONBody(req);
      if (!isEmail(email)) {
        sendJSON(res, 400, { error: "Valid email is required." });
        return;
      }
      if (!isValidPassword(password)) {
        sendJSON(res, 400, { error: "Password must be at least 8 characters." });
        return;
      }

      const normalizedEmail = email.toLowerCase();
      const db = getPool();

      const existing = await db.query(
        "SELECT id, email, password_hash FROM users WHERE email = $1 LIMIT 1",
        [normalizedEmail]
      );
      const existingUser = existing.rows[0];

      // Signup with existing credentials behaves like sign-in without revealing account existence.
      if (existingUser) {
        if (!verifyPassword(password, existingUser.password_hash)) {
          recordAuthFailure(clientIp);
          await applyAuthFailureDelay();
          sendJSON(res, 401, { error: AUTH_GENERIC_ERROR });
          return;
        }

        const sid = await createSession(db, existingUser.id);
        clearAuthFailures(clientIp);
        sendJSON(
          res,
          200,
          { ok: true, email: existingUser.email },
          {
            "Set-Cookie": buildSessionCookie(req, sid, SESSION_TTL_MS / 1000),
          }
        );
        return;
      }

      const userInsert = await db.query(
        "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email",
        [normalizedEmail, hashPassword(password)]
      );

      const user = userInsert.rows[0];
      const sid = await createSession(db, user.id);
      clearAuthFailures(clientIp);
      sendJSON(
        res,
        201,
        { ok: true, email: user.email },
        {
          "Set-Cookie": buildSessionCookie(req, sid, SESSION_TTL_MS / 1000),
        }
      );
      return;
    }

    if (method === "POST" && url === "/api/login") {
      const clientIp = getClientIp(req);
      if (isRateLimited(clientIp)) {
        sendJSON(res, 429, { error: "Too many attempts. Please try again later." });
        return;
      }

      const { email, password } = await parseJSONBody(req);
      const normalizedEmail = String(email || "").toLowerCase();
      const db = getPool();

      const result = await db.query(
        "SELECT id, email, password_hash FROM users WHERE email = $1 LIMIT 1",
        [normalizedEmail]
      );
      const user = result.rows[0];

      if (!user || !verifyPassword(String(password || ""), user.password_hash)) {
        // Burn comparable CPU for unknown users to reduce account-enumeration timing signals.
        if (!user) {
          verifyPassword(String(password || ""), DUMMY_PASSWORD_HASH);
        }
        recordAuthFailure(clientIp);
        await applyAuthFailureDelay();
        sendJSON(res, 401, { error: AUTH_GENERIC_ERROR });
        return;
      }

      const sid = await createSession(db, user.id);
      clearAuthFailures(clientIp);
      sendJSON(
        res,
        200,
        { ok: true, email: user.email },
        {
          "Set-Cookie": buildSessionCookie(req, sid, SESSION_TTL_MS / 1000),
        }
      );
      return;
    }

    if (method === "POST" && url === "/api/logout") {
      await clearSession(req);
      sendJSON(
        res,
        200,
        { ok: true },
        {
          "Set-Cookie": buildExpiredSessionCookie(req),
        }
      );
      return;
    }

    if (method === "GET" && url === "/api/me") {
      const user = await getAuthenticatedUser(req);
      if (!user) {
        sendJSON(res, 401, { error: "Not authenticated." });
        return;
      }

      sendJSON(res, 200, { email: user.email });
      return;
    }

    if (method === "GET" && url === "/api/painting") {
      const user = await getAuthenticatedUser(req);
      if (!user) {
        sendJSON(res, 401, { error: "Not authenticated." });
        return;
      }

      const db = getPool();
      const result = await db.query("SELECT painting FROM users WHERE id = $1 LIMIT 1", [user.id]);
      sendJSON(res, 200, { imageData: result.rows[0]?.painting || null });
      return;
    }

    if (method === "POST" && url === "/api/painting") {
      const user = await getAuthenticatedUser(req);
      if (!user) {
        sendJSON(res, 401, { error: "Not authenticated." });
        return;
      }

      const { imageData } = await parseJSONBody(req);
      if (!hasValidPngDataUrl(imageData)) {
        sendJSON(res, 400, { error: "Invalid image payload." });
        return;
      }

      const db = getPool();
      await db.query("UPDATE users SET painting = $1 WHERE id = $2", [imageData, user.id]);
      sendJSON(res, 200, { ok: true });
      return;
    }

    sendText(res, 404, "Not found");
  } catch (error) {
    sendJSON(res, 500, { error: "Server error." });
  }
}

if (require.main === module) {
  const server = http.createServer(handleRequest);
  server.listen(PORT, () => {
    console.log(`Paint app running at http://localhost:${PORT}`);
  });
} else {
  module.exports = (req, res) => handleRequest(req, res);
}
