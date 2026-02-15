const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

function env(name, fallback = "") {
  return String(process.env[name] ?? fallback).trim();
}

const PORT = process.env.PORT || 3000;
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const AUTH_WINDOW_MS = 15 * 60 * 1000;
const AUTH_MAX_ATTEMPTS = 12;
const AUTH_FAILURE_DELAY_MS = 250;
const AUTH_FAILURE_JITTER_MS = 250;
const PASSWORD_RESET_TOKEN_TTL_MS = 1000 * 60 * 30;
const PASSWORD_RESET_IP_MAX_ATTEMPTS = 8;
const PASSWORD_RESET_WINDOW_MS = 15 * 60 * 1000;
const AUTH_GENERIC_ERROR = "Invalid email or password.";
const FORGOT_GENERIC_MESSAGE = "If an account exists for that email, a reset link has been sent.";
const DATABASE_URL =
  env("POSTGRES_URL") ||
  env("DATABASE_URL") ||
  env("POSTGRES_PRISMA_URL") ||
  env("POSTGRES_URL_NON_POOLING") ||
  "";
const APP_BASE_URL = env("APP_BASE_URL");
const RESEND_API_KEY = env("RESEND_API_KEY");
const RESEND_FROM = env("RESEND_FROM", "Paint App <onboarding@resend.dev>");
const GOOGLE_CLIENT_ID = env("GOOGLE_CLIENT_ID");
const GOOGLE_CLIENT_SECRET = env("GOOGLE_CLIENT_SECRET");
const OPENAI_API_KEY = env("OPENAI_API_KEY");
const OPENAI_IMAGE_MODEL = env("OPENAI_IMAGE_MODEL", "gpt-image-1");
const MAGIC_WINDOW_MS = 15 * 60 * 1000;
const MAGIC_MAX_ATTEMPTS = 10;
const MAGIC_STYLES = {
  photoreal:
    "Transform this sketch into a photorealistic image. Preserve the exact subject layout and major shapes from the input drawing. Add realistic materials, natural lighting, and coherent details.",
  cinematic:
    "Transform this sketch into a realistic cinematic scene. Keep the same composition from the sketch, with dramatic film lighting, atmospheric depth, and high-detail textures.",
  fantasy:
    "Transform this sketch into realistic fantasy concept art. Preserve the original composition, while adding believable textures, environmental storytelling, and rich but realistic lighting.",
};

const staticFiles = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/index.html": { file: "index.html", type: "text/html; charset=utf-8" },
  "/styles.css": { file: "styles.css", type: "text/css; charset=utf-8" },
  "/app.js": { file: "app.js", type: "application/javascript; charset=utf-8" },
  "/reset-password": { file: "reset-password.html", type: "text/html; charset=utf-8" },
  "/reset-password.html": { file: "reset-password.html", type: "text/html; charset=utf-8" },
  "/reset-password.js": { file: "reset-password.js", type: "application/javascript; charset=utf-8" },
};

let pool = null;
let schemaReadyPromise = null;
const authAttempts = new Map();
const resetAttempts = new Map();
const magicAttempts = new Map();
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
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          token_hash TEXT UNIQUE NOT NULL,
          expires_at TIMESTAMPTZ NOT NULL,
          used_at TIMESTAMPTZ,
          requested_ip TEXT,
          user_agent TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await db.query(`
        CREATE TABLE IF NOT EXISTS oauth_accounts (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          provider TEXT NOT NULL,
          provider_subject TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          UNIQUE (provider, provider_subject)
        );
      `);

      await db.query(`
        CREATE TABLE IF NOT EXISTS oauth_states (
          id BIGSERIAL PRIMARY KEY,
          state_hash TEXT UNIQUE NOT NULL,
          provider TEXT NOT NULL,
          code_verifier TEXT,
          expires_at TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      await db.query(`
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
        ON sessions (expires_at);
      `);

      await db.query(`
        CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user
        ON password_reset_tokens (user_id, expires_at);
      `);

      await db.query(`
        CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at
        ON oauth_states (expires_at);
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
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    ...headers,
  });
  res.end(JSON.stringify(payload));
}

function sendText(res, statusCode, text) {
  res.writeHead(statusCode, {
    "Cache-Control": "no-store",
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  });
  res.end(text);
}

function sendRedirect(res, location, headers = {}) {
  res.writeHead(302, {
    Location: location,
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    ...headers,
  });
  res.end();
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

function hashResetToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function createSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

function createResetToken() {
  return crypto.randomBytes(32).toString("hex");
}

function createOauthState() {
  return crypto.randomBytes(32).toString("hex");
}

function hashState(state) {
  return crypto.createHash("sha256").update(state).digest("hex");
}

function createCodeVerifier() {
  return crypto.randomBytes(48).toString("base64url");
}

function createCodeChallenge(codeVerifier) {
  return crypto.createHash("sha256").update(codeVerifier).digest("base64url");
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

function isValidResetToken(token) {
  return typeof token === "string" && /^[a-f0-9]{64}$/.test(token);
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

function getAttemptState(map, key, windowMs) {
  const now = Date.now();
  const current = map.get(key);

  if (!current || now - current.windowStart > windowMs) {
    const reset = { count: 0, windowStart: now };
    map.set(key, reset);
    return reset;
  }

  return current;
}

function isRateLimitedWithMap(map, key, windowMs, maxAttempts) {
  const state = getAttemptState(map, key, windowMs);
  return state.count >= maxAttempts;
}

function recordAttemptWithMap(map, key, windowMs) {
  const state = getAttemptState(map, key, windowMs);
  state.count += 1;
  map.set(key, state);
}

function isAuthRateLimited(ip) {
  return isRateLimitedWithMap(authAttempts, ip, AUTH_WINDOW_MS, AUTH_MAX_ATTEMPTS);
}

function recordAuthFailure(ip) {
  recordAttemptWithMap(authAttempts, ip, AUTH_WINDOW_MS);
}

function clearAuthFailures(ip) {
  authAttempts.delete(ip);
}

function isForgotRateLimited(ip) {
  return isRateLimitedWithMap(resetAttempts, `ip:${ip}`, PASSWORD_RESET_WINDOW_MS, PASSWORD_RESET_IP_MAX_ATTEMPTS);
}

function recordForgotAttempt(ip) {
  recordAttemptWithMap(resetAttempts, `ip:${ip}`, PASSWORD_RESET_WINDOW_MS);
}

function isMagicRateLimited(ip) {
  return isRateLimitedWithMap(magicAttempts, `ip:${ip}`, MAGIC_WINDOW_MS, MAGIC_MAX_ATTEMPTS);
}

function recordMagicAttempt(ip) {
  recordAttemptWithMap(magicAttempts, `ip:${ip}`, MAGIC_WINDOW_MS);
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

function getBaseUrl(req) {
  if (APP_BASE_URL) {
    return APP_BASE_URL.replace(/\/$/, "");
  }

  const protocol = req.headers["x-forwarded-proto"] || "http";
  return `${protocol}://${req.headers.host}`;
}

function getOauthProviderConfig(provider, req) {
  const baseUrl = getBaseUrl(req);

  if (provider === "google") {
    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) return null;
    return {
      provider: "google",
      clientId: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackUrl: `${baseUrl}/api/oauth/google/callback`,
      authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenUrl: "https://oauth2.googleapis.com/token",
      userInfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
      scopes: ["openid", "email", "profile"],
    };
  }

  return null;
}

function getEnabledOauthProviders(req) {
  return {
    google: Boolean(getOauthProviderConfig("google", req)),
  };
}

async function createOauthStateRecord(db, provider, codeVerifier = null) {
  const state = createOauthState();
  const stateHash = hashState(state);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  await db.query(
    "INSERT INTO oauth_states (state_hash, provider, code_verifier, expires_at) VALUES ($1, $2, $3, $4)",
    [stateHash, provider, codeVerifier, expiresAt]
  );
  return state;
}

async function consumeOauthStateRecord(db, provider, state) {
  const stateHash = hashState(state);
  const result = await db.query(
    `
      DELETE FROM oauth_states
      WHERE state_hash = $1
        AND provider = $2
        AND expires_at > NOW()
      RETURNING provider, code_verifier
    `,
    [stateHash, provider]
  );
  return result.rows[0] || null;
}

async function exchangeGoogleCodeForProfile(config, code, codeVerifier) {
  const tokenResponse = await fetch(config.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: config.clientId,
      client_secret: config.clientSecret,
      redirect_uri: config.callbackUrl,
      grant_type: "authorization_code",
      code_verifier: codeVerifier || "",
    }),
  });
  if (!tokenResponse.ok) throw new Error("oauth_token_error");
  const tokenData = await tokenResponse.json();

  const profileResponse = await fetch(config.userInfoUrl, {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  });
  if (!profileResponse.ok) throw new Error("oauth_profile_error");
  const profile = await profileResponse.json();
  return {
    subject: String(profile.sub || ""),
    email: String(profile.email || "").toLowerCase(),
  };
}

async function findOrCreateOauthUser(db, provider, subject, email) {
  const byOauth = await db.query(
    `
      SELECT u.id, u.email
      FROM oauth_accounts oa
      JOIN users u ON u.id = oa.user_id
      WHERE oa.provider = $1 AND oa.provider_subject = $2
      LIMIT 1
    `,
    [provider, subject]
  );
  if (byOauth.rows[0]) return byOauth.rows[0];

  let user = null;
  if (isEmail(email)) {
    const byEmail = await db.query("SELECT id, email FROM users WHERE email = $1 LIMIT 1", [email]);
    user = byEmail.rows[0] || null;
  }

  if (!user) {
    const fallbackEmail = isEmail(email) ? email : `${provider}-${subject}@oauth.local`;
    const created = await db.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email",
      [fallbackEmail, hashPassword(createSessionId())]
    );
    user = created.rows[0];
  }

  await db.query(
    `
      INSERT INTO oauth_accounts (user_id, provider, provider_subject)
      VALUES ($1, $2, $3)
      ON CONFLICT (provider, provider_subject) DO NOTHING
    `,
    [user.id, provider, subject]
  );

  return user;
}

function isAllowedRequestOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) {
    return true;
  }

  const host = req.headers.host;
  if (!host) {
    return false;
  }

  const expectedHttp = `http://${host}`;
  const expectedHttps = `https://${host}`;
  return origin === expectedHttp || origin === expectedHttps;
}

function enforceSameOriginForWrites(req, res) {
  if (req.method !== "POST") {
    return true;
  }

  if (isAllowedRequestOrigin(req)) {
    return true;
  }

  sendJSON(res, 403, { error: "Forbidden." });
  return false;
}

async function sendPasswordResetEmail(email, resetLink) {
  const subject = "Reset your Paint app password";
  const text = [
    "You requested a password reset.",
    "",
    `Use this link (valid for 30 minutes): ${resetLink}`,
    "",
    "If you did not request this, you can ignore this email.",
  ].join("\n");

  const html = `
    <p>You requested a password reset.</p>
    <p><a href="${resetLink}">Reset password</a> (valid for 30 minutes).</p>
    <p>If you did not request this, you can ignore this email.</p>
  `;

  if (RESEND_API_KEY) {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: RESEND_FROM,
        to: [email],
        subject,
        text,
        html,
      }),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`resend_error:${response.status}:${errorBody}`);
    }
    return;
  }

}

function parsePngDataUrl(dataUrl) {
  if (!hasValidPngDataUrl(dataUrl)) {
    return null;
  }

  const base64Payload = dataUrl.slice("data:image/png;base64,".length);
  try {
    return Buffer.from(base64Payload, "base64");
  } catch {
    return null;
  }
}

async function generateMagicImage(imageData, styleKey) {
  const stylePrompt = MAGIC_STYLES[styleKey];
  if (!stylePrompt) {
    throw new Error("invalid_style");
  }

  if (!OPENAI_API_KEY) {
    throw new Error("openai_not_configured");
  }

  const imageBuffer = parsePngDataUrl(imageData);
  if (!imageBuffer) {
    throw new Error("invalid_image");
  }

  const candidateModels = [
    OPENAI_IMAGE_MODEL,
    "gpt-image-1",
    "gpt-image-1-mini",
  ].filter((value, index, all) => value && all.indexOf(value) === index);

  let lastError = null;

  for (const model of candidateModels) {
    const fieldNames = ["image", "image[]"];

    for (const fieldName of fieldNames) {
      const form = new FormData();
      form.append("model", model);
      form.append("prompt", stylePrompt);
      form.append("size", "1024x1024");
      form.append("response_format", "b64_json");
      form.append(fieldName, new Blob([imageBuffer], { type: "image/png" }), "canvas.png");

      const response = await fetch("https://api.openai.com/v1/images/edits", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
        },
        body: form,
      });

      if (!response.ok) {
        const errText = await response.text();
        lastError = new Error(`openai_error:${response.status}:${errText.slice(0, 500)}`);
        continue;
      }

      const payload = await response.json();
      const item = payload?.data?.[0];
      const b64 = item?.b64_json;
      if (b64 && typeof b64 === "string") {
        return `data:image/png;base64,${b64}`;
      }

      const imageUrl = item?.url;
      if (imageUrl && typeof imageUrl === "string") {
        const imageResponse = await fetch(imageUrl);
        if (!imageResponse.ok) {
          throw new Error("invalid_openai_image_url");
        }
        const arr = await imageResponse.arrayBuffer();
        return `data:image/png;base64,${Buffer.from(arr).toString("base64")}`;
      }

      lastError = new Error("invalid_openai_response");
    }
  }

  if (lastError) {
    throw lastError;
  }
  throw new Error("openai_error:unknown");
}

async function handleRequest(req, res) {
  try {
    const rawUrl = req.url || "/";
    const requestUrl = new URL(rawUrl, getBaseUrl(req));
    const url = requestUrl.pathname;
    const { method } = req;

    if (!enforceSameOriginForWrites(req, res)) {
      return;
    }

    if (method === "GET" && staticFiles[url]) {
      const filePath = path.join(__dirname, staticFiles[url].file);
      if (!fs.existsSync(filePath)) {
        sendText(res, 404, "Not found");
        return;
      }

      res.writeHead(200, {
        "Content-Type": staticFiles[url].type,
        "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
      });
      fs.createReadStream(filePath).pipe(res);
      return;
    }

    if (url.startsWith("/api/")) {
      if (!ensureDatabaseOrFail(res)) {
        return;
      }

      await ensureSchema();
    }

    if (method === "GET" && url === "/api/oauth/providers") {
      sendJSON(res, 200, getEnabledOauthProviders(req));
      return;
    }

    if (method === "GET" && url === "/api/oauth/google/start") {
      const provider = "google";
      const config = getOauthProviderConfig(provider, req);
      if (!config) {
        sendJSON(res, 404, { error: "OAuth provider not configured." });
        return;
      }

      const db = getPool();
      const codeVerifier = createCodeVerifier();
      const state = await createOauthStateRecord(db, provider, codeVerifier);

      const authUrl = new URL(config.authUrl);
      authUrl.searchParams.set("client_id", config.clientId);
      authUrl.searchParams.set("redirect_uri", config.callbackUrl);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("scope", config.scopes.join(" "));
      authUrl.searchParams.set("state", state);

      authUrl.searchParams.set("code_challenge", createCodeChallenge(codeVerifier));
      authUrl.searchParams.set("code_challenge_method", "S256");
      authUrl.searchParams.set("access_type", "online");
      authUrl.searchParams.set("prompt", "select_account");

      sendRedirect(res, authUrl.toString());
      return;
    }

    if (method === "GET" && url === "/api/oauth/google/callback") {
      const provider = "google";
      const config = getOauthProviderConfig(provider, req);
      if (!config) {
        sendRedirect(res, "/?oauth_error=provider_not_configured");
        return;
      }

      const error = requestUrl.searchParams.get("error");
      if (error) {
        sendRedirect(res, "/?oauth_error=access_denied");
        return;
      }

      const code = requestUrl.searchParams.get("code") || "";
      const state = requestUrl.searchParams.get("state") || "";
      if (!code || !state) {
        sendRedirect(res, "/?oauth_error=invalid_callback");
        return;
      }

      const db = getPool();
      const stateRecord = await consumeOauthStateRecord(db, provider, state);
      if (!stateRecord) {
        sendRedirect(res, "/?oauth_error=invalid_state");
        return;
      }

      const oauthProfile = await exchangeGoogleCodeForProfile(config, code, stateRecord.code_verifier);

      if (!oauthProfile.subject) {
        sendRedirect(res, "/?oauth_error=invalid_profile");
        return;
      }

      const user = await findOrCreateOauthUser(db, provider, oauthProfile.subject, oauthProfile.email);
      const sid = await createSession(db, user.id);
      sendRedirect(res, "/", {
        "Set-Cookie": buildSessionCookie(req, sid, SESSION_TTL_MS / 1000),
      });
      return;
    }

    if (method === "POST" && url === "/api/signup") {
      const clientIp = getClientIp(req);
      if (isAuthRateLimited(clientIp)) {
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
      if (isAuthRateLimited(clientIp)) {
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

    if (method === "POST" && url === "/api/forgot-password") {
      const clientIp = getClientIp(req);
      const { email } = await parseJSONBody(req);
      const normalizedEmail = String(email || "").trim().toLowerCase();

      if (!isEmail(normalizedEmail)) {
        await applyAuthFailureDelay();
        sendJSON(res, 200, { ok: true, message: FORGOT_GENERIC_MESSAGE });
        return;
      }

      if (isForgotRateLimited(clientIp)) {
        await applyAuthFailureDelay();
        sendJSON(res, 200, { ok: true, message: FORGOT_GENERIC_MESSAGE });
        return;
      }

      recordForgotAttempt(clientIp);

      const db = getPool();
      const userResult = await db.query("SELECT id, email FROM users WHERE email = $1 LIMIT 1", [
        normalizedEmail,
      ]);
      const user = userResult.rows[0];

      if (user) {
        // Enforce one reset email per account per 15 minutes using DB state.
        const recentResetResult = await db.query(
          `
            SELECT 1
            FROM password_reset_tokens
            WHERE user_id = $1
              AND created_at > NOW() - INTERVAL '15 minutes'
            LIMIT 1
          `,
          [user.id]
        );

        if (recentResetResult.rows[0]) {
          await applyAuthFailureDelay();
          sendJSON(res, 200, { ok: true, message: FORGOT_GENERIC_MESSAGE });
          return;
        }

        const token = createResetToken();
        const tokenHash = hashResetToken(token);
        const expiresAt = new Date(Date.now() + PASSWORD_RESET_TOKEN_TTL_MS);
        const userAgent = String(req.headers["user-agent"] || "").slice(0, 1024);
        const resetLink = `${getBaseUrl(req)}/reset-password.html?token=${encodeURIComponent(token)}`;

        await db.query("DELETE FROM password_reset_tokens WHERE expires_at <= NOW() OR used_at IS NOT NULL");
        await db.query(
          `
            INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, requested_ip, user_agent)
            VALUES ($1, $2, $3, $4, $5)
          `,
          [user.id, tokenHash, expiresAt, clientIp, userAgent]
        );

        try {
          await sendPasswordResetEmail(user.email, resetLink);
        } catch (error) {
          console.error("password reset email send failure", error);
        }
      }

      await applyAuthFailureDelay();
      sendJSON(res, 200, { ok: true, message: FORGOT_GENERIC_MESSAGE });
      return;
    }

    if (method === "POST" && url === "/api/reset-password") {
      const { token, password } = await parseJSONBody(req);

      if (!isValidResetToken(token)) {
        sendJSON(res, 400, { error: "Invalid or expired reset link." });
        return;
      }

      if (!isValidPassword(password)) {
        sendJSON(res, 400, { error: "Password must be at least 8 characters." });
        return;
      }

      const db = getPool();
      const tokenHash = hashResetToken(token);
      const client = await db.connect();

      try {
        await client.query("BEGIN");

        const resetResult = await client.query(
          `
            SELECT id, user_id
            FROM password_reset_tokens
            WHERE token_hash = $1
              AND used_at IS NULL
              AND expires_at > NOW()
            FOR UPDATE
            LIMIT 1
          `,
          [tokenHash]
        );

        const row = resetResult.rows[0];
        if (!row) {
          await client.query("ROLLBACK");
          sendJSON(res, 400, { error: "Invalid or expired reset link." });
          return;
        }

        await client.query("UPDATE users SET password_hash = $1 WHERE id = $2", [
          hashPassword(password),
          row.user_id,
        ]);
        await client.query("UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1", [row.id]);
        await client.query("DELETE FROM sessions WHERE user_id = $1", [row.user_id]);

        await client.query("COMMIT");
        sendJSON(res, 200, { ok: true });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }

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

    if (method === "POST" && url === "/api/magic-transform") {
      const user = await getAuthenticatedUser(req);
      if (!user) {
        sendJSON(res, 401, { error: "Not authenticated." });
        return;
      }

      const clientIp = getClientIp(req);
      if (isMagicRateLimited(clientIp)) {
        sendJSON(res, 429, { error: "Too many requests. Please try again later." });
        return;
      }

      const { imageData, style } = await parseJSONBody(req);
      if (!hasValidPngDataUrl(imageData)) {
        sendJSON(res, 400, { error: "Invalid image payload." });
        return;
      }

      if (!Object.prototype.hasOwnProperty.call(MAGIC_STYLES, String(style || ""))) {
        sendJSON(res, 400, { error: "Invalid style." });
        return;
      }

      recordMagicAttempt(clientIp);

      try {
        const generatedImageData = await generateMagicImage(imageData, String(style));
        sendJSON(res, 200, { imageData: generatedImageData });
      } catch (error) {
        console.error("magic transform failure", error);
        if (String(error.message || "").startsWith("openai_not_configured")) {
          sendJSON(res, 503, { error: "Magic feature not configured yet." });
          return;
        }
        if (
          String(error.message || "").startsWith("openai_error:401") ||
          String(error.message || "").startsWith("openai_error:403")
        ) {
          sendJSON(res, 503, { error: "Magic is unavailable. Check OpenAI API billing/verification." });
          return;
        }
        if (String(error.message || "").startsWith("openai_error:429")) {
          sendJSON(res, 503, { error: "Magic is unavailable. OpenAI quota/billing limit reached." });
          return;
        }
        if (String(error.message || "").startsWith("openai_error:400")) {
          sendJSON(res, 422, { error: "Magic could not process this sketch. Try a clearer drawing and retry." });
          return;
        }
        sendJSON(res, 502, { error: "Magic generation failed. Please try again." });
      }
      return;
    }

    sendText(res, 404, "Not found");
  } catch (error) {
    console.error("server error", error);
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
