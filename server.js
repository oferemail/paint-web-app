const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const DB_PATH = path.join(__dirname, "db.json");

const sessions = new Map();

const staticFiles = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/index.html": { file: "index.html", type: "text/html; charset=utf-8" },
  "/styles.css": { file: "styles.css", type: "text/css; charset=utf-8" },
  "/app.js": { file: "app.js", type: "application/javascript; charset=utf-8" },
};

function loadDB() {
  if (!fs.existsSync(DB_PATH)) {
    return { users: {} };
  }

  try {
    const raw = fs.readFileSync(DB_PATH, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed.users || typeof parsed.users !== "object") {
      return { users: {} };
    }
    return parsed;
  } catch {
    return { users: {} };
  }
}

function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
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

function getAuthenticatedEmail(req) {
  const sid = parseCookies(req).sid;
  if (!sid) return null;

  const session = sessions.get(sid);
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    sessions.delete(sid);
    return null;
  }

  return session.email;
}

function createSession(email) {
  const sid = crypto.randomBytes(24).toString("hex");
  sessions.set(sid, { email, expiresAt: Date.now() + SESSION_TTL_MS });
  return sid;
}

function clearSession(req) {
  const sid = parseCookies(req).sid;
  if (sid) {
    sessions.delete(sid);
  }
}

function isEmail(value) {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isValidPassword(value) {
  return typeof value === "string" && value.length >= 8;
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

    if (method === "POST" && url === "/api/signup") {
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
      const db = loadDB();
      if (db.users[normalizedEmail]) {
        sendJSON(res, 409, { error: "Account already exists." });
        return;
      }

      db.users[normalizedEmail] = {
        passwordHash: hashPassword(password),
        painting: null,
      };
      saveDB(db);

      const sid = createSession(normalizedEmail);
      sendJSON(
        res,
        201,
        { ok: true, email: normalizedEmail },
        {
          "Set-Cookie": `sid=${sid}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`,
        }
      );
      return;
    }

    if (method === "POST" && url === "/api/login") {
      const { email, password } = await parseJSONBody(req);
      const normalizedEmail = String(email || "").toLowerCase();
      const db = loadDB();
      const user = db.users[normalizedEmail];

      if (!user || !verifyPassword(String(password || ""), user.passwordHash)) {
        sendJSON(res, 401, { error: "Invalid credentials." });
        return;
      }

      const sid = createSession(normalizedEmail);
      sendJSON(
        res,
        200,
        { ok: true, email: normalizedEmail },
        {
          "Set-Cookie": `sid=${sid}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`,
        }
      );
      return;
    }

    if (method === "POST" && url === "/api/logout") {
      clearSession(req);
      sendJSON(
        res,
        200,
        { ok: true },
        {
          "Set-Cookie": "sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0",
        }
      );
      return;
    }

    if (method === "GET" && url === "/api/me") {
      const email = getAuthenticatedEmail(req);
      if (!email) {
        sendJSON(res, 401, { error: "Not authenticated." });
        return;
      }

      sendJSON(res, 200, { email });
      return;
    }

    if (method === "GET" && url === "/api/painting") {
      const email = getAuthenticatedEmail(req);
      if (!email) {
        sendJSON(res, 401, { error: "Not authenticated." });
        return;
      }

      const db = loadDB();
      const user = db.users[email];
      sendJSON(res, 200, { imageData: user?.painting || null });
      return;
    }

    if (method === "POST" && url === "/api/painting") {
      const email = getAuthenticatedEmail(req);
      if (!email) {
        sendJSON(res, 401, { error: "Not authenticated." });
        return;
      }

      const { imageData } = await parseJSONBody(req);
      if (
        typeof imageData !== "string" ||
        !imageData.startsWith("data:image/png;base64,") ||
        imageData.length > 5 * 1024 * 1024
      ) {
        sendJSON(res, 400, { error: "Invalid image payload." });
        return;
      }

      const db = loadDB();
      if (!db.users[email]) {
        sendJSON(res, 404, { error: "User not found." });
        return;
      }

      db.users[email].painting = imageData;
      saveDB(db);
      sendJSON(res, 200, { ok: true });
      return;
    }

    sendText(res, 404, "Not found");
  } catch (error) {
    sendJSON(res, 500, { error: error.message || "Server error" });
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
