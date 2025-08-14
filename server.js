// server.js
// Auth API sederhana tapi aman: Express + JWT (access token) + Session cookie
// Fitur: signup, login, logout, me (profile), rate limit, helmet, CORS, argon2 hashing,
// sesi tersimpan di SQLite (connect-sqlite3), tokenVersion untuk mematikan token lama saat logout.

require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const morgan = require("morgan");

// ====== Konfigurasi dari ENV ======
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:5173";
const SESSION_SECRET =
   process.env.SESSION_SECRET || "change-this-session-secret";
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true"; // true di production (https)

// ====== Database ======
const db = new Database(process.env.DB_PATH || "./app.db");
db.pragma("journal_mode = WAL");

// ====== Database ======
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  token_version INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
`);

// ====== App ======
const app = express();

// Logging HTTP
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// trust proxy jika di belakang reverse proxy (Render/Heroku/Nginx)
if (process.env.TRUST_PROXY === "true") {
   app.set("trust proxy", 1);
}

app.use(
   helmet({
      crossOriginResourcePolicy: { policy: "cross-origin" },
   })
);

app.use(
   cors({
      origin: CORS_ORIGIN,
      credentials: true,
   })
);

app.use(express.json({ limit: "10kb" }));

// Session store di SQLite (persisten)
app.use(
   session({
      store: new SQLiteStore({ db: "sessions.sqlite", dir: "./" }),
      name: "sid",
      secret: SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
         httpOnly: true,
         sameSite: "lax",
         secure: COOKIE_SECURE, // aktifkan di production (HTTPS)
         maxAge: 1000 * 60 * 60 * 24 * 7, // 7 hari
      },
   })
);

// Rate limit untuk endpoint auth
const authLimiter = rateLimit({
   windowMs: 15 * 60 * 1000,
   limit: 100,
   standardHeaders: "draft-7",
   legacyHeaders: false,
});
app.use(["/auth/signup", "/auth/login", "/auth/logout"], authLimiter);

// ====== Helper ======
// const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i;

// ====== Helper ======
function genJwt(user) {
   return jwt.sign({ sub: user.id, tv: user.token_version }, JWT_SECRET, {
      expiresIn: "15m",
   });
}

function pickUser(u) {
   return { id: u.id, username: u.username, created_at: u.created_at };
}

function getUserByUsername(username) {
   return db.prepare("SELECT * FROM users WHERE username = ?").get(username);
}

function getUserById(id) {
   return db.prepare("SELECT * FROM users WHERE id = ?").get(id);
}

// Middleware: validasi token JWT (opsional untuk route yang menerima keduanya)
function verifyToken(req, res, next) {
   const auth = req.headers.authorization;
   if (!auth || !auth.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing Bearer token" });
   }
   const token = auth.slice("Bearer ".length);
   try {
      const payload = jwt.verify(token, JWT_SECRET);
      const user = getUserById(payload.sub);
      if (!user) return res.status(401).json({ error: "User not found" });
      if (payload.tv !== user.token_version) {
         return res.status(401).json({ error: "Token revoked" });
      }
      req.user = pickUser(user);
      next();
   } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
   }
}

// Middleware: requires session login
function requireSession(req, res, next) {
   if (req.session && req.session.userId) {
      const user = getUserById(req.session.userId);
      if (user) {
         req.user = pickUser(user);
         return next();
      }
   }
   return res.status(401).json({ error: "Not authenticated (session)" });
}

// Middleware: menerima EITHER session atau token
function requireAuth(req, res, next) {
   if (req.session && req.session.userId) {
      const user = getUserById(req.session.userId);
      if (user) {
         req.user = pickUser(user);
         return next();
      }
   }
   const auth = req.headers.authorization;
   if (auth && auth.startsWith("Bearer ")) {
      try {
         const payload = jwt.verify(auth.slice(7), JWT_SECRET);
         const user = getUserById(payload.sub);
         if (user && payload.tv === user.token_version) {
            req.user = pickUser(user);
            return next();
         }
      } catch (e) {
         /* fallthrough */
      }
   }
   return res.status(401).json({ error: "Not authenticated" });
}

// ====== Routes ======
app.get("/", (req, res) => {
   res.json({ ok: true, message: "Auth API ready" });
});

// ====== Routes ======
app.post("/auth/signup", async (req, res) => {
   try {
      const { username, password } = req.body || {};
      if (!username || !password)
         return res.status(400).json({ error: "Username & password required" });
      if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
         return res
            .status(400)
            .json({
               error: "Username must be 3-20 chars, alphanumeric/underscore only",
            });
      if (password.length < 8)
         return res.status(400).json({ error: "Password min 8 chars" });

      const exists = getUserByUsername(username);
      if (exists)
         return res.status(409).json({ error: "Username already in use" });
      const id = uuidv4();
      const password_hash = await argon2.hash(password);
      const created_at = new Date().toISOString();
      db.prepare(
         "INSERT INTO users (id, username, password_hash, token_version, created_at) VALUES (?, ?, ?, 0, ?)"
      ).run(id, username, password_hash, created_at);

      req.session.userId = id;
      const user = getUserById(id);
      const token = genJwt(user);
      res.status(201).json({ user: pickUser(user), token });
   } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
   }
});

app.post("/auth/login", async (req, res) => {
   try {
      const { username, password } = req.body || {};
      if (!username || !password)
         return res.status(400).json({ error: "Username & password required" });
      const user = getUserByUsername(username);
      if (!user) return res.status(401).json({ error: "Invalid credentials" });
      const ok = await argon2.verify(user.password_hash, password);
      if (!ok) return res.status(401).json({ error: "Invalid credentials" });

      req.session.userId = user.id;
      const token = genJwt(user);
      res.json({ user: pickUser(user), token });
   } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
   }
});

app.post("/auth/logout", requireSession, (req, res) => {
   try {
      // Naikkan token_version untuk mematikan semua access token yang masih hidup
      db.prepare(
         "UPDATE users SET token_version = token_version + 1 WHERE id = ?"
      ).run(req.user.id);
      req.session.destroy((err) => {
         if (err) {
            console.error(err);
         }
         // Hapus cookie session di client
         res.clearCookie("sid", { path: "/" });
         return res.json({ ok: true });
      });
   } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
   }
});

// Contoh endpoint yang butuh auth (token ATAU session)
app.get("/auth/me", requireAuth, (req, res) => {
   res.json({ user: req.user });
});

// Contoh endpoint yang wajib token Bearer (mis. untuk akses dari mobile app)
app.get("/api/secure-data", verifyToken, (req, res) => {
   res.json({ message: "Data rahasia untuk " + req.user.username });
});

// 404 handler
app.use((req, res) => {
   res.status(404).json({ error: "Not found" });
});

// Error handler
app.use((err, req, res, next) => {
   console.error(err);
   res.status(500).json({ error: "Unexpected error" });
});

app.listen(PORT, () => {
   console.log(`Auth API listening on http://localhost:${PORT}`);
});

// ================= Additional Files for Deployment =================

/*
Procfile (Heroku)
--------------------------------------------------
web: node server.js
*/

/*
render.yaml (Render.com)
--------------------------------------------------
services:
  - type: web
    name: auth-api
    env: node
    plan: starter
    buildCommand: npm install
    startCommand: node server.js
    autoDeploy: true
    envVars:
      - key: NODE_ENV
        value: production
      - key: PORT
        value: 10000
      - key: JWT_SECRET
        generateValue: true
      - key: SESSION_SECRET
        generateValue: true
      - key: CORS_ORIGIN
        value: https://app-kamu.example.com
      - key: COOKIE_SECURE
        value: "true"
      - key: TRUST_PROXY
        value: "true"
      - key: DB_PATH
        value: /opt/render/project/src/app.db
    disks:
      - name: data
        mountPath: /opt/render/project/src
*/

/*
Dockerfile (opsional / untuk VPS)
--------------------------------------------------
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev || npm i --production
COPY . .
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "server.js"]
*/

/*
ecosystem.config.cjs (PM2 untuk VPS)
--------------------------------------------------
module.exports = {
  apps: [
    {
      name: 'auth-api',
      script: 'server.js',
      env: {
        NODE_ENV: 'production',
        PORT: 3000
      }
    }
  ]
}
*/
