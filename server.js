require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, "fasi.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS app_state (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS admin_user (id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL, password_hash TEXT NOT NULL);
`);
const initialState = JSON.parse(fs.readFileSync(path.join(DATA_DIR, "initial-state.json"), "utf8"));
if (!db.prepare("SELECT id FROM app_state WHERE id=1").get()) {
  db.prepare("INSERT INTO app_state (id,data) VALUES (1,?)").run(JSON.stringify(initialState));
}
if (!db.prepare("SELECT id FROM admin_user WHERE id=1").get()) {
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;
  if (!username || !password || password.length < 12) {
    console.error("Atur ADMIN_USERNAME dan ADMIN_PASSWORD (minimal 12 karakter) pada environment/.env sebelum menjalankan server.");
    process.exit(1);
  }
  db.prepare("INSERT INTO admin_user (id,username,password_hash) VALUES (1,?,?)")
    .run(username, bcrypt.hashSync(password, 12));
}

app.disable("x-powered-by");
app.set("trust proxy", process.env.TRUST_PROXY === "1" ? 1 : false);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "8mb" }));
const SQLiteStore = SQLiteStoreFactory(session);
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR, table: "sessions" }),
  name: "fasi_admin_session",
  secret: process.env.SESSION_SECRET || (() => { throw new Error("SESSION_SECRET belum diatur."); })(),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 *  60 * 1000,
  limit: 8,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Terlalu banyak percobaan login. Coba lagi 15 menit." }
});
function requireAdmin(req, res, next) {
  if (req.session && req.session.adminId === 1) return next();
  return res.status(401).json({ error: "Akses ditolak. Silakan login sebagai admin." });
}
function readState() {
  return JSON.parse(db.prepare("SELECT data FROM app_state WHERE id=1").get().data);
}
function writeState(data) {
  const safe = {
    settings: data.settings || {},
    berita: Array.isArray(data.berita) ? data.berita : [],
    venues: Array.isArray(data.venues) ? data.venues : [],
    wisata: Array.isArray(data.wisata) ? data.wisata : [],
    kuliner: Array.isArray(data.kuliner) ? data.kuliner : []
  };
  db.prepare("UPDATE app_state SET data=? WHERE id=1").run(JSON.stringify(safe));
  return safe;
}
app.get("/api/health", (_req, res) => res.json({ ok: true }));
app.get("/api/public/state", (_req, res) => res.json(readState()));

app.post("/api/auth/login", loginLimiter, (req, res, next) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string" || username.length > 100 || password.length > 200) {
    return res.status(400).json({ error: "Username atau password tidak valid." });
  }
  const admin = db.prepare("SELECT * FROM admin_user WHERE id=1").get();
  if (username !== admin.username || !bcrypt.compareSync(password, admin.password_hash)) {
    return res.status(401).json({ error: "Username atau password salah." });
  }
  req.session.regenerate(err => {
    if (err) return next(err);
    req.session.adminId = 1;
    res.json({ ok: true });
  });
});
app.get("/api/auth/me", (req, res) => res.json({ authenticated: req.session?.adminId === 1 }));
app.post("/api/auth/logout", (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("fasi_admin_session", { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production" });
    res.json({ ok: true });
  });
});
app.get("/api/admin/profile", requireAdmin, (_req, res) => {
  const admin = db.prepare("SELECT username FROM admin_user WHERE id=1").get();
  res.json({ username: admin.username });
});
app.get("/api/admin/state", requireAdmin, (_req, res) => res.json(readState()));
app.put("/api/admin/state", requireAdmin, (req, res) => {
  const body = req.body || {};
  if (!body.settings || !Array.isArray(body.berita) || !Array.isArray(body.venues) ||
      !Array.isArray(body.wisata) || !Array.isArray(body.kuliner)) {
    return res.status(400).json({ error: "Struktur data tidak valid." });
  }
  if (JSON.stringify(body).length > 7_500_000) return res.status(413).json({ error: "Ukuran data terlalu besar." });
  res.json({ ok: true, state: writeState(body) });
});
app.put("/api/admin/credentials", requireAdmin, (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || username.trim().length < 3 || username.length > 60)
    return res.status(400).json({ error: "Username minimal 3 dan maksimal 60 karakter." });
  if (typeof password !== "string" || password.length < 12 || password.length > 200)
    return res.status(400).json({ error: "Password minimal 12 karakter." });
  db.prepare("UPDATE admin_user SET username=?, password_hash=? WHERE id=1")
    .run(username.trim(), bcrypt.hashSync(password, 12));
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Kredensial berubah, tetapi sesi perlu login ulang." });
    req.session.adminId = 1;
    res.json({ ok: true });
  });
});

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Terjadi kesalahan pada server." });
});
app.listen(PORT, () => console.log(`Portal FASI berjalan di http://localhost:${PORT}`));
