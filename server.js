/**
 * SINGLE-FILE SERVER (Drop-in)
 * Express + ws + mysql2 + jwt
 *
 * Keeps compatibility with your existing API:
 * - /api/register, /api/login, /api/me, /api/rooms, /api/rooms/:id, /api/rooms/:id/messages, ...
 * Adds REST routes requested:
 * - /auth/register, /auth/login, /profile, /messages/:id, /points/grant, /rooms/:id/mute, /frames, /subscriptions, /bots...
 *
 * WebSocket protocol (type-based):
 * - auth -> join_room -> chat/edit/delete/moderate/seats/webrtc...
 */

require("dotenv").config();
const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json({ limit: "5mb" }));

const PORT = process.env.PORT || 3000;
const server = http.createServer(app);

/* ================== DB AUTO DETECT ================== */
function parseDbUrl(url) {
  const u = new URL(url);
  return {
    host: u.hostname,
    port: u.port ? Number(u.port) : 3306,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: u.pathname.replace("/", ""),
  };
}
function getDbConfigFromEnv() {
  if (process.env.MYSQLHOST && process.env.MYSQLUSER && process.env.MYSQLPASSWORD && process.env.MYSQLDATABASE) {
    return {
      host: process.env.MYSQLHOST,
      port: process.env.MYSQLPORT ? Number(process.env.MYSQLPORT) : 3306,
      user: process.env.MYSQLUSER,
      password: process.env.MYSQLPASSWORD,
      database: process.env.MYSQLDATABASE,
    };
  }
  const url = process.env.DATABASE_URL || process.env.MYSQL_URL;
  if (url) return parseDbUrl(url);
  return null;
}

const baseDb = getDbConfigFromEnv();
console.log("🔍 DB ENV CHECK", {
  MYSQLHOST: process.env.MYSQLHOST,
  MYSQLUSER: process.env.MYSQLUSER,
  MYSQLDATABASE: process.env.MYSQLDATABASE,
  MYSQL_URL: process.env.MYSQL_URL,
  MYSQL_PUBLIC_URL: process.env.MYSQL_PUBLIC_URL,
});
if (!baseDb) {
  console.error("❌ DB config not found.");
  process.exit(1);
}

const DB_CONFIG = {
  ...baseDb,
  waitForConnections: true,
  connectionLimit: 15,
  queueLimit: 0,
  ssl: process.env.MYSQL_SSL === "true" ? { rejectUnauthorized: false } : false,
};

let pool;

/* ================== JWT SECRET (ENV OR DB) ================== */
let JWT_SECRET = process.env.JWT_SECRET || null;

async function dbOne(sql, params) {
  const [rows] = await pool.execute(sql, params);
  return rows && rows.length ? rows[0] : null;
}
function nowIso() {
  return new Date().toISOString().slice(0, 19).replace("T", " ");
}
function safeJsonParse(s) {
  try { return JSON.parse(s); } catch { return null; }
}
function mustInt(n, def = 0) {
  const x = Number(n);
  return Number.isFinite(x) ? Math.trunc(x) : def;
}

/* ================== PASSWORD HASH (pbkdf2, supports legacy sha256) ================== */
function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function pbkdf2Hash(password, iters = 140000) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.pbkdf2Sync(String(password), salt, iters, 32, "sha256");
  return `pbkdf2$${iters}$${salt.toString("base64")}$${dk.toString("base64")}`;
}
function pbkdf2Verify(password, stored) {
  // "pbkdf2$iters$saltB64$hashB64"
  const parts = String(stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iters = Number(parts[1]);
  const salt = Buffer.from(parts[2], "base64");
  const hash = Buffer.from(parts[3], "base64");
  const dk = crypto.pbkdf2Sync(String(password), salt, iters, hash.length, "sha256");
  return crypto.timingSafeEqual(dk, hash);
}
function verifyPassword(password, stored) {
  const v = String(stored || "");
  // legacy sha256 hex
  if (/^[a-f0-9]{64}$/i.test(v)) return sha256Hex(password) === v;
  // pbkdf2 format
  if (v.startsWith("pbkdf2$")) return pbkdf2Verify(password, v);
  return false;
}

/* ================== DB bootstrap ================== */
async function ensureJwtSecret() {
  if (JWT_SECRET) return JWT_SECRET;

  const row = await dbOne("SELECT setting_value FROM server_settings WHERE setting_key=? LIMIT 1", ["jwt_secret"]);
  if (row?.setting_value) {
    JWT_SECRET = row.setting_value;
    return JWT_SECRET;
  }
  JWT_SECRET = crypto.randomBytes(48).toString("hex");
  await pool.execute(
    "INSERT INTO server_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)",
    ["jwt_secret", JWT_SECRET]
  );
  console.log("🔐 JWT_SECRET generated & stored in DB");
  return JWT_SECRET;
}

async function tryExec(sql) {
  try { await pool.execute(sql); } catch (e) { /* ignore duplicate/exists */ }
}

async function createTablesIfNotExist() {
  // base tables (compatible with your current server) + v2 additions
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS server_settings (
      setting_key VARCHAR(100) PRIMARY KEY,
      setting_value TEXT NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      pass_hash VARCHAR(255) NOT NULL,
      is_developer TINYINT DEFAULT 0,
      points INT DEFAULT 0,
      banned TINYINT DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS rooms (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(80) NOT NULL,
      type ENUM('text','voice') DEFAULT 'text',
      owner_user_id INT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS room_members (
      id INT AUTO_INCREMENT PRIMARY KEY,
      room_id INT NOT NULL,
      user_id INT NOT NULL,
      role ENUM('owner','developer','member') DEFAULT 'member',
      muted_until DATETIME NULL,
      restricted TINYINT DEFAULT 0,
      banned TINYINT DEFAULT 0,
      joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_room_user (room_id, user_id),
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS room_settings (
      room_id INT PRIMARY KEY,
      auto_delete_limit INT DEFAULT 0,
      chat_disabled TINYINT DEFAULT 0,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      room_id INT NOT NULL,
      user_id INT NOT NULL,
      text TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      edited_at DATETIME NULL,
      deleted TINYINT DEFAULT 0,
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_room_time (room_id, created_at)
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS point_transactions (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      from_user_id INT NULL,
      to_user_id INT NULL,
      amount INT NOT NULL,
      reason VARCHAR(150) NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS room_labels (
      id INT AUTO_INCREMENT PRIMARY KEY,
      room_id INT NOT NULL,
      user_id INT NOT NULL,
      label_text VARCHAR(40) NOT NULL,
      label_color VARCHAR(20) DEFAULT '#ff3b30',
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_label (room_id, user_id),
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS room_seats (
      id INT AUTO_INCREMENT PRIMARY KEY,
      room_id INT NOT NULL,
      seat_index INT NOT NULL,
      user_id INT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_seat (room_id, seat_index),
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
    )
  `);

  // ---- V2 migrations (safe adds) ----
  await tryExec(`ALTER TABLE users ADD COLUMN avatar_url TEXT NULL`);
  await tryExec(`ALTER TABLE users ADD COLUMN bio TEXT NULL`);
  await tryExec(`ALTER TABLE users ADD COLUMN links_json JSON NULL`);
  await tryExec(`ALTER TABLE users ADD COLUMN verified TINYINT DEFAULT 0`);
  await tryExec(`ALTER TABLE users ADD COLUMN frame_id INT NULL`);

  await tryExec(`ALTER TABLE rooms ADD COLUMN description TEXT NULL`);
  await tryExec(`ALTER TABLE rooms ADD COLUMN image_url TEXT NULL`);

  await tryExec(`ALTER TABLE room_settings ADD COLUMN chat_locked TINYINT DEFAULT 0`);
  await tryExec(`ALTER TABLE room_settings ADD COLUMN voice_enabled TINYINT DEFAULT 1`);
  await tryExec(`ALTER TABLE room_settings ADD COLUMN voice_seats_count INT DEFAULT 8`);

  await tryExec(`ALTER TABLE messages ADD COLUMN type VARCHAR(24) DEFAULT 'text'`);
  await tryExec(`ALTER TABLE messages ADD COLUMN metadata JSON NULL`);
  await tryExec(`ALTER TABLE messages ADD COLUMN deleted_at DATETIME NULL`);

  await tryExec(`ALTER TABLE room_seats ADD COLUMN seat_locked TINYINT DEFAULT 0`);
  await tryExec(`ALTER TABLE room_seats ADD COLUMN seat_muted TINYINT DEFAULT 0`);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS room_voice_bans (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      room_id INT NOT NULL,
      user_id INT NOT NULL,
      banned TINYINT DEFAULT 1,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_voice_ban (room_id, user_id),
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS frames (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(60) NOT NULL,
      description VARCHAR(160) NULL,
      css_class VARCHAR(80) NULL,
      image_url TEXT NULL,
      price_points INT DEFAULT 0,
      category VARCHAR(30) DEFAULT 'normal',
      available TINYINT DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS user_frames (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      frame_id INT NOT NULL,
      acquired_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_user_frame (user_id, frame_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (frame_id) REFERENCES frames(id) ON DELETE CASCADE
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS payment_methods (
      id INT AUTO_INCREMENT PRIMARY KEY,
      method_key VARCHAR(40) UNIQUE NOT NULL,
      display_name VARCHAR(60) NOT NULL,
      enabled TINYINT DEFAULT 1,
      config_json JSON NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      plan_key VARCHAR(40) UNIQUE NOT NULL,
      display_name VARCHAR(60) NOT NULL,
      price_usd DECIMAL(10,2) DEFAULT 0,
      price_points INT DEFAULT 0,
      features_json JSON NULL,
      enabled TINYINT DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS user_subscriptions (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      subscription_id INT NOT NULL,
      status ENUM('active','expired','canceled','pending') DEFAULT 'pending',
      started_at DATETIME NULL,
      expires_at DATETIME NULL,
      payment_method_id INT NULL,
      meta_json JSON NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_user_sub (user_id, status),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
      FOREIGN KEY (payment_method_id) REFERENCES payment_methods(id) ON DELETE SET NULL
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS bots (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      room_id INT NOT NULL,
      name VARCHAR(60) NOT NULL,
      avatar_url TEXT NULL,
      enabled TINYINT DEFAULT 1,
      created_by INT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS bot_commands (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      bot_id BIGINT NOT NULL,
      trigger_text VARCHAR(80) NOT NULL,
      response_text TEXT NOT NULL,
      match_mode ENUM('exact','starts_with','contains') DEFAULT 'exact',
      enabled TINYINT DEFAULT 1,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_bot_trigger (bot_id, trigger_text),
      FOREIGN KEY (bot_id) REFERENCES bots(id) ON DELETE CASCADE
    )
  `);

  // seed payment method placeholder
  await pool.execute(
    `INSERT IGNORE INTO payment_methods(method_key, display_name, enabled, config_json)
     VALUES ('master_iraq', 'Master عراق', 1, JSON_OBJECT('note','Placeholder gateway module'))`
  );

  console.log("✅ Tables ready (v2)");
}

async function initializeDatabase() {
  pool = await mysql.createPool(DB_CONFIG);
  await createTablesIfNotExist();
  await ensureJwtSecret();
}

/* ================== AUTH MIDDLEWARE ================== */
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "NO_TOKEN" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "BAD_TOKEN" });
  }
}

/* ================== PERMISSIONS ================== */
function roleRank(role) {
  if (role === "owner") return 3;
  if (role === "developer") return 2;
  return 1;
}
function isMuted(member) {
  if (!member?.muted_until) return false;
  return new Date(member.muted_until).getTime() > Date.now();
}
async function getRoomAndMember(roomId, userId) {
  const room = await dbOne("SELECT * FROM rooms WHERE id=? LIMIT 1", [roomId]);
  if (!room) return { room: null, member: null };
  const member = await dbOne("SELECT * FROM room_members WHERE room_id=? AND user_id=? LIMIT 1", [roomId, userId]);
  return { room, member };
}
async function ensureMember(roomId, userId) {
  return await dbOne("SELECT * FROM room_members WHERE room_id=? AND user_id=? LIMIT 1", [roomId, userId]);
}
async function ensureCanModerate(roomId, userId) {
  const m = await ensureMember(roomId, userId);
  return m ? roleRank(m.role) >= 2 : false;
}
async function ensureCanOwner(roomId, userId) {
  const m = await ensureMember(roomId, userId);
  return m?.role === "owner";
}

/* ================== REST API ================== */
app.get("/", (req, res) => res.send("OK"));

/** Auth (keep old + add new aliases) */
app.post(["/api/register", "/auth/register"], async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) return res.status(400).json({ error: "MISSING_FIELDS" });

  try {
    const ph = pbkdf2Hash(password);
    await pool.execute(
      "INSERT INTO users (username,email,pass_hash) VALUES (?,?,?)",
      [String(username).trim(), String(email).trim().toLowerCase(), ph]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: "USER_EXISTS" });
  }
});

app.post(["/api/login", "/auth/login"], async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ ok: false, error: "MISSING_FIELDS" });
  }

  const isEmail = email.includes("@");

  const user = await dbOne(
    isEmail
      ? "SELECT * FROM users WHERE email=? LIMIT 1"
      : "SELECT * FROM users WHERE username=? LIMIT 1",
    [login.trim().toLowerCase()]
  );

  if (!user) {
    return res.status(401).json({ ok: false, error: "BAD_CREDENTIALS" });
  }

  if (user.banned) {
    return res.status(403).json({ ok: false, error: "BANNED" });
  }

  const valid = verifyPassword(password, user.pass_hash);
  if (!valid) {
    return res.status(401).json({ ok: false, error: "BAD_CREDENTIALS" });
  }

  const token = jwt.sign(
    {
      id: user.id,
      username: user.username,
      is_developer: !!user.is_developer
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ ok: true, token });
});

app.get("/api/me", authMiddleware, async (req, res) => {
  const u = await dbOne(
    "SELECT id,username,email,avatar_url,bio,links_json,is_developer,verified,frame_id,points,banned,created_at FROM users WHERE id=? LIMIT 1",
    [req.user.id]
  );
  res.json({ ok: true, user: u });
});

/** Profile */
app.get("/profile", authMiddleware, async (req, res) => {
  const u = await dbOne(
    "SELECT id,username,avatar_url,bio,links_json,verified,frame_id,points,is_developer FROM users WHERE id=? LIMIT 1",
    [req.user.id]
  );
  res.json({ ok: true, profile: u });
});

app.put("/profile", authMiddleware, async (req, res) => {
  const avatar_url = req.body?.avatar_url ?? null;
  const bio = req.body?.bio ?? null;
  const links_json = req.body?.links_json ?? null;

  await pool.execute(
    "UPDATE users SET avatar_url=?, bio=?, links_json=? WHERE id=?",
    [avatar_url, bio, links_json ? JSON.stringify(links_json) : null, req.user.id]
  );

  res.json({ ok: true });
});

/** Rooms */
app.get("/api/rooms", authMiddleware, async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT r.*,
      (SELECT COUNT(*) FROM room_members rm WHERE rm.room_id=r.id AND rm.banned=0) AS members_count
     FROM rooms r
     ORDER BY r.id DESC
     LIMIT 200`
  );
  res.json({ ok: true, rooms: rows });
});

app.post("/api/rooms", authMiddleware, async (req, res) => {
  const { name, type, description, image_url } = req.body || {};
  const roomName = String(name || "").trim();
  const roomType = type === "voice" ? "voice" : "text";
  if (!roomName) return res.status(400).json({ error: "NAME_REQUIRED" });

  const [r] = await pool.execute(
    "INSERT INTO rooms (name,type,owner_user_id,description,image_url) VALUES (?,?,?,?,?)",
    [roomName, roomType, req.user.id, description || null, image_url || null]
  );
  const roomId = r.insertId;

  await pool.execute("INSERT INTO room_members (room_id,user_id,role) VALUES (?,?, 'owner')", [roomId, req.user.id]);

  await pool.execute(
    "INSERT INTO room_settings (room_id,auto_delete_limit,chat_disabled,chat_locked,voice_enabled,voice_seats_count) VALUES (?,?,?,?,?,?)",
    [roomId, 0, 0, 0, 1, 8]
  );

  // init seats if voice
  if (roomType === "voice") {
    const seats = [];
    for (let i = 1; i <= 8; i++) seats.push([roomId, i, null, 0, 0]);
    await pool.query(
      "INSERT IGNORE INTO room_seats (room_id, seat_index, user_id, seat_locked, seat_muted) VALUES ?",
      [seats]
    );
  }

  res.json({ ok: true, room_id: roomId });
});

app.get("/api/rooms/:id", authMiddleware, async (req, res) => {
  const roomId = mustInt(req.params.id, 0);
  const room = await dbOne("SELECT * FROM rooms WHERE id=? LIMIT 1", [roomId]);
  if (!room) return res.status(404).json({ error: "NOT_FOUND" });

  const settings = await dbOne("SELECT * FROM room_settings WHERE room_id=? LIMIT 1", [roomId]);

  const [members] = await pool.execute(
    `SELECT rm.user_id, rm.role, rm.muted_until, rm.restricted, rm.banned,
            u.username, u.is_developer, u.points, u.verified, u.frame_id,
            rl.label_text, rl.label_color
     FROM room_members rm
     JOIN users u ON u.id=rm.user_id
     LEFT JOIN room_labels rl ON rl.room_id=rm.room_id AND rl.user_id=rm.user_id
     WHERE rm.room_id=?
     ORDER BY FIELD(rm.role,'owner','developer','member'), rm.joined_at ASC`,
    [roomId]
  );

  let seats = [];
  if (room.type === "voice") {
    const [s] = await pool.execute(
      "SELECT seat_index, user_id, seat_locked, seat_muted FROM room_seats WHERE room_id=? ORDER BY seat_index ASC",
      [roomId]
    );
    seats = s;
  }

  res.json({ ok: true, room, settings, members, seats });
});

/** Messages REST (history/edit/delete) */
app.get("/api/rooms/:id/messages", authMiddleware, async (req, res) => {
  const roomId = mustInt(req.params.id, 0);
  const limit = Math.min(200, Math.max(1, mustInt(req.query.limit, 50)));
  const beforeId = mustInt(req.query.before_id, 0);

  let sql =
    `SELECT m.id, m.room_id, m.user_id, m.text, m.type, m.metadata, m.created_at, m.edited_at, m.deleted, m.deleted_at,
            u.username, u.verified, u.frame_id,
            rl.label_text, rl.label_color
     FROM messages m
     JOIN users u ON u.id=m.user_id
     LEFT JOIN room_labels rl ON rl.room_id=m.room_id AND rl.user_id=m.user_id
     WHERE m.room_id=? `;
  const params = [roomId];

  if (beforeId > 0) { sql += " AND m.id < ? "; params.push(beforeId); }
  sql += " ORDER BY m.id DESC LIMIT ? ";
  params.push(limit);

  const [rows] = await pool.execute(sql, params);
  res.json({ ok: true, messages: rows.reverse() });
});

app.put("/messages/:id", authMiddleware, async (req, res) => {
  const messageId = Number(req.params.id);
  const text = String(req.body?.text || "").trim();
  if (!messageId || !text) return res.status(400).json({ error: "BAD_INPUT" });

  const m = await dbOne("SELECT * FROM messages WHERE id=? LIMIT 1", [messageId]);
  if (!m || m.deleted) return res.status(404).json({ error: "NOT_FOUND" });

  const member = await ensureMember(m.room_id, req.user.id);
  if (!member) return res.status(403).json({ error: "NOT_MEMBER" });

  const can = (m.user_id === req.user.id) || roleRank(member.role) >= 2;
  if (!can) return res.status(403).json({ error: "NO_PERMISSION" });

  await pool.execute("UPDATE messages SET text=?, edited_at=NOW() WHERE id=?", [text, messageId]);
  broadcastRoom(m.room_id, { type: "message_updated", room_id: m.room_id, message_id: messageId, text, edited_at: nowIso() });

  res.json({ ok: true });
});

app.delete("/messages/:id", authMiddleware, async (req, res) => {
  const messageId = Number(req.params.id);
  if (!messageId) return res.status(400).json({ error: "BAD_INPUT" });

  const m = await dbOne("SELECT * FROM messages WHERE id=? LIMIT 1", [messageId]);
  if (!m || m.deleted) return res.status(404).json({ error: "NOT_FOUND" });

  const member = await ensureMember(m.room_id, req.user.id);
  if (!member) return res.status(403).json({ error: "NOT_MEMBER" });

  const can = (m.user_id === req.user.id) || roleRank(member.role) >= 2;
  if (!can) return res.status(403).json({ error: "NO_PERMISSION" });

  await pool.execute("UPDATE messages SET deleted=1, deleted_at=NOW() WHERE id=?", [messageId]);
  broadcastRoom(m.room_id, { type: "message_deleted", room_id: m.room_id, message_id: messageId });

  res.json({ ok: true });
});

/** Room settings REST */
app.post("/api/rooms/:id/autodelete", authMiddleware, async (req, res) => {
  const roomId = mustInt(req.params.id, 0);
  const limit = mustInt(req.body?.limit, 0);
  const { room, member } = await getRoomAndMember(roomId, req.user.id);
  if (!room || !member) return res.status(404).json({ error: "NOT_FOUND_OR_NOT_MEMBER" });
  if (roleRank(member.role) < 2) return res.status(403).json({ error: "NO_PERMISSION" });

  await pool.execute("UPDATE room_settings SET auto_delete_limit=? WHERE room_id=?", [Math.max(0, Math.min(500, limit)), roomId]);
  res.json({ ok: true });
});

app.post("/api/rooms/:id/chat-lock", authMiddleware, async (req, res) => {
  const roomId = mustInt(req.params.id, 0);
  const locked = req.body?.locked ? 1 : 0;
  const { room, member } = await getRoomAndMember(roomId, req.user.id);
  if (!room || !member) return res.status(404).json({ error: "NOT_FOUND_OR_NOT_MEMBER" });
  if (roleRank(member.role) < 2) return res.status(403).json({ error: "NO_PERMISSION" });

  await pool.execute("UPDATE room_settings SET chat_locked=? WHERE room_id=?", [locked, roomId]);
  broadcastRoom(roomId, { type: locked ? "chat_locked" : "chat_unlocked", room_id: roomId });
  res.json({ ok: true });
});

/** Points */
app.post("/points/grant", authMiddleware, async (req, res) => {
  const to_user_id = mustInt(req.body?.to_user_id, 0);
  const amount = mustInt(req.body?.amount, 0);
  const reason = String(req.body?.reason || "grant");
  if (!to_user_id || amount <= 0) return res.status(400).json({ error: "BAD_INPUT" });

  // dev only
  const me = await dbOne("SELECT is_developer FROM users WHERE id=? LIMIT 1", [req.user.id]);
  if (!me?.is_developer) return res.status(403).json({ error: "NO_PERMISSION" });

  await pool.execute("UPDATE users SET points=points+? WHERE id=?", [amount, to_user_id]);
  await pool.execute("INSERT INTO point_transactions (from_user_id,to_user_id,amount,reason) VALUES (?,?,?,?)",
    [req.user.id, to_user_id, amount, reason]);

  res.json({ ok: true });
});

app.post("/points/deduct", authMiddleware, async (req, res) => {
  const to_user_id = mustInt(req.body?.to_user_id, 0);
  const amount = mustInt(req.body?.amount, 0);
  const reason = String(req.body?.reason || "deduct");
  if (!to_user_id || amount <= 0) return res.status(400).json({ error: "BAD_INPUT" });

  const me = await dbOne("SELECT is_developer FROM users WHERE id=? LIMIT 1", [req.user.id]);
  if (!me?.is_developer) return res.status(403).json({ error: "NO_PERMISSION" });

  await pool.execute("UPDATE users SET points=GREATEST(points-?,0) WHERE id=?", [amount, to_user_id]);
  await pool.execute("INSERT INTO point_transactions (from_user_id,to_user_id,amount,reason) VALUES (?,?,?,?)",
    [req.user.id, to_user_id, -amount, reason]);

  res.json({ ok: true });
});

/** Moderation REST (aliases) */
async function modRequire(roomId, actorId) {
  const ok = await ensureCanModerate(roomId, actorId);
  if (!ok) return { ok: false, error: "NO_PERMISSION" };
  return { ok: true };
}
app.post("/rooms/:id/mute", authMiddleware, async (req, res) => {
  const roomId = mustInt(req.params.id, 0);
  const target = mustInt(req.body?.target_user_id, 0);
  const minutes = mustInt(req.body?.minutes, 10);
  if (!roomId || !target) return res.status(400).json({ error: "BAD_INPUT" });
  const chk = await modRequire(roomId, req.user.id);
  if (!chk.ok) return res.status(403).json(chk);

  const until = new Date(Date.now() + Math.max(1, minutes) * 60_000);
  await pool.execute(
    "UPDATE room_members SET muted_until=? WHERE room_id=? AND user_id=?",
    [until.toISOString().slice(0, 19).replace("T", " "), roomId, target]
  );
  broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم كتم المستخدم (${target})` });
  await broadcastMembersSnapshot(roomId);
  res.json({ ok: true });
});

app.post("/rooms/:id/ban", authMiddleware, async (req, res) => {
  const roomId = mustInt(req.params.id, 0);
  const target = mustInt(req.body?.target_user_id, 0);
  if (!roomId || !target) return res.status(400).json({ error: "BAD_INPUT" });
  const chk = await modRequire(roomId, req.user.id);
  if (!chk.ok) return res.status(403).json(chk);

  await pool.execute("UPDATE room_members SET banned=1 WHERE room_id=? AND user_id=?", [roomId, target]);
  broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم حظر المستخدم (${target})` });
  await broadcastMembersSnapshot(roomId);
  res.json({ ok: true });
});

app.post("/rooms/:id/restrict", authMiddleware, async (req, res) => {
  const roomId = mustInt(req.params.id, 0);
  const target = mustInt(req.body?.target_user_id, 0);
  const restricted = req.body?.restricted ? 1 : 0;
  if (!roomId || !target) return res.status(400).json({ error: "BAD_INPUT" });
  const chk = await modRequire(roomId, req.user.id);
  if (!chk.ok) return res.status(403).json(chk);

  await pool.execute("UPDATE room_members SET restricted=? WHERE room_id=? AND user_id=?", [restricted, roomId, target]);
  broadcastRoom(roomId, { type: "system", room_id: roomId, text: restricted ? `تم تقييد الدردشة (${target})` : `تم فك التقييد (${target})` });
  await broadcastMembersSnapshot(roomId);
  res.json({ ok: true });
});

/** Frames */
app.get("/frames", authMiddleware, async (req, res) => {
  const [rows] = await pool.execute("SELECT * FROM frames ORDER BY id DESC LIMIT 500");
  res.json({ ok: true, frames: rows });
});

// dev CRUD
app.post("/frames", authMiddleware, async (req, res) => {
  const me = await dbOne("SELECT is_developer FROM users WHERE id=? LIMIT 1", [req.user.id]);
  if (!me?.is_developer) return res.status(403).json({ error: "NO_PERMISSION" });

  const name = String(req.body?.name || "").trim();
  if (!name) return res.status(400).json({ error: "NAME_REQUIRED" });

  const [r] = await pool.execute(
    "INSERT INTO frames (name,description,css_class,image_url,price_points,category,available) VALUES (?,?,?,?,?,?,?)",
    [
      name,
      req.body?.description || null,
      req.body?.css_class || null,
      req.body?.image_url || null,
      mustInt(req.body?.price_points, 0),
      req.body?.category || "normal",
      req.body?.available ? 1 : 0,
    ]
  );

  res.json({ ok: true, frame_id: r.insertId });
});

app.post("/frames/grant", authMiddleware, async (req, res) => {
  const me = await dbOne("SELECT is_developer FROM users WHERE id=? LIMIT 1", [req.user.id]);
  if (!me?.is_developer) return res.status(403).json({ error: "NO_PERMISSION" });

  const user_id = mustInt(req.body?.user_id, 0);
  const frame_id = mustInt(req.body?.frame_id, 0);
  if (!user_id || !frame_id) return res.status(400).json({ error: "BAD_INPUT" });

  await pool.execute("INSERT IGNORE INTO user_frames (user_id, frame_id) VALUES (?,?)", [user_id, frame_id]);
  res.json({ ok: true });
});

app.post("/frames/select", authMiddleware, async (req, res) => {
  const frame_id = req.body?.frame_id === null ? null : mustInt(req.body?.frame_id, 0);
  if (frame_id === 0) return res.status(400).json({ error: "BAD_INPUT" });

  // ensure owned if not null
  if (frame_id !== null) {
    const owned = await dbOne("SELECT 1 FROM user_frames WHERE user_id=? AND frame_id=? LIMIT 1", [req.user.id, frame_id]);
    if (!owned) return res.status(403).json({ error: "NOT_OWNED" });
  }

  await pool.execute("UPDATE users SET frame_id=? WHERE id=?", [frame_id, req.user.id]);
  res.json({ ok: true });
});

/** Subscriptions + Payments */
app.get("/payment-methods", authMiddleware, async (req, res) => {
  const [rows] = await pool.execute("SELECT id,method_key,display_name,enabled FROM payment_methods ORDER BY id ASC");
  res.json({ ok: true, methods: rows });
});

app.get("/subscriptions", authMiddleware, async (req, res) => {
  const [rows] = await pool.execute("SELECT * FROM subscriptions WHERE enabled=1 ORDER BY id ASC");
  res.json({ ok: true, plans: rows });
});

// dev: create plan
app.post("/subscriptions", authMiddleware, async (req, res) => {
  const me = await dbOne("SELECT is_developer FROM users WHERE id=? LIMIT 1", [req.user.id]);
  if (!me?.is_developer) return res.status(403).json({ error: "NO_PERMISSION" });

  const plan_key = String(req.body?.plan_key || "").trim();
  const display_name = String(req.body?.display_name || "").trim();
  if (!plan_key || !display_name) return res.status(400).json({ error: "BAD_INPUT" });

  const [r] = await pool.execute(
    "INSERT INTO subscriptions(plan_key,display_name,price_usd,price_points,features_json,enabled) VALUES (?,?,?,?,?,?)",
    [
      plan_key,
      display_name,
      Number(req.body?.price_usd || 0),
      mustInt(req.body?.price_points, 0),
      req.body?.features_json ? JSON.stringify(req.body.features_json) : null,
      req.body?.enabled ? 1 : 0,
    ]
  );

  res.json({ ok: true, subscription_id: r.insertId });
});

// user: subscribe request (pending)
app.post("/subscriptions/subscribe", authMiddleware, async (req, res) => {
  const subscription_id = mustInt(req.body?.subscription_id, 0);
  const payment_method_id = mustInt(req.body?.payment_method_id, 0);
  const months = Math.max(1, mustInt(req.body?.months, 1));

  if (!subscription_id) return res.status(400).json({ error: "BAD_INPUT" });

  await pool.execute(
    `INSERT INTO user_subscriptions(user_id,subscription_id,status,started_at,expires_at,payment_method_id,meta_json)
     VALUES (?,?,?,?,?,?,?)`,
    [
      req.user.id,
      subscription_id,
      "pending",
      null,
      null,
      payment_method_id || null,
      JSON.stringify({ months, note: "payment pending" }),
    ]
  );

  res.json({ ok: true, status: "pending" });
});

/** Bots */
app.get("/api/rooms/:id/bots", authMiddleware, async (req, res) => {
  const roomId = mustInt(req.params.id, 0);
  const member = await ensureMember(roomId, req.user.id);
  if (!member || member.banned) return res.status(403).json({ error: "NOT_MEMBER" });

  const [bots] = await pool.execute("SELECT * FROM bots WHERE room_id=? AND enabled=1 ORDER BY id ASC", [roomId]);
  const botIds = bots.map(b => b.id);
  let commands = [];
  if (botIds.length) {
    const [cmds] = await pool.query(
      "SELECT * FROM bot_commands WHERE bot_id IN (?) AND enabled=1",
      [botIds]
    );
    commands = cmds;
  }
  res.json({ ok: true, bots, commands });
});

app.post("/api/bots", authMiddleware, async (req, res) => {
  const room_id = mustInt(req.body?.room_id, 0);
  const name = String(req.body?.name || "").trim();
  const avatar_url = req.body?.avatar_url || null;
  if (!room_id || !name) return res.status(400).json({ error: "BAD_INPUT" });

  // owner/dev only
  const m = await ensureMember(room_id, req.user.id);
  if (!m || roleRank(m.role) < 2) return res.status(403).json({ error: "NO_PERMISSION" });

  const [r] = await pool.execute(
    "INSERT INTO bots(room_id,name,avatar_url,enabled,created_by) VALUES (?,?,?,?,?)",
    [room_id, name, avatar_url, 1, req.user.id]
  );
  res.json({ ok: true, bot_id: r.insertId });
});

app.post("/api/bots/:id/commands", authMiddleware, async (req, res) => {
  const bot_id = Number(req.params.id);
  const trigger_text = String(req.body?.trigger_text || "").trim();
  const response_text = String(req.body?.response_text || "").trim();
  const match_mode = req.body?.match_mode || "exact";
  if (!bot_id || !trigger_text || !response_text) return res.status(400).json({ error: "BAD_INPUT" });

  // check bot room permission
  const bot = await dbOne("SELECT room_id FROM bots WHERE id=? LIMIT 1", [bot_id]);
  if (!bot) return res.status(404).json({ error: "BOT_NOT_FOUND" });

  const m = await ensureMember(bot.room_id, req.user.id);
  if (!m || roleRank(m.role) < 2) return res.status(403).json({ error: "NO_PERMISSION" });

  const [r] = await pool.execute(
    "INSERT INTO bot_commands(bot_id,trigger_text,response_text,match_mode,enabled) VALUES (?,?,?,?,1)",
    [bot_id, trigger_text, response_text, ["exact","starts_with","contains"].includes(match_mode) ? match_mode : "exact"]
  );
  res.json({ ok: true, command_id: r.insertId });
});

/* ================== WEBSOCKET ================== */
const wss = new WebSocket.Server({ server });

const WS_STATE = new Map();     // ws -> { userId, username, rooms:Set, lastPong, rate:{ts,count} }
const ROOM_SOCKETS = new Map(); // roomId -> Set<ws>

function roomSet(roomId) {
  if (!ROOM_SOCKETS.has(roomId)) ROOM_SOCKETS.set(roomId, new Set());
  return ROOM_SOCKETS.get(roomId);
}
function wsSend(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}
function broadcastRoom(roomId, obj) {
  const set = ROOM_SOCKETS.get(roomId);
  if (!set) return;
  const msg = JSON.stringify(obj);
  for (const ws of set) if (ws.readyState === WebSocket.OPEN) ws.send(msg);
}

async function broadcastMembersSnapshot(roomId) {
  const [members] = await pool.execute(
    `SELECT rm.user_id, rm.role, rm.muted_until, rm.restricted, rm.banned,
            u.username, u.verified, u.frame_id,
            rl.label_text, rl.label_color
     FROM room_members rm
     JOIN users u ON u.id=rm.user_id
     LEFT JOIN room_labels rl ON rl.room_id=rm.room_id AND rl.user_id=rm.user_id
     WHERE rm.room_id=? AND rm.banned=0
     ORDER BY FIELD(rm.role,'owner','developer','member'), rm.joined_at ASC`,
    [roomId]
  );

  const online = new Set();
  for (const [ws, st] of WS_STATE.entries()) {
    if (st.rooms?.has(roomId)) online.add(st.userId);
  }

  broadcastRoom(roomId, {
    type: "members_snapshot",
    room_id: roomId,
    members: members.map((m) => ({
      user_id: m.user_id,
      username: m.username,
      role: m.role,
      muted_until: m.muted_until,
      restricted: !!m.restricted,
      label_text: m.label_text || null,
      label_color: m.label_color || null,
      verified: !!m.verified,
      frame_id: m.frame_id ?? null,
      online: online.has(m.user_id),
    })),
  });
}

async function broadcastSeats(roomId) {
  const [s] = await pool.execute(
    "SELECT seat_index, user_id, seat_locked, seat_muted FROM room_seats WHERE room_id=? ORDER BY seat_index ASC",
    [roomId]
  );
  broadcastRoom(roomId, { type: "seats_snapshot", room_id: roomId, seats: s });
}

async function enforceAutoDelete(roomId) {
  const settings = await dbOne("SELECT auto_delete_limit FROM room_settings WHERE room_id=? LIMIT 1", [roomId]);
  const limit = mustInt(settings?.auto_delete_limit, 0);
  if (!limit || limit <= 0) return;

  const row = await dbOne("SELECT COUNT(*) AS c FROM messages WHERE room_id=? AND deleted=0", [roomId]);
  const count = mustInt(row?.c, 0);
  if (count <= limit) return;

  const overflow = count - limit;

  await pool.execute(
    `UPDATE messages SET deleted=1, deleted_at=NOW()
     WHERE room_id=? AND deleted=0
     ORDER BY id ASC
     LIMIT ?`,
    [roomId, overflow]
  );

  broadcastRoom(roomId, { type: "system", room_id: roomId, text: "تم حذف الرسائل لتوفير مساحة للدردشة" });
}

async function requireWsAuth(ws) {
  const st = WS_STATE.get(ws);
  if (!st?.userId) return null;
  const u = await dbOne("SELECT id, username, banned, is_developer FROM users WHERE id=? LIMIT 1", [st.userId]);
  if (!u || u.banned) return null;
  return u;
}

function normalizeType(t) {
  // allow "seat.join" -> "seat_join"
  const s = String(t || "");
  return s.includes(".") ? s.replace(/\./g, "_") : s;
}

function rateLimitOK(st) {
  const now = Date.now();
  if (!st.rate) st.rate = { ts: now, count: 0 };
  if (now - st.rate.ts > 2000) { st.rate.ts = now; st.rate.count = 0; }
  st.rate.count++;
  // allow ~10 actions per 2 sec
  return st.rate.count <= 10;
}

wss.on("connection", (ws) => {
  WS_STATE.set(ws, { userId: null, username: null, rooms: new Set(), lastPong: Date.now(), rate: { ts: Date.now(), count: 0 } });

  wsSend(ws, { type: "hello", server_time: Date.now() });

  ws.on("message", async (raw) => {
    const msg = safeJsonParse(raw);
    if (!msg || !msg.type) return;

    const st = WS_STATE.get(ws);
    if (!rateLimitOK(st)) return wsSend(ws, { type: "error", error: "RATE_LIMIT" });

    const type = normalizeType(msg.type);

    // heartbeat
    if (type === "ping") {
      st.lastPong = Date.now();
      return wsSend(ws, { type: "pong" });
    }

    // AUTH
    if (type === "auth") {
      try {
        const token = String(msg.token || "");
        const payload = jwt.verify(token, JWT_SECRET);
        const u = await dbOne("SELECT id, username, banned, is_developer FROM users WHERE id=? LIMIT 1", [payload.id]);
        if (!u || u.banned) {
          wsSend(ws, { type: "auth", ok: false, error: "BANNED_OR_NOUSER" });
          return ws.close();
        }
        st.userId = u.id;
        st.username = u.username;
        wsSend(ws, { type: "auth", ok: true, user: { id: u.id, username: u.username, is_developer: !!u.is_developer } });
      } catch {
        wsSend(ws, { type: "auth", ok: false, error: "BAD_TOKEN" });
        return ws.close();
      }
      return;
    }

    // after this require auth
    const authedUser = await requireWsAuth(ws);
    if (!authedUser) return wsSend(ws, { type: "error", error: "UNAUTHORIZED" });

    // JOIN ROOM
    if (type === "join_room") {
      const roomId = mustInt(msg.room_id, 0);
      const room = await dbOne("SELECT * FROM rooms WHERE id=? LIMIT 1", [roomId]);
      if (!room) return wsSend(ws, { type: "join_room", ok: false, error: "ROOM_NOT_FOUND" });

      const existing = await ensureMember(roomId, authedUser.id);
      if (existing && existing.banned) return wsSend(ws, { type: "join_room", ok: false, error: "ROOM_BANNED" });

      if (!existing) {
        const role = authedUser.is_developer ? "developer" : "member";
        await pool.execute("INSERT INTO room_members (room_id,user_id,role) VALUES (?,?,?)", [roomId, authedUser.id, role]);
      }

      roomSet(roomId).add(ws);
      st.rooms.add(roomId);

      wsSend(ws, { type: "join_room", ok: true, room_id: roomId });
      broadcastRoom(roomId, { type: "system", room_id: roomId, text: `انضم ${st.username}` });

      await broadcastMembersSnapshot(roomId);
      if (room.type === "voice") await broadcastSeats(roomId);
      return;
    }

    // LEAVE ROOM
    if (type === "leave_room") {
      const roomId = mustInt(msg.room_id, 0);
      const set = ROOM_SOCKETS.get(roomId);
      if (set) set.delete(ws);
      st.rooms.delete(roomId);

      wsSend(ws, { type: "leave_room", ok: true, room_id: roomId });
      broadcastRoom(roomId, { type: "system", room_id: roomId, text: `غادر ${st.username}` });
      await broadcastMembersSnapshot(roomId);
      return;
    }

    // TYPING
    if (type === "typing") {
      const roomId = mustInt(msg.room_id, 0);
      if (!st.rooms.has(roomId)) return;
      broadcastRoom(roomId, { type: "typing", room_id: roomId, user_id: authedUser.id, username: st.username, on: !!msg.on });
      return;
    }

    // CHAT SEND
    if (type === "chat") {
      const roomId = mustInt(msg.room_id, 0);
      const text = String(msg.text || "").trim();
      if (!text) return;

      if (!st.rooms.has(roomId)) return wsSend(ws, { type: "chat", ok: false, error: "NOT_IN_ROOM" });

      const { room, member } = await getRoomAndMember(roomId, authedUser.id);
      if (!room || !member) return wsSend(ws, { type: "chat", ok: false, error: "NOT_MEMBER" });
      if (member.banned) return wsSend(ws, { type: "chat", ok: false, error: "ROOM_BANNED" });

      const settings = await dbOne("SELECT chat_disabled, chat_locked FROM room_settings WHERE room_id=? LIMIT 1", [roomId]);
      const locked = (settings?.chat_locked || settings?.chat_disabled) ? 1 : 0;
      if (locked && roleRank(member.role) < 2) return wsSend(ws, { type: "chat", ok: false, error: "CHAT_LOCKED" });

      if (member.restricted) return wsSend(ws, { type: "chat", ok: false, error: "RESTRICTED" });
      if (isMuted(member)) return wsSend(ws, { type: "chat", ok: false, error: "MUTED" });

      const msgType = String(msg.type || "text").slice(0, 24);
      const metadata = msg.metadata ? JSON.stringify(msg.metadata) : null;

      const [r] = await pool.execute(
        "INSERT INTO messages (room_id,user_id,text,type,metadata) VALUES (?,?,?,?,?)",
        [roomId, authedUser.id, text, msgType, metadata]
      );
      const messageId = r.insertId;

      const lbl = await dbOne("SELECT label_text,label_color FROM room_labels WHERE room_id=? AND user_id=? LIMIT 1", [roomId, authedUser.id]);

      broadcastRoom(roomId, {
        type: "chat",
        ok: true,
        room_id: roomId,
        message: {
          id: messageId,
          room_id: roomId,
          user_id: authedUser.id,
          username: st.username,
          text,
          type: msgType,
          metadata: msg.metadata || null,
          created_at: nowIso(),
          edited_at: null,
          deleted: 0,
          label_text: lbl?.label_text || null,
          label_color: lbl?.label_color || null,
        },
      });

      // BOT SYSTEM: if any bot matches this text -> emit bot message
      await maybeRunBots(roomId, text);

      await enforceAutoDelete(roomId);
      return;
    }

    // EDIT / DELETE messages
    if (type === "edit_message" || type === "delete_message") {
      const roomId = mustInt(msg.room_id, 0);
      const messageId = Number(msg.message_id);
      if (!roomId || !messageId) return;

      const m = await dbOne("SELECT * FROM messages WHERE id=? AND room_id=? LIMIT 1", [messageId, roomId]);
      if (!m || m.deleted) return wsSend(ws, { type, ok: false, error: "NOT_FOUND" });

      const member = await ensureMember(roomId, authedUser.id);
      if (!member) return wsSend(ws, { type, ok: false, error: "NOT_MEMBER" });

      const can = (m.user_id === authedUser.id) || roleRank(member.role) >= 2;
      if (!can) return wsSend(ws, { type, ok: false, error: "NO_PERMISSION" });

      if (type === "edit_message") {
        const newText = String(msg.text || "").trim();
        if (!newText) return;
        await pool.execute("UPDATE messages SET text=?, edited_at=NOW() WHERE id=?", [newText, messageId]);
        broadcastRoom(roomId, { type: "message_updated", room_id: roomId, message_id: messageId, text: newText, edited_at: nowIso() });
        wsSend(ws, { type: "edit_message", ok: true });
      } else {
        await pool.execute("UPDATE messages SET deleted=1, deleted_at=NOW() WHERE id=?", [messageId]);
        broadcastRoom(roomId, { type: "message_deleted", room_id: roomId, message_id: messageId });
        wsSend(ws, { type: "delete_message", ok: true });
      }
      return;
    }

    // MODERATION (WS)
    if (type === "moderate") {
      const roomId = mustInt(msg.room_id, 0);
      const action = String(msg.action || "");
      const targetUserId = mustInt(msg.target_user_id, 0);
      const minutes = mustInt(msg.minutes, 0);
      if (!roomId || !action) return;

      const canMod = await ensureCanModerate(roomId, authedUser.id);
      if (!canMod) return wsSend(ws, { type: "moderate", ok: false, error: "NO_PERMISSION" });

      if (["mute", "ban", "unban", "restrict", "unrestrict", "kick"].includes(action) && !targetUserId) {
        return wsSend(ws, { type: "moderate", ok: false, error: "NO_TARGET" });
      }

      if (action === "mute") {
        const until = new Date(Date.now() + Math.max(1, minutes) * 60_000);
        await pool.execute(
          "UPDATE room_members SET muted_until=? WHERE room_id=? AND user_id=?",
          [until.toISOString().slice(0, 19).replace("T", " "), roomId, targetUserId]
        );
        broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم كتم المستخدم (${targetUserId})` });
      }

      if (action === "ban") {
        await pool.execute("UPDATE room_members SET banned=1 WHERE room_id=? AND user_id=?", [roomId, targetUserId]);
        broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم حظر المستخدم (${targetUserId})` });
      }

      if (action === "unban") {
        await pool.execute("UPDATE room_members SET banned=0 WHERE room_id=? AND user_id=?", [roomId, targetUserId]);
        broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم رفع الحظر عن المستخدم (${targetUserId})` });
      }

      if (action === "restrict") {
        await pool.execute("UPDATE room_members SET restricted=1 WHERE room_id=? AND user_id=?", [roomId, targetUserId]);
        broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم تقييد الدردشة للمستخدم (${targetUserId})` });
      }

      if (action === "unrestrict") {
        await pool.execute("UPDATE room_members SET restricted=0 WHERE room_id=? AND user_id=?", [roomId, targetUserId]);
        broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم فك التقييد عن المستخدم (${targetUserId})` });
      }

      if (action === "kick") {
        const set = ROOM_SOCKETS.get(roomId);
        if (set) {
          for (const sock of set) {
            const sst = WS_STATE.get(sock);
            if (sst?.userId === targetUserId) {
              sst.rooms.delete(roomId);
              set.delete(sock);
              wsSend(sock, { type: "kicked", room_id: roomId });
            }
          }
        }
        broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم طرد المستخدم (${targetUserId})` });
      }

      if (action === "chat_lock" || action === "chat_unlock") {
        const locked = action === "chat_lock" ? 1 : 0;
        await pool.execute("UPDATE room_settings SET chat_locked=? WHERE room_id=?", [locked, roomId]);
        broadcastRoom(roomId, { type: locked ? "chat_locked" : "chat_unlocked", room_id: roomId });
      }

      if (action === "autodelete_set") {
        const limit = Math.max(0, Math.min(500, mustInt(msg.limit, 0)));
        await pool.execute("UPDATE room_settings SET auto_delete_limit=? WHERE room_id=?", [limit, roomId]);
        broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم تحديث حد الحذف التلقائي إلى ${limit}` });
      }

      await broadcastMembersSnapshot(roomId);
      wsSend(ws, { type: "moderate", ok: true });
      return;
    }

    // SET LABEL
    if (type === "set_label") {
      const roomId = mustInt(msg.room_id, 0);
      const targetUserId = mustInt(msg.target_user_id, 0);
      const labelText = String(msg.label_text || "").trim();
      const labelColor = String(msg.label_color || "#ff3b30").trim();
      if (!roomId || !targetUserId || !labelText) return;

      const canMod = await ensureCanModerate(roomId, authedUser.id);
      if (!canMod) return wsSend(ws, { type: "set_label", ok: false, error: "NO_PERMISSION" });

      await pool.execute(
        `INSERT INTO room_labels (room_id, user_id, label_text, label_color)
         VALUES (?,?,?,?)
         ON DUPLICATE KEY UPDATE label_text=VALUES(label_text), label_color=VALUES(label_color)`,
        [roomId, targetUserId, labelText.slice(0, 40), labelColor.slice(0, 20)]
      );

      await broadcastMembersSnapshot(roomId);
      wsSend(ws, { type: "set_label", ok: true });
      return;
    }

    // TRANSFER OWNERSHIP
    if (type === "transfer_owner") {
      const roomId = mustInt(msg.room_id, 0);
      const newOwnerId = mustInt(msg.new_owner_id, 0);
      if (!roomId || !newOwnerId) return;

      const canOwner = await ensureCanOwner(roomId, authedUser.id);
      if (!canOwner) return wsSend(ws, { type: "transfer_owner", ok: false, error: "OWNER_ONLY" });

      // ensure new owner is member
      const target = await ensureMember(roomId, newOwnerId);
      if (!target) return wsSend(ws, { type: "transfer_owner", ok: false, error: "TARGET_NOT_MEMBER" });

      await pool.execute("UPDATE rooms SET owner_user_id=? WHERE id=?", [newOwnerId, roomId]);
      await pool.execute("UPDATE room_members SET role='member' WHERE room_id=? AND user_id=?", [roomId, authedUser.id]);
      await pool.execute("UPDATE room_members SET role='owner' WHERE room_id=? AND user_id=?", [roomId, newOwnerId]);

      broadcastRoom(roomId, { type: "owner_transfer", room_id: roomId, old_owner_id: authedUser.id, new_owner_id: newOwnerId });
      await broadcastMembersSnapshot(roomId);

      wsSend(ws, { type: "transfer_owner", ok: true });
      return;
    }

    // ===== Seats & WebRTC signaling =====
    if (type === "seat_join" || type === "seat_take") {
      const roomId = mustInt(msg.room_id, 0);
      const seatIndex = mustInt(msg.seat_index, 0);
      if (!roomId || !seatIndex) return;

      const room = await dbOne("SELECT * FROM rooms WHERE id=? LIMIT 1", [roomId]);
      if (!room || room.type !== "voice") return;

      // must be in room
      if (!st.rooms.has(roomId)) return wsSend(ws, { type, ok: false, error: "NOT_IN_ROOM" });

      // voice ban check
      const vb = await dbOne("SELECT banned FROM room_voice_bans WHERE room_id=? AND user_id=? LIMIT 1", [roomId, authedUser.id]);
      if (vb?.banned) return wsSend(ws, { type, ok: false, error: "VOICE_BANNED" });

      const seat = await dbOne("SELECT * FROM room_seats WHERE room_id=? AND seat_index=? LIMIT 1", [roomId, seatIndex]);
      if (!seat) return wsSend(ws, { type, ok: false, error: "SEAT_NOT_FOUND" });
      if (seat.seat_locked) return wsSend(ws, { type, ok: false, error: "SEAT_LOCKED" });
      if (seat.user_id && seat.user_id !== authedUser.id) return wsSend(ws, { type, ok: false, error: "SEAT_TAKEN" });

      // leave other seat if sitting
      await pool.execute("UPDATE room_seats SET user_id=NULL, seat_muted=0 WHERE room_id=? AND user_id=?", [roomId, authedUser.id]);

      await pool.execute("UPDATE room_seats SET user_id=? WHERE room_id=? AND seat_index=?", [authedUser.id, roomId, seatIndex]);
      await broadcastSeats(roomId);

      wsSend(ws, { type: "seat_join_approved", room_id: roomId, seat_index: seatIndex });
      return;
    }

    if (type === "seat_leave") {
      const roomId = mustInt(msg.room_id, 0);
      if (!roomId) return;
      await pool.execute("UPDATE room_seats SET user_id=NULL, seat_muted=0 WHERE room_id=? AND user_id=?", [roomId, authedUser.id]);
      await broadcastSeats(roomId);
      return;
    }

    if (type === "seat_kick") {
      const roomId = mustInt(msg.room_id, 0);
      const targetUserId = mustInt(msg.target_user_id, 0);
      if (!roomId || !targetUserId) return;

      const canMod = await ensureCanModerate(roomId, authedUser.id);
      if (!canMod) return wsSend(ws, { type, ok: false, error: "NO_PERMISSION" });

      await pool.execute("UPDATE room_seats SET user_id=NULL, seat_muted=0 WHERE room_id=? AND user_id=?", [roomId, targetUserId]);
      await broadcastSeats(roomId);
      broadcastRoom(roomId, { type: "seat_kick", room_id: roomId, target_user_id: targetUserId });
      return;
    }

    if (type === "seat_lock" || type === "seat_unlock") {
      const roomId = mustInt(msg.room_id, 0);
      const seatIndex = mustInt(msg.seat_index, 0);
      const locked = type === "seat_lock" ? 1 : 0;
      if (!roomId || !seatIndex) return;

      const canMod = await ensureCanModerate(roomId, authedUser.id);
      if (!canMod) return wsSend(ws, { type, ok: false, error: "NO_PERMISSION" });

      await pool.execute("UPDATE room_seats SET seat_locked=? WHERE room_id=? AND seat_index=?", [locked, roomId, seatIndex]);
      await broadcastSeats(roomId);
      broadcastRoom(roomId, { type: locked ? "seat_lock" : "seat_unlock", room_id: roomId, seat_index: seatIndex });
      return;
    }

    if (type === "seat_mute" || type === "seat_unmute") {
      const roomId = mustInt(msg.room_id, 0);
      const seatIndex = mustInt(msg.seat_index, 0);
      const muted = type === "seat_mute" ? 1 : 0;
      if (!roomId || !seatIndex) return;

      const canMod = await ensureCanModerate(roomId, authedUser.id);
      if (!canMod) return wsSend(ws, { type, ok: false, error: "NO_PERMISSION" });

      await pool.execute("UPDATE room_seats SET seat_muted=? WHERE room_id=? AND seat_index=?", [muted, roomId, seatIndex]);
      await broadcastSeats(roomId);
      broadcastRoom(roomId, { type: muted ? "seat_mute" : "seat_unmute", room_id: roomId, seat_index: seatIndex });
      return;
    }

    // accept dotted webrtc.* too
    if (type === "webrtc_offer" || type === "webrtc_answer" || type === "webrtc_ice") {
      const roomId = mustInt(msg.room_id, 0);
      const toUserId = mustInt(msg.to_user_id, 0);
      if (!roomId || !toUserId) return;

      // must be in room
      if (!st.rooms.has(roomId)) return;

      // forward to that user if online in same room
      const set = ROOM_SOCKETS.get(roomId);
      if (!set) return;
      for (const sock of set) {
        const sst = WS_STATE.get(sock);
        if (sst?.userId === toUserId) {
          wsSend(sock, {
            type, // already normalized
            room_id: roomId,
            from_user_id: authedUser.id,
            sdp: msg.sdp,
            candidate: msg.candidate,
            seat_index: msg.seat_index ?? null,
          });
        }
      }
      return;
    }
  });

  ws.on("close", async () => {
    const st = WS_STATE.get(ws);
    if (st?.rooms) {
      for (const roomId of st.rooms) {
        const set = ROOM_SOCKETS.get(roomId);
        if (set) set.delete(ws);
        // leave seat if sitting
        await pool.execute("UPDATE room_seats SET user_id=NULL, seat_muted=0 WHERE room_id=? AND user_id=?", [roomId, st.userId]);
        await broadcastMembersSnapshot(roomId);
        await broadcastSeats(roomId);
      }
    }
    WS_STATE.delete(ws);
  });
});

// server-side heartbeat monitor
setInterval(() => {
  const now = Date.now();
  for (const [ws, st] of WS_STATE.entries()) {
    if (ws.readyState !== WebSocket.OPEN) continue;
    if (now - (st.lastPong || 0) > 45000) {
      try { ws.close(); } catch {}
    } else {
      wsSend(ws, { type: "ping" });
    }
  }
}, 15000);

/* ================== BOT RUNTIME ================== */
async function maybeRunBots(roomId, text) {
  const [bots] = await pool.execute("SELECT * FROM bots WHERE room_id=? AND enabled=1", [roomId]);
  if (!bots.length) return;

  const botIds = bots.map(b => b.id);
  const [cmds] = await pool.query("SELECT * FROM bot_commands WHERE bot_id IN (?) AND enabled=1", [botIds]);

  const msgText = String(text || "");
  for (const cmd of cmds) {
    const trig = String(cmd.trigger_text || "");
    const mode = cmd.match_mode || "exact";
    let hit = false;
    if (mode === "exact") hit = msgText.trim() === trig;
    if (mode === "starts_with") hit = msgText.startsWith(trig);
    if (mode === "contains") hit = msgText.includes(trig);

    if (hit) {
      const bot = bots.find(b => b.id === cmd.bot_id);
      const botName = bot?.name || "Bot";

      // store as message type=bot
      const [r] = await pool.execute(
        "INSERT INTO messages (room_id,user_id,text,type,metadata) VALUES (?,?,?,?,?)",
        [roomId, 0, cmd.response_text, "bot", JSON.stringify({ bot_id: cmd.bot_id, bot_name: botName, avatar_url: bot?.avatar_url || null })]
      );

      broadcastRoom(roomId, {
        type: "bot_message",
        room_id: roomId,
        message: {
          id: r.insertId,
          room_id: roomId,
          user_id: 0,
          username: botName,
          text: cmd.response_text,
          type: "bot",
          metadata: { bot_id: cmd.bot_id, bot_name: botName, avatar_url: bot?.avatar_url || null },
          created_at: nowIso(),
        }
      });
      break;
    }
  }
}

/* ================== START ================== */
initializeDatabase()
  .then(() => {
    server.listen(PORT, () => console.log("✅ Server running on port", PORT));
  })
  .catch((err) => {
    console.error("❌ Failed to init DB", err);
    process.exit(1);
  });
