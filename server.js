/**
 * FULL SINGLE-FILE SERVER
 * Express + WebSocket + MySQL (Railway auto) + JWT
 * Features:
 * - Auth: register/login/me
 * - Rooms: create/join/leave/list + owner/dev roles + transfer ownership
 * - Members list live updates (online/typing)
 * - Chat: send/edit/delete
 * - Auto-delete messages after N (room setting)
 * - Moderation: mute/ban/restrict chat, kick
 * - Points: give/charge + transactions
 * - Labels: developer can set label + color for user in room
 * - WebRTC signaling: seats + offer/answer/ice via WS (voice rooms)
 */

require("dotenv").config();
const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const crypto = require("crypto");

/* ================== APP ================== */
const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

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
  // Railway plugin vars
  if (
    process.env.MYSQLHOST &&
    process.env.MYSQLUSER &&
    process.env.MYSQLPASSWORD &&
    process.env.MYSQLDATABASE
  ) {
    return {
      host: process.env.MYSQLHOST,
      port: process.env.MYSQLPORT ? Number(process.env.MYSQLPORT) : 3306,
      user: process.env.MYSQLUSER,
      password: process.env.MYSQLPASSWORD,
      database: process.env.MYSQLDATABASE,
    };
  }
  // URL style
  const url = process.env.DATABASE_URL || process.env.MYSQL_URL;
  if (url) return parseDbUrl(url);
  return null;
}

const baseDb = getDbConfigFromEnv();

// DEBUG مؤقت (احذفه بعد التأكد)
console.log("🔍 DB ENV CHECK", {
  MYSQLHOST: process.env.MYSQLHOST,
  MYSQLUSER: process.env.MYSQLUSER,
  MYSQLDATABASE: process.env.MYSQLDATABASE,
  MYSQL_URL: process.env.MYSQL_URL,
  MYSQL_PUBLIC_URL: process.env.MYSQL_PUBLIC_URL
});

if (!baseDb) {
  console.error("❌ DB config not found. Variables موجودة بس مو مقروءة من السيرفر");
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

async function ensureJwtSecret() {
  if (JWT_SECRET) return JWT_SECRET;

  const [rows] = await pool.execute(
    "SELECT setting_value FROM server_settings WHERE setting_key=? LIMIT 1",
    ["jwt_secret"]
  );

  if (rows.length && rows[0].setting_value) {
    JWT_SECRET = rows[0].setting_value;
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

/* ================== HELPERS ================== */
function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function nowIso() {
  return new Date().toISOString().slice(0, 19).replace("T", " ");
}

function safeJsonParse(s) {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

function mustInt(n, def = 0) {
  const x = Number(n);
  return Number.isFinite(x) ? Math.trunc(x) : def;
}

async function dbOne(sql, params) {
  const [rows] = await pool.execute(sql, params);
  return rows && rows.length ? rows[0] : null;
}

/* ================== TABLES ================== */
async function createTablesIfNotExist() {
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

  console.log("✅ Tables ready");
}

/* ================== DB INIT ================== */
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
async function getRoomAndMember(roomId, userId) {
  const room = await dbOne("SELECT * FROM rooms WHERE id=? LIMIT 1", [roomId]);
  if (!room) return { room: null, member: null };

  const member = await dbOne(
    "SELECT * FROM room_members WHERE room_id=? AND user_id=? LIMIT 1",
    [roomId, userId]
  );

  return { room, member };
}

function roleRank(role) {
  if (role === "owner") return 3;
  if (role === "developer") return 2;
  return 1;
}

function isMuted(member) {
  if (!member || !member.muted_until) return false;
  return new Date(member.muted_until).getTime() > Date.now();
}

/* ================== API ================== */

// health
app.get("/", (req, res) => res.send("OK"));

// register
app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password)
    return res.status(400).json({ error: "MISSING_FIELDS" });

  try {
    await pool.execute(
      "INSERT INTO users (username,email,pass_hash) VALUES (?,?,?)",
      [String(username).trim(), String(email).trim().toLowerCase(), sha256(password)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: "USER_EXISTS" });
  }
});

// login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "MISSING_FIELDS" });

  const user = await dbOne(
    "SELECT id,username,is_developer,points,banned FROM users WHERE email=? AND pass_hash=? LIMIT 1",
    [String(email).trim().toLowerCase(), sha256(password)]
  );

  if (!user) return res.status(401).json({ error: "BAD_CREDENTIALS" });
  if (user.banned) return res.status(403).json({ error: "BANNED" });

  const token = jwt.sign(
    {
      id: user.id,
      username: user.username,
      is_developer: !!user.is_developer,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ ok: true, token });
});

// me
app.get("/api/me", authMiddleware, async (req, res) => {
  const u = await dbOne(
    "SELECT id,username,email,is_developer,points,banned,created_at FROM users WHERE id=? LIMIT 1",
    [req.user.id]
  );
  res.json({ ok: true, user: u });
});

// rooms list
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

// create room
app.post("/api/rooms", authMiddleware, async (req, res) => {
  const { name, type } = req.body || {};
  const roomName = String(name || "").trim();
  const roomType = type === "voice" ? "voice" : "text";
  if (!roomName) return res.status(400).json({ error: "NAME_REQUIRED" });

  const [r] = await pool.execute(
    "INSERT INTO rooms (name,type,owner_user_id) VALUES (?,?,?)",
    [roomName, roomType, req.user.id]
  );
  const roomId = r.insertId;

  await pool.execute(
    "INSERT INTO room_members (room_id,user_id,role) VALUES (?,?, 'owner')",
    [roomId, req.user.id]
  );
  await pool.execute(
    "INSERT INTO room_settings (room_id,auto_delete_limit,chat_disabled) VALUES (?,?,?)",
    [roomId, 0, 0]
  );

  // init 8 seats for voice
  if (roomType === "voice") {
    const seats = [];
    for (let i = 1; i <= 8; i++) seats.push([roomId, i, null]);
    await pool.query(
      "INSERT IGNORE INTO room_seats (room_id, seat_index, user_id) VALUES ?",
      [seats]
    );
  }

  res.json({ ok: true, room_id: roomId });
});

// room info
app.get("/api/rooms/:id", authMiddleware, async (req, res) => {
  const roomId = mustInt(req.params.id, 0);
  const room = await dbOne("SELECT * FROM rooms WHERE id=? LIMIT 1", [roomId]);
  if (!room) return res.status(404).json({ error: "NOT_FOUND" });

  const settings = await dbOne("SELECT * FROM room_settings WHERE room_id=? LIMIT 1", [roomId]);

  const [members] = await pool.execute(
    `SELECT rm.user_id, rm.role, rm.muted_until, rm.restricted, rm.banned,
            u.username, u.is_developer, u.points,
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
      "SELECT seat_index, user_id FROM room_seats WHERE room_id=? ORDER BY seat_index ASC",
      [roomId]
    );
    seats = s;
  }

  res.json({ ok: true, room, settings, members, seats });
});

// messages fetch
app.get("/api/rooms/:id/messages", authMiddleware, async (req, res) => {
  const roomId = mustInt(req.params.id, 0);
  const limit = Math.min(200, Math.max(1, mustInt(req.query.limit, 50)));
  const beforeId = mustInt(req.query.before_id, 0);

  let sql =
    `SELECT m.id, m.room_id, m.user_id, m.text, m.created_at, m.edited_at, m.deleted,
            u.username,
            rl.label_text, rl.label_color
     FROM messages m
     JOIN users u ON u.id=m.user_id
     LEFT JOIN room_labels rl ON rl.room_id=m.room_id AND rl.user_id=m.user_id
     WHERE m.room_id=? `;
  const params = [roomId];

  if (beforeId > 0) {
    sql += " AND m.id < ? ";
    params.push(beforeId);
  }

  sql += " ORDER BY m.id DESC LIMIT ? ";
  params.push(limit);

  const [rows] = await pool.execute(sql, params);
  res.json({ ok: true, messages: rows.reverse() });
});

// set auto-delete limit (owner/dev only)
app.post("/api/rooms/:id/autodelete", authMiddleware, async (req, res) => {
  const roomId = mustInt(req.params.id, 0);
  const limit = mustInt(req.body?.limit, 0);

  const { room, member } = await getRoomAndMember(roomId, req.user.id);
  if (!room || !member) return res.status(404).json({ error: "NOT_FOUND_OR_NOT_MEMBER" });

  if (roleRank(member.role) < 2) return res.status(403).json({ error: "NO_PERMISSION" });

  await pool.execute(
    "UPDATE room_settings SET auto_delete_limit=? WHERE room_id=?",
    [Math.max(0, Math.min(500, limit)), roomId]
  );

  res.json({ ok: true });
});

// toggle chat disabled (owner/dev)
app.post("/api/rooms/:id/chat", authMiddleware, async (req, res) => {
  const roomId = mustInt(req.params.id, 0);
  const disabled = req.body?.disabled ? 1 : 0;

  const { room, member } = await getRoomAndMember(roomId, req.user.id);
  if (!room || !member) return res.status(404).json({ error: "NOT_FOUND_OR_NOT_MEMBER" });
  if (roleRank(member.role) < 2) return res.status(403).json({ error: "NO_PERMISSION" });

  await pool.execute(
    "UPDATE room_settings SET chat_disabled=? WHERE room_id=?",
    [disabled, roomId]
  );

  res.json({ ok: true });
});

/* ================== WEBSOCKET ================== */

const wss = new WebSocket.Server({ server });

/**
 * In-memory presence:
 * ws => { userId, username, rooms:Set }
 */
const WS_STATE = new Map(); // ws -> state
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
  for (const ws of set) {
    if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  }
}

async function broadcastMembersSnapshot(roomId) {
  const [members] = await pool.execute(
    `SELECT rm.user_id, rm.role, rm.muted_until, rm.restricted, rm.banned,
            u.username,
            rl.label_text, rl.label_color
     FROM room_members rm
     JOIN users u ON u.id=rm.user_id
     LEFT JOIN room_labels rl ON rl.room_id=rm.room_id AND rl.user_id=rm.user_id
     WHERE rm.room_id=? AND rm.banned=0
     ORDER BY FIELD(rm.role,'owner','developer','member'), rm.joined_at ASC`,
    [roomId]
  );

  // presence online
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
      online: online.has(m.user_id),
    })),
  });
}

async function broadcastSeats(roomId) {
  const [s] = await pool.execute(
    "SELECT seat_index, user_id FROM room_seats WHERE room_id=? ORDER BY seat_index ASC",
    [roomId]
  );
  broadcastRoom(roomId, { type: "seats_snapshot", room_id: roomId, seats: s });
}

async function enforceAutoDelete(roomId) {
  const settings = await dbOne("SELECT auto_delete_limit FROM room_settings WHERE room_id=? LIMIT 1", [roomId]);
  const limit = mustInt(settings?.auto_delete_limit, 0);
  if (!limit || limit <= 0) return;

  // Count active (not deleted)
  const row = await dbOne(
    "SELECT COUNT(*) AS c FROM messages WHERE room_id=? AND deleted=0",
    [roomId]
  );
  const count = mustInt(row?.c, 0);
  if (count <= limit) return;

  const overflow = count - limit;

  // delete oldest overflow messages
  await pool.execute(
    `UPDATE messages
     SET deleted=1
     WHERE room_id=? AND deleted=0
     ORDER BY id ASC
     LIMIT ?`,
    [roomId, overflow]
  );

  broadcastRoom(roomId, {
    type: "system",
    room_id: roomId,
    text: "تم حذف الرسائل لتوفير مساحة للدردشة",
  });
}

async function requireWsAuth(ws) {
  const st = WS_STATE.get(ws);
  if (!st?.userId) return null;
  // user must not be globally banned
  const u = await dbOne("SELECT id, username, banned, is_developer FROM users WHERE id=? LIMIT 1", [st.userId]);
  if (!u || u.banned) return null;
  return u;
}

async function ensureMember(roomId, userId) {
  const member = await dbOne(
    "SELECT * FROM room_members WHERE room_id=? AND user_id=? LIMIT 1",
    [roomId, userId]
  );
  return member;
}

async function ensureCanModerate(roomId, userId) {
  const member = await ensureMember(roomId, userId);
  if (!member) return false;
  return roleRank(member.role) >= 2; // developer or owner
}

async function ensureCanOwner(roomId, userId) {
  const member = await ensureMember(roomId, userId);
  if (!member) return false;
  return member.role === "owner";
}

async function setRoomLabel(roomId, targetUserId, text, color) {
  await pool.execute(
    `INSERT INTO room_labels (room_id, user_id, label_text, label_color)
     VALUES (?,?,?,?)
     ON DUPLICATE KEY UPDATE label_text=VALUES(label_text), label_color=VALUES(label_color)`,
    [roomId, targetUserId, text, color]
  );
}

async function updatePoints(fromUserId, toUserId, amount, reason) {
  const amt = mustInt(amount, 0);
  if (!amt || amt === 0) return { ok: false, error: "BAD_AMOUNT" };

  if (toUserId && amt > 0) {
    // give points (deduct from sender)
    const sender = await dbOne("SELECT points FROM users WHERE id=? LIMIT 1", [fromUserId]);
    if (!sender) return { ok: false, error: "NO_SENDER" };
    if (sender.points < amt) return { ok: false, error: "NO_BALANCE" };

    await pool.execute("UPDATE users SET points=points-? WHERE id=?", [amt, fromUserId]);
    await pool.execute("UPDATE users SET points=points+? WHERE id=?", [amt, toUserId]);
  } else {
    // charge (negative) or system add
    // keep simple
  }

  await pool.execute(
    "INSERT INTO point_transactions (from_user_id,to_user_id,amount,reason) VALUES (?,?,?,?)",
    [fromUserId || null, toUserId || null, amt, reason || null]
  );

  return { ok: true };
}

wss.on("connection", (ws) => {
  WS_STATE.set(ws, { userId: null, username: null, rooms: new Set() });

  wsSend(ws, { type: "hello", server_time: Date.now() });

  ws.on("message", async (raw) => {
    const msg = safeJsonParse(raw);
    if (!msg || !msg.type) return;

    // AUTH
    if (msg.type === "auth") {
      try {
        const token = String(msg.token || "");
        const payload = jwt.verify(token, JWT_SECRET);
        const u = await dbOne(
          "SELECT id, username, banned, is_developer FROM users WHERE id=? LIMIT 1",
          [payload.id]
        );
        if (!u || u.banned) {
          wsSend(ws, { type: "auth", ok: false, error: "BANNED_OR_NOUSER" });
          return ws.close();
        }
        const st = WS_STATE.get(ws);
        st.userId = u.id;
        st.username = u.username;

        wsSend(ws, { type: "auth", ok: true, user: { id: u.id, username: u.username, is_developer: !!u.is_developer } });
      } catch {
        wsSend(ws, { type: "auth", ok: false, error: "BAD_TOKEN" });
        return ws.close();
      }
      return;
    }

    // All after this require auth
    const authedUser = await requireWsAuth(ws);
    if (!authedUser) {
      wsSend(ws, { type: "error", error: "UNAUTHORIZED" });
      return;
    }

    const st = WS_STATE.get(ws);

    // JOIN ROOM (auto member create)
    if (msg.type === "join_room") {
      const roomId = mustInt(msg.room_id, 0);
      const room = await dbOne("SELECT * FROM rooms WHERE id=? LIMIT 1", [roomId]);
      if (!room) return wsSend(ws, { type: "join_room", ok: false, error: "ROOM_NOT_FOUND" });

      // ensure member row exists (if not, add as member)
      const existing = await ensureMember(roomId, authedUser.id);
      if (existing && existing.banned) return wsSend(ws, { type: "join_room", ok: false, error: "ROOM_BANNED" });

      if (!existing) {
        // if user globally developer, mark developer in room? (اختياري)
        const role = authedUser.is_developer ? "developer" : "member";
        await pool.execute(
          "INSERT INTO room_members (room_id,user_id,role) VALUES (?,?,?)",
          [roomId, authedUser.id, role]
        );
      } else {
        // if globally developer but room role member, you can upgrade manually later
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
    if (msg.type === "leave_room") {
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
    if (msg.type === "typing") {
      const roomId = mustInt(msg.room_id, 0);
      if (!st.rooms.has(roomId)) return;
      broadcastRoom(roomId, {
        type: "typing",
        room_id: roomId,
        user_id: authedUser.id,
        username: st.username,
        on: !!msg.on,
      });
      return;
    }

    // CHAT SEND
    if (msg.type === "chat") {
      const roomId = mustInt(msg.room_id, 0);
      const text = String(msg.text || "").trim();
      if (!text) return;

      if (!st.rooms.has(roomId)) return wsSend(ws, { type: "chat", ok: false, error: "NOT_IN_ROOM" });

      const { room, member } = await getRoomAndMember(roomId, authedUser.id);
      if (!room || !member) return wsSend(ws, { type: "chat", ok: false, error: "NOT_MEMBER" });
      if (member.banned) return wsSend(ws, { type: "chat", ok: false, error: "ROOM_BANNED" });

      const settings = await dbOne("SELECT chat_disabled, auto_delete_limit FROM room_settings WHERE room_id=? LIMIT 1", [roomId]);
      if (settings?.chat_disabled && roleRank(member.role) < 2) {
        return wsSend(ws, { type: "chat", ok: false, error: "CHAT_DISABLED" });
      }

      if (member.restricted) return wsSend(ws, { type: "chat", ok: false, error: "RESTRICTED" });
      if (isMuted(member)) return wsSend(ws, { type: "chat", ok: false, error: "MUTED" });

      const [r] = await pool.execute(
        "INSERT INTO messages (room_id,user_id,text) VALUES (?,?,?)",
        [roomId, authedUser.id, text]
      );
      const messageId = r.insertId;

      // label for sender
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
          created_at: nowIso(),
          edited_at: null,
          deleted: 0,
          label_text: lbl?.label_text || null,
          label_color: lbl?.label_color || null,
        },
      });

      await enforceAutoDelete(roomId);
      return;
    }

    // EDIT MESSAGE (owner/dev OR message owner)
    if (msg.type === "edit_message") {
      const roomId = mustInt(msg.room_id, 0);
      const messageId = Number(msg.message_id);
      const newText = String(msg.text || "").trim();
      if (!roomId || !messageId || !newText) return;

      const m = await dbOne("SELECT * FROM messages WHERE id=? AND room_id=? LIMIT 1", [messageId, roomId]);
      if (!m || m.deleted) return wsSend(ws, { type: "edit_message", ok: false, error: "NOT_FOUND" });

      const member = await ensureMember(roomId, authedUser.id);
      if (!member) return wsSend(ws, { type: "edit_message", ok: false, error: "NOT_MEMBER" });

      const can = (m.user_id === authedUser.id) || roleRank(member.role) >= 2;
      if (!can) return wsSend(ws, { type: "edit_message", ok: false, error: "NO_PERMISSION" });

      await pool.execute(
        "UPDATE messages SET text=?, edited_at=NOW() WHERE id=?",
        [newText, messageId]
      );

      broadcastRoom(roomId, {
        type: "message_updated",
        room_id: roomId,
        message_id: messageId,
        text: newText,
        edited_at: nowIso(),
      });
      wsSend(ws, { type: "edit_message", ok: true });
      return;
    }

    // DELETE MESSAGE (owner/dev OR message owner)
    if (msg.type === "delete_message") {
      const roomId = mustInt(msg.room_id, 0);
      const messageId = Number(msg.message_id);
      if (!roomId || !messageId) return;

      const m = await dbOne("SELECT * FROM messages WHERE id=? AND room_id=? LIMIT 1", [messageId, roomId]);
      if (!m || m.deleted) return wsSend(ws, { type: "delete_message", ok: false, error: "NOT_FOUND" });

      const member = await ensureMember(roomId, authedUser.id);
      if (!member) return wsSend(ws, { type: "delete_message", ok: false, error: "NOT_MEMBER" });

      const can = (m.user_id === authedUser.id) || roleRank(member.role) >= 2;
      if (!can) return wsSend(ws, { type: "delete_message", ok: false, error: "NO_PERMISSION" });

      await pool.execute("UPDATE messages SET deleted=1 WHERE id=?", [messageId]);

      broadcastRoom(roomId, { type: "message_deleted", room_id: roomId, message_id: messageId });
      wsSend(ws, { type: "delete_message", ok: true });
      return;
    }

    // MODERATION: mute/ban/restrict/kick + chat on/off + set auto delete
    if (msg.type === "moderate") {
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
        await pool.execute(
          "UPDATE room_members SET banned=1 WHERE room_id=? AND user_id=?",
          [roomId, targetUserId]
        );
        broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم حظر المستخدم (${targetUserId})` });
      }

      if (action === "unban") {
        await pool.execute(
          "UPDATE room_members SET banned=0 WHERE room_id=? AND user_id=?",
          [roomId, targetUserId]
        );
        broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم رفع الحظر عن المستخدم (${targetUserId})` });
      }

      if (action === "restrict") {
        await pool.execute(
          "UPDATE room_members SET restricted=1 WHERE room_id=? AND user_id=?",
          [roomId, targetUserId]
        );
        broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم تقييد الدردشة للمستخدم (${targetUserId})` });
      }

      if (action === "unrestrict") {
        await pool.execute(
          "UPDATE room_members SET restricted=0 WHERE room_id=? AND user_id=?",
          [roomId, targetUserId]
        );
        broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم فك التقييد عن المستخدم (${targetUserId})` });
      }

      if (action === "kick") {
        // remove from WS room if online
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

      await broadcastMembersSnapshot(roomId);
      wsSend(ws, { type: "moderate", ok: true });
      return;
    }

    // SET LABEL (dev/owner)
    if (msg.type === "set_label") {
      const roomId = mustInt(msg.room_id, 0);
      const targetUserId = mustInt(msg.target_user_id, 0);
      const labelText = String(msg.label_text || "").trim();
      const labelColor = String(msg.label_color || "#ff3b30").trim();

      if (!roomId || !targetUserId || !labelText) return;

      const canMod = await ensureCanModerate(roomId, authedUser.id);
      if (!canMod) return wsSend(ws, { type: "set_label", ok: false, error: "NO_PERMISSION" });

      await setRoomLabel(roomId, targetUserId, labelText.slice(0, 40), labelColor.slice(0, 20));
      await broadcastMembersSnapshot(roomId);

      wsSend(ws, { type: "set_label", ok: true });
      return;
    }

    // TRANSFER OWNERSHIP (owner only)
    if (msg.type === "transfer_owner") {
      const roomId = mustInt(msg.room_id, 0);
      const newOwnerId = mustInt(msg.new_owner_id, 0);
      if (!roomId || !newOwnerId) return;

      const canOwner = await ensureCanOwner(roomId, authedUser.id);
      if (!canOwner) return wsSend(ws, { type: "transfer_owner", ok: false, error: "ONLY_OWNER" });

      const target = await ensureMember(roomId, newOwnerId);
      if (!target || target.banned) return wsSend(ws, { type: "transfer_owner", ok: false, error: "TARGET_NOT_MEMBER" });

      await pool.execute(
        "UPDATE room_members SET role='member' WHERE room_id=? AND user_id=?",
        [roomId, authedUser.id]
      );
      await pool.execute(
        "UPDATE room_members SET role='owner' WHERE room_id=? AND user_id=?",
        [roomId, newOwnerId]
      );
      await pool.execute(
        "UPDATE rooms SET owner_user_id=? WHERE id=?",
        [newOwnerId, roomId]
      );

      broadcastRoom(roomId, { type: "system", room_id: roomId, text: `تم نقل الملكية الى المستخدم (${newOwnerId})` });
      await broadcastMembersSnapshot(roomId);
      wsSend(ws, { type: "transfer_owner", ok: true });
      return;
    }

    // POINTS GIVE (dev/owner can grant in room OR any user can send if enough)
    if (msg.type === "give_points") {
      const to = mustInt(msg.to_user_id, 0);
      const amount = mustInt(msg.amount, 0);
      const reason = String(msg.reason || "").slice(0, 150);

      if (!to || amount <= 0) return wsSend(ws, { type: "give_points", ok: false, error: "BAD_INPUT" });

      // If msg.room_id exists -> optionally require membership
      const roomId = mustInt(msg.room_id, 0);
      if (roomId) {
        const meMem = await ensureMember(roomId, authedUser.id);
        if (!meMem) return wsSend(ws, { type: "give_points", ok: false, error: "NOT_MEMBER" });
      }

      const r = await updatePoints(authedUser.id, to, amount, reason || "transfer");
      if (!r.ok) return wsSend(ws, { type: "give_points", ok: false, error: r.error });

      wsSend(ws, { type: "give_points", ok: true });
      return;
    }

    /**
     * ===== WebRTC Signaling (Voice Rooms) =====
     * Client sends:
     * - seat_take {room_id, seat_index}
     * - seat_leave {room_id, seat_index}
     * - webrtc_offer/answer/ice {room_id, to_user_id, payload}
     */
    if (msg.type === "seat_take") {
      const roomId = mustInt(msg.room_id, 0);
      const seatIndex = mustInt(msg.seat_index, 0);
      if (!roomId || seatIndex < 1 || seatIndex > 50) return;

      const room = await dbOne("SELECT * FROM rooms WHERE id=? LIMIT 1", [roomId]);
      if (!room || room.type !== "voice") return wsSend(ws, { type: "seat_take", ok: false, error: "NOT_VOICE_ROOM" });

      if (!st.rooms.has(roomId)) return wsSend(ws, { type: "seat_take", ok: false, error: "NOT_IN_ROOM" });

      // seat must be empty
      const seat = await dbOne(
        "SELECT user_id FROM room_seats WHERE room_id=? AND seat_index=? LIMIT 1",
        [roomId, seatIndex]
      );

      if (!seat) {
        await pool.execute(
          "INSERT INTO room_seats (room_id, seat_index, user_id) VALUES (?,?,?)",
          [roomId, seatIndex, authedUser.id]
        );
      } else {
        if (seat.user_id) return wsSend(ws, { type: "seat_take", ok: false, error: "SEAT_TAKEN" });
        await pool.execute(
          "UPDATE room_seats SET user_id=? WHERE room_id=? AND seat_index=?",
          [authedUser.id, roomId, seatIndex]
        );
      }

      await broadcastSeats(roomId);
      wsSend(ws, { type: "seat_take", ok: true });
      return;
    }

    if (msg.type === "seat_leave") {
      const roomId = mustInt(msg.room_id, 0);
      const seatIndex = mustInt(msg.seat_index, 0);
      if (!roomId || seatIndex < 1) return;

      const seat = await dbOne(
        "SELECT user_id FROM room_seats WHERE room_id=? AND seat_index=? LIMIT 1",
        [roomId, seatIndex]
      );

      if (!seat || seat.user_id !== authedUser.id) return wsSend(ws, { type: "seat_leave", ok: false, error: "NOT_YOUR_SEAT" });

      await pool.execute(
        "UPDATE room_seats SET user_id=NULL WHERE room_id=? AND seat_index=?",
        [roomId, seatIndex]
      );
      await broadcastSeats(roomId);
      wsSend(ws, { type: "seat_leave", ok: true });
      return;
    }

    if (msg.type === "webrtc_offer" || msg.type === "webrtc_answer" || msg.type === "webrtc_ice") {
      const roomId = mustInt(msg.room_id, 0);
      const toUserId = mustInt(msg.to_user_id, 0);
      const payload = msg.payload;

      if (!roomId || !toUserId || !payload) return;
      if (!st.rooms.has(roomId)) return;

      // send to target user socket(s) inside room
      const set = ROOM_SOCKETS.get(roomId);
      if (!set) return;

      for (const sock of set) {
        const sst = WS_STATE.get(sock);
        if (sst?.userId === toUserId) {
          wsSend(sock, {
            type: msg.type,
            room_id: roomId,
            from_user_id: authedUser.id,
            payload,
          });
        }
      }
      return;
    }

    // unknown
    wsSend(ws, { type: "error", error: "UNKNOWN_TYPE" });
  });

  ws.on("close", async () => {
    const st = WS_STATE.get(ws);
    WS_STATE.delete(ws);

    if (st?.rooms?.size) {
      for (const roomId of st.rooms) {
        const set = ROOM_SOCKETS.get(roomId);
        if (set) set.delete(ws);

        broadcastRoom(roomId, { type: "system", room_id: roomId, text: `غادر ${st.username || "مستخدم"}` });
        await broadcastMembersSnapshot(roomId);
      }
    }
  });
});

/* ================== START ================== */
async function start() {
  try {
    await initializeDatabase();
    server.listen(PORT, () => {
      console.log(`🚀 Server running on :${PORT}`);
      console.log(`📦 DB: ${DB_CONFIG.host}:${DB_CONFIG.port}/${DB_CONFIG.database}`);
      console.log(`🔐 JWT: READY`);
    });
  } catch (e) {
    console.error("❌ Start failed:", e);
    process.exit(1);
  }
}

start();
