/**
 * COMPLETE SERVER FILE - ProfileHub v2.0
 * Express + Socket.IO + MySQL + JWT + Full API
 * Supports: Chat, Voice Rooms, Frames, Points, Moderation, Bots, Subscriptions
 */

require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3306;
const server = http.createServer(app);

// ================== DATABASE CONFIGURATION ==================
const DB_CONFIG = {
  host: process.env.MYSQLHOST || "localhost",
  port: process.env.MYSQLPORT || 3306,
  user: process.env.MYSQLUSER || "root",
  password: process.env.MYSQLPASSWORD || "",
  database: process.env.MYSQLDATABASE || "profilehub",
  waitForConnections: true,
  connectionLimit: 20,
  queueLimit: 0,
  ssl: process.env.MYSQL_SSL === "true" ? { rejectUnauthorized: false } : false,
};

let pool;
let JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex");

// ================== UTILITY FUNCTIONS ==================
async function dbOne(sql, params = []) {
  try {
    const [rows] = await pool.execute(sql, params);
    return rows && rows.length ? rows[0] : null;
  } catch (error) {
    console.error("Database query error:", error);
    throw error;
  }
}

async function dbAll(sql, params = []) {
  try {
    const [rows] = await pool.execute(sql, params);
    return rows;
  } catch (error) {
    console.error("Database query error:", error);
    throw error;
  }
}

function nowIso() {
  return new Date().toISOString().slice(0, 19).replace("T", " ");
}

function safeJsonParse(str) {
  try {
    return JSON.parse(str);
  } catch {
    return null;
  }
}

function mustInt(n, def = 0) {
  const x = Number(n);
  return Number.isFinite(x) ? Math.trunc(x) : def;
}

// ================== PASSWORD HASHING ==================
const SALT_ROUNDS = 12;

async function hashPassword(password) {
  return await bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// ================== JWT FUNCTIONS ==================
function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      email: user.email,
      is_developer: user.is_developer || false,
      verified: user.verified || false,
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// ================== AUTH MIDDLEWARE ==================
async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "NO_TOKEN" });
  }
  
  const token = authHeader.split(" ")[1];
  const decoded = verifyToken(token);
  
  if (!decoded) {
    return res.status(401).json({ error: "INVALID_TOKEN" });
  }
  
  const user = await dbOne(
    "SELECT id, username, email, is_developer, verified, points, banned, avatar_url, bio, frame_id, created_at FROM users WHERE id = ?",
    [decoded.id]
  );
  
  if (!user || user.banned) {
    return res.status(401).json({ error: "USER_NOT_FOUND_OR_BANNED" });
  }
  
  req.user = user;
  next();
}

// ================== PERMISSIONS ==================
function roleRank(role) {
  const ranks = {
    owner: 3,
    developer: 3,
    admin: 2,
    member: 1,
  };
  return ranks[role] || 1;
}

async function getRoomMember(roomId, userId) {
  return await dbOne(
    "SELECT * FROM room_members WHERE room_id = ? AND user_id = ?",
    [roomId, userId]
  );
}

async function canModerateRoom(roomId, userId) {
  const member = await getRoomMember(roomId, userId);
  if (!member) return false;
  
  const user = await dbOne("SELECT is_developer FROM users WHERE id = ?", [userId]);
  if (user?.is_developer) return true;
  
  return roleRank(member.role) >= 2;
}

async function isRoomOwner(roomId, userId) {
  const member = await getRoomMember(roomId, userId);
  if (!member) return false;
  return member.role === "owner";
}

// ================== DATABASE INITIALIZATION ==================
async function initializeDatabase() {
  try {
    pool = await mysql.createPool(DB_CONFIG);
    console.log("✅ Database connected successfully");
    
    await createTables();
    await createDefaultAdmin();
    
    return true;
  } catch (error) {
    console.error("❌ Database initialization failed:", error);
    return false;
  }
}

async function createTables() {
  const tables = [
    `CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      is_developer BOOLEAN DEFAULT FALSE,
      points INT DEFAULT 100,
      verified BOOLEAN DEFAULT FALSE,
      banned BOOLEAN DEFAULT FALSE,
      avatar_url TEXT,
      bio TEXT,
      links_json JSON,
      frame_id INT,
      referral_code VARCHAR(20) UNIQUE,
      referred_by INT,
      settings_json JSON DEFAULT '{}',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_username (username),
      INDEX idx_email (email),
      INDEX idx_points (points),
      INDEX idx_banned (banned)
    )`,
    
    `CREATE TABLE IF NOT EXISTS frames (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      description TEXT,
      css_class VARCHAR(100),
      image_url TEXT,
      price_points INT DEFAULT 0,
      category VARCHAR(50) DEFAULT 'basic',
      available BOOLEAN DEFAULT TRUE,
      created_by INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_category (category),
      INDEX idx_available (available)
    )`,
    
    `CREATE TABLE IF NOT EXISTS user_frames (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      frame_id INT NOT NULL,
      purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (frame_id) REFERENCES frames(id) ON DELETE CASCADE,
      UNIQUE KEY unique_user_frame (user_id, frame_id),
      INDEX idx_user_id (user_id)
    )`,
    
    `CREATE TABLE IF NOT EXISTS rooms (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      description TEXT,
      type ENUM('text', 'voice') DEFAULT 'text',
      icon VARCHAR(10) DEFAULT '💬',
      owner_id INT NOT NULL,
      price_points INT DEFAULT 0,
      max_members INT DEFAULT 100,
      voice_seats INT DEFAULT 8,
      settings_json JSON DEFAULT '{}',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_type (type),
      INDEX idx_owner_id (owner_id)
    )`,
    
    `CREATE TABLE IF NOT EXISTS room_members (
      id INT AUTO_INCREMENT PRIMARY KEY,
      room_id INT NOT NULL,
      user_id INT NOT NULL,
      role ENUM('owner', 'admin', 'member') DEFAULT 'member',
      joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      muted_until TIMESTAMP NULL,
      is_banned BOOLEAN DEFAULT FALSE,
      label_text VARCHAR(50),
      label_color VARCHAR(20) DEFAULT '#007AFF',
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE KEY unique_room_user (room_id, user_id),
      INDEX idx_room_id (room_id),
      INDEX idx_user_id (user_id),
      INDEX idx_role (role)
    )`,
    
    `CREATE TABLE IF NOT EXISTS messages (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      room_id INT NOT NULL,
      user_id INT NOT NULL,
      text TEXT NOT NULL,
      message_type ENUM('text', 'image', 'system', 'bot') DEFAULT 'text',
      metadata_json JSON,
      edited BOOLEAN DEFAULT FALSE,
      deleted BOOLEAN DEFAULT FALSE,
      deleted_by INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_room_id (room_id),
      INDEX idx_user_id (user_id),
      INDEX idx_created_at (created_at),
      INDEX idx_deleted (deleted)
    )`,
    
    `CREATE TABLE IF NOT EXISTS point_transactions (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      from_user_id INT,
      to_user_id INT NOT NULL,
      amount INT NOT NULL,
      reason VARCHAR(200),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (to_user_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_to_user_id (to_user_id),
      INDEX idx_created_at (created_at)
    )`,
    
    `CREATE TABLE IF NOT EXISTS voice_seats (
      id INT AUTO_INCREMENT PRIMARY KEY,
      room_id INT NOT NULL,
      seat_index INT NOT NULL,
      user_id INT,
      is_locked BOOLEAN DEFAULT FALSE,
      is_muted BOOLEAN DEFAULT FALSE,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
      UNIQUE KEY unique_room_seat (room_id, seat_index),
      INDEX idx_room_id (room_id),
      INDEX idx_user_id (user_id)
    )`,
    
    `CREATE TABLE IF NOT EXISTS bots (
      id INT AUTO_INCREMENT PRIMARY KEY,
      room_id INT NOT NULL,
      name VARCHAR(100) NOT NULL,
      avatar_url TEXT,
      created_by INT NOT NULL,
      enabled BOOLEAN DEFAULT TRUE,
      settings_json JSON DEFAULT '{}',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_room_id (room_id),
      INDEX idx_enabled (enabled)
    )`,
    
    `CREATE TABLE IF NOT EXISTS bot_commands (
      id INT AUTO_INCREMENT PRIMARY KEY,
      bot_id INT NOT NULL,
      trigger_text VARCHAR(200) NOT NULL,
      response_text TEXT NOT NULL,
      match_type ENUM('exact', 'starts_with', 'contains') DEFAULT 'exact',
      enabled BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (bot_id) REFERENCES bots(id) ON DELETE CASCADE,
      INDEX idx_bot_id (bot_id),
      INDEX idx_enabled (enabled)
    )`,
    
    `CREATE TABLE IF NOT EXISTS subscriptions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      plan_key VARCHAR(50) UNIQUE NOT NULL,
      name VARCHAR(100) NOT NULL,
      description TEXT,
      price_usd DECIMAL(10,2) DEFAULT 0.00,
      price_points INT DEFAULT 0,
      duration_days INT DEFAULT 30,
      features_json JSON,
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_is_active (is_active)
    )`,
    
    `CREATE TABLE IF NOT EXISTS user_subscriptions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      subscription_id INT NOT NULL,
      status ENUM('active', 'expired', 'canceled', 'pending') DEFAULT 'pending',
      start_date TIMESTAMP NULL,
      end_date TIMESTAMP NULL,
      payment_method VARCHAR(50),
      transaction_id VARCHAR(100),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
      UNIQUE KEY unique_user_subscription (user_id, subscription_id, status),
      INDEX idx_user_id (user_id),
      INDEX idx_status (status)
    )`,
    
    `CREATE TABLE IF NOT EXISTS payment_methods (
      id INT AUTO_INCREMENT PRIMARY KEY,
      method_key VARCHAR(50) UNIQUE NOT NULL,
      name VARCHAR(100) NOT NULL,
      description TEXT,
      is_active BOOLEAN DEFAULT TRUE,
      config_json JSON,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_is_active (is_active)
    )`,
    
    `CREATE TABLE IF NOT EXISTS server_settings (
      setting_key VARCHAR(100) PRIMARY KEY,
      setting_value TEXT NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`,
  ];
  
  for (const tableSql of tables) {
    try {
      await pool.execute(tableSql);
    } catch (error) {
      console.error("Error creating table:", error.message);
    }
  }
  
  console.log("✅ All tables created successfully");
}

async function createDefaultAdmin() {
  const adminExists = await dbOne("SELECT id FROM users WHERE username = ?", ["admin"]);
  
  if (!adminExists) {
    const adminPassword = await hashPassword("admin123");
    const referralCode = crypto.randomBytes(8).toString("hex").toUpperCase();
    
    await pool.execute(
      `INSERT INTO users (username, email, password_hash, is_developer, verified, points, avatar_url, bio, referral_code, settings_json) 
       VALUES (?, ?, ?, TRUE, TRUE, 10000, ?, ?, ?, ?)`,
      [
        "admin",
        "admin@profilehub.com",
        adminPassword,
        "https://ui-avatars.com/api/?name=Admin&background=007AFF&color=fff&size=150",
        "مدير النظام - يمكنني مساعدتك في أي شيء",
        referralCode,
        JSON.stringify({
          theme: "auto",
          language: "ar",
          notifications: true,
          sound: true,
          privacy: "public"
        })
      ]
    );
    
    console.log("✅ Default admin user created");
  }
}

// ================== REST API ROUTES ==================

// ===== Health Check =====
app.get("/", (req, res) => {
  res.json({
    status: "online",
    name: "ProfileHub API",
    version: "2.0.0",
    timestamp: new Date().toISOString()
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.execute("SELECT 1");
    res.json({
      status: "healthy",
      database: "connected",
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      status: "unhealthy",
      database: "disconnected",
      error: error.message
    });
  }
});

// ===== Authentication Routes =====
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, referral_code } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: "MISSING_FIELDS" });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: "PASSWORD_TOO_SHORT" });
    }
    
    const existingUser = await dbOne(
      "SELECT id FROM users WHERE username = ? OR email = ?",
      [username, email.toLowerCase()]
    );
    
    if (existingUser) {
      return res.status(400).json({ error: "USER_ALREADY_EXISTS" });
    }
    
    const passwordHash = await hashPassword(password);
    const referralCode = crypto.randomBytes(6).toString("hex").toUpperCase();
    
    let referredBy = null;
    let bonusPoints = 0;
    
    if (referral_code) {
      const referrer = await dbOne(
        "SELECT id FROM users WHERE referral_code = ?",
        [referral_code]
      );
      
      if (referrer) {
        referredBy = referrer.id;
        bonusPoints = 1000;
        
        await pool.execute(
          "UPDATE users SET points = points + 500 WHERE id = ?",
          [referrer.id]
        );
        
        await pool.execute(
          "INSERT INTO point_transactions (to_user_id, amount, reason) VALUES (?, ?, ?)",
          [referrer.id, 500, `إحالة: ${username}`]
        );
      }
    }
    
    const [result] = await pool.execute(
      `INSERT INTO users (username, email, password_hash, points, referral_code, referred_by, settings_json) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        username,
        email.toLowerCase(),
        passwordHash,
        100 + bonusPoints,
        referralCode,
        referredBy,
        JSON.stringify({
          theme: "auto",
          language: "ar",
          notifications: true,
          sound: true,
          privacy: "public"
        })
      ]
    );
    
    const userId = result.insertId;
    
    if (bonusPoints > 0) {
      await pool.execute(
        "INSERT INTO point_transactions (to_user_id, amount, reason) VALUES (?, ?, ?)",
        [userId, bonusPoints, "مكافأة التسجيل بكود دعوة"]
      );
    }
    
    const user = await dbOne(
      "SELECT id, username, email, is_developer, verified, points, avatar_url, bio, frame_id, created_at FROM users WHERE id = ?",
      [userId]
    );
    
    const token = generateToken(user);
    
    res.json({
      ok: true,
      token,
      user
    });
    
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "SERVER_ERROR", message: error.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: "MISSING_FIELDS" });
    }
    
    const user = await dbOne(
      "SELECT id, username, email, password_hash, is_developer, verified, points, banned, avatar_url, bio, frame_id, created_at FROM users WHERE email = ? OR username = ?",
      [email.toLowerCase(), email]
    );
    
    if (!user) {
      return res.status(401).json({ error: "INVALID_CREDENTIALS" });
    }
    
    if (user.banned) {
      return res.status(403).json({ error: "ACCOUNT_BANNED" });
    }
    
    const validPassword = await verifyPassword(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "INVALID_CREDENTIALS" });
    }
    
    await pool.execute(
      "UPDATE users SET last_seen = ? WHERE id = ?",
      [nowIso(), user.id]
    );
    
    delete user.password_hash;
    
    const token = generateToken(user);
    
    res.json({
      ok: true,
      token,
      user
    });
    
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "SERVER_ERROR", message: error.message });
  }
});

// ===== Profile Routes =====
app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    res.json({
      ok: true,
      user: req.user
    });
  } catch (error) {
    console.error("Get profile error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.put("/api/profile", authMiddleware, async (req, res) => {
  try {
    const { avatar_url, bio, links_json, frame_id } = req.body;
    
    const updates = [];
    const params = [];
    
    if (avatar_url !== undefined) {
      updates.push("avatar_url = ?");
      params.push(avatar_url);
    }
    
    if (bio !== undefined) {
      updates.push("bio = ?");
      params.push(bio);
    }
    
    if (links_json !== undefined) {
      updates.push("links_json = ?");
      params.push(JSON.stringify(links_json));
    }
    
    if (frame_id !== undefined) {
      if (frame_id !== null) {
        const ownsFrame = await dbOne(
          "SELECT id FROM user_frames WHERE user_id = ? AND frame_id = ?",
          [req.user.id, frame_id]
        );
        
        if (!ownsFrame) {
          return res.status(403).json({ error: "FRAME_NOT_OWNED" });
        }
      }
      
      updates.push("frame_id = ?");
      params.push(frame_id);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: "NO_UPDATES" });
    }
    
    params.push(req.user.id);
    
    await pool.execute(
      `UPDATE users SET ${updates.join(", ")} WHERE id = ?`,
      params
    );
    
    const updatedUser = await dbOne(
      "SELECT id, username, email, is_developer, verified, points, avatar_url, bio, links_json, frame_id, created_at FROM users WHERE id = ?",
      [req.user.id]
    );
    
    res.json({
      ok: true,
      user: updatedUser
    });
    
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ===== Rooms Routes =====
app.get("/api/rooms", authMiddleware, async (req, res) => {
  try {
    const rooms = await dbAll(`
      SELECT r.*, 
             u.username as owner_name,
             u.avatar_url as owner_avatar,
             (SELECT COUNT(*) FROM room_members rm WHERE rm.room_id = r.id AND rm.is_banned = FALSE) as member_count
      FROM rooms r
      LEFT JOIN users u ON r.owner_id = u.id
      ORDER BY r.created_at DESC
      LIMIT 100
    `);
    
    res.json({
      ok: true,
      rooms
    });
  } catch (error) {
    console.error("Get rooms error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/rooms", authMiddleware, async (req, res) => {
  try {
    const { name, description, type, icon, price_points, max_members, voice_seats } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: "ROOM_NAME_REQUIRED" });
    }
    
    const [roomResult] = await pool.execute(
      `INSERT INTO rooms (name, description, type, icon, owner_id, price_points, max_members, voice_seats, settings_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        name,
        description || "",
        type || "text",
        icon || "💬",
        req.user.id,
        price_points || 0,
        max_members || 100,
        voice_seats || 8,
        JSON.stringify({
          auto_delete_limit: 0,
          chat_locked: false,
          voice_enabled: true
        })
      ]
    );
    
    const roomId = roomResult.insertId;
    
    await pool.execute(
      "INSERT INTO room_members (room_id, user_id, role) VALUES (?, ?, 'owner')",
      [roomId, req.user.id]
    );
    
    if (type === "voice") {
      const seats = [];
      for (let i = 1; i <= (voice_seats || 8); i++) {
        seats.push([roomId, i, null, 0, 0]);
      }
      
      if (seats.length > 0) {
        await pool.query(
          "INSERT INTO voice_seats (room_id, seat_index, user_id, is_locked, is_muted) VALUES ?",
          [seats]
        );
      }
    }
    
    const room = await dbOne(`
      SELECT r.*, 
             u.username as owner_name,
             u.avatar_url as owner_avatar
      FROM rooms r
      LEFT JOIN users u ON r.owner_id = u.id
      WHERE r.id = ?
    `, [roomId]);
    
    res.json({
      ok: true,
      room,
      room_id: roomId
    });
    
  } catch (error) {
    console.error("Create room error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.get("/api/rooms/:id", authMiddleware, async (req, res) => {
  try {
    const roomId = mustInt(req.params.id);
    
    const room = await dbOne(`
      SELECT r.*, 
             u.username as owner_name,
             u.avatar_url as owner_avatar,
             (SELECT COUNT(*) FROM room_members rm WHERE rm.room_id = r.id AND rm.is_banned = FALSE) as member_count
      FROM rooms r
      LEFT JOIN users u ON r.owner_id = u.id
      WHERE r.id = ?
    `, [roomId]);
    
    if (!room) {
      return res.status(404).json({ error: "ROOM_NOT_FOUND" });
    }
    
    const members = await dbAll(`
      SELECT rm.*, 
             u.username, 
             u.avatar_url, 
             u.is_developer,
             u.verified,
             u.points,
             uf.frame_id
      FROM room_members rm
      LEFT JOIN users u ON rm.user_id = u.id
      LEFT JOIN user_frames uf ON u.id = uf.user_id AND uf.frame_id = u.frame_id
      WHERE rm.room_id = ? AND rm.is_banned = FALSE
      ORDER BY 
        CASE rm.role 
          WHEN 'owner' THEN 1
          WHEN 'admin' THEN 2
          ELSE 3
        END,
        rm.joined_at ASC
    `, [roomId]);
    
    let seats = [];
    if (room.type === "voice") {
      seats = await dbAll(
        "SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_index ASC",
        [roomId]
      );
    }
    
    const isMember = members.some(m => m.user_id === req.user.id);
    
    res.json({
      ok: true,
      room,
      members,
      seats,
      is_member: isMember
    });
    
  } catch (error) {
    console.error("Get room error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.delete("/api/rooms/:id", authMiddleware, async (req, res) => {
  try {
    const roomId = mustInt(req.params.id);
    
    const room = await dbOne("SELECT owner_id FROM rooms WHERE id = ?", [roomId]);
    
    if (!room) {
      return res.status(404).json({ error: "ROOM_NOT_FOUND" });
    }
    
    const isOwner = room.owner_id === req.user.id;
    const isDeveloper = req.user.is_developer;
    
    if (!isOwner && !isDeveloper) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    await pool.execute("DELETE FROM rooms WHERE id = ?", [roomId]);
    
    res.json({
      ok: true,
      message: "Room deleted successfully"
    });
    
  } catch (error) {
    console.error("Delete room error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ===== Messages Routes =====
app.get("/api/rooms/:id/messages", authMiddleware, async (req, res) => {
  try {
    const roomId = mustInt(req.params.id);
    const limit = mustInt(req.query.limit, 50);
    const beforeId = mustInt(req.query.before_id, 0);
    
    const isMember = await dbOne(
      "SELECT id FROM room_members WHERE room_id = ? AND user_id = ? AND is_banned = FALSE",
      [roomId, req.user.id]
    );
    
    if (!isMember) {
      return res.status(403).json({ error: "NOT_ROOM_MEMBER" });
    }
    
    let query = `
      SELECT m.*, 
             u.username,
             u.avatar_url,
             u.is_developer,
             u.verified,
             rm.label_text,
             rm.label_color
      FROM messages m
      LEFT JOIN users u ON m.user_id = u.id
      LEFT JOIN room_members rm ON m.room_id = rm.room_id AND m.user_id = rm.user_id
      WHERE m.room_id = ? AND m.deleted = FALSE
    `;
    
    const params = [roomId];
    
    if (beforeId > 0) {
      query += " AND m.id < ?";
      params.push(beforeId);
    }
    
    query += " ORDER BY m.id DESC LIMIT ?";
    params.push(limit);
    
    const messages = await dbAll(query, params);
    
    messages.reverse();
    
    res.json({
      ok: true,
      messages
    });
    
  } catch (error) {
    console.error("Get messages error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.put("/api/messages/:id", authMiddleware, async (req, res) => {
  try {
    const messageId = mustInt(req.params.id);
    const { text } = req.body;
    
    if (!text || text.trim().length === 0) {
      return res.status(400).json({ error: "EMPTY_MESSAGE" });
    }
    
    const message = await dbOne(
      "SELECT * FROM messages WHERE id = ? AND deleted = FALSE",
      [messageId]
    );
    
    if (!message) {
      return res.status(404).json({ error: "MESSAGE_NOT_FOUND" });
    }
    
    const isOwner = message.user_id === req.user.id;
    const canModerate = await canModerateRoom(message.room_id, req.user.id);
    
    if (!isOwner && !canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    await pool.execute(
      "UPDATE messages SET text = ?, edited = TRUE, updated_at = ? WHERE id = ?",
      [text.trim(), nowIso(), messageId]
    );
    
    res.json({
      ok: true,
      message: "Message updated successfully"
    });
    
  } catch (error) {
    console.error("Update message error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.delete("/api/messages/:id", authMiddleware, async (req, res) => {
  try {
    const messageId = mustInt(req.params.id);
    
    const message = await dbOne("SELECT * FROM messages WHERE id = ?", [messageId]);
    
    if (!message) {
      return res.status(404).json({ error: "MESSAGE_NOT_FOUND" });
    }
    
    const isOwner = message.user_id === req.user.id;
    const canModerate = await canModerateRoom(message.room_id, req.user.id);
    
    if (!isOwner && !canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    await pool.execute(
      "UPDATE messages SET deleted = TRUE, deleted_by = ?, updated_at = ? WHERE id = ?",
      [req.user.id, nowIso(), messageId]
    );
    
    res.json({
      ok: true,
      message: "Message deleted successfully"
    });
    
  } catch (error) {
    console.error("Delete message error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ===== Points Routes =====
app.post("/api/points/grant", authMiddleware, async (req, res) => {
  try {
    const { to_user_id, amount, reason } = req.body;
    
    if (!to_user_id || !amount || amount <= 0) {
      return res.status(400).json({ error: "INVALID_PARAMETERS" });
    }
    
    if (!req.user.is_developer) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    const targetUser = await dbOne("SELECT id FROM users WHERE id = ?", [to_user_id]);
    if (!targetUser) {
      return res.status(404).json({ error: "USER_NOT_FOUND" });
    }
    
    await pool.execute(
      "UPDATE users SET points = points + ? WHERE id = ?",
      [amount, to_user_id]
    );
    
    await pool.execute(
      "INSERT INTO point_transactions (from_user_id, to_user_id, amount, reason) VALUES (?, ?, ?, ?)",
      [req.user.id, to_user_id, amount, reason || "منح من المطور"]
    );
    
    res.json({
      ok: true,
      message: "Points granted successfully"
    });
    
  } catch (error) {
    console.error("Grant points error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/points/deduct", authMiddleware, async (req, res) => {
  try {
    const { to_user_id, amount, reason } = req.body;
    
    if (!to_user_id || !amount || amount <= 0) {
      return res.status(400).json({ error: "INVALID_PARAMETERS" });
    }
    
    if (!req.user.is_developer) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    const targetUser = await dbOne("SELECT id, points FROM users WHERE id = ?", [to_user_id]);
    if (!targetUser) {
      return res.status(404).json({ error: "USER_NOT_FOUND" });
    }
    
    const newPoints = Math.max(0, targetUser.points - amount);
    
    await pool.execute(
      "UPDATE users SET points = ? WHERE id = ?",
      [newPoints, to_user_id]
    );
    
    await pool.execute(
      "INSERT INTO point_transactions (from_user_id, to_user_id, amount, reason) VALUES (?, ?, ?, ?)",
      [req.user.id, to_user_id, -amount, reason || "خصم من المطور"]
    );
    
    res.json({
      ok: true,
      message: "Points deducted successfully"
    });
    
  } catch (error) {
    console.error("Deduct points error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ===== Moderation Routes =====
app.post("/api/rooms/:id/mute", authMiddleware, async (req, res) => {
  try {
    const roomId = mustInt(req.params.id);
    const { target_user_id, minutes, reason } = req.body;
    
    if (!target_user_id || !minutes) {
      return res.status(400).json({ error: "INVALID_PARAMETERS" });
    }
    
    const canModerate = await canModerateRoom(roomId, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    const muteUntil = new Date(Date.now() + minutes * 60000);
    
    await pool.execute(
      "UPDATE room_members SET muted_until = ? WHERE room_id = ? AND user_id = ?",
      [muteUntil, roomId, target_user_id]
    );
    
    await pool.execute(
      "INSERT INTO messages (room_id, user_id, text, message_type) VALUES (?, 0, ?, 'system')",
      [roomId, `تم كتم المستخدم لمدة ${minutes} دقيقة${reason ? ` - السبب: ${reason}` : ''}`]
    );
    
    res.json({
      ok: true,
      message: "User muted successfully"
    });
    
  } catch (error) {
    console.error("Mute user error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/rooms/:id/ban", authMiddleware, async (req, res) => {
  try {
    const roomId = mustInt(req.params.id);
    const { target_user_id, reason } = req.body;
    
    if (!target_user_id) {
      return res.status(400).json({ error: "INVALID_PARAMETERS" });
    }
    
    const canModerate = await canModerateRoom(roomId, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    await pool.execute(
      "UPDATE room_members SET is_banned = TRUE WHERE room_id = ? AND user_id = ?",
      [roomId, target_user_id]
    );
    
    await pool.execute(
      "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND user_id = ?",
      [roomId, target_user_id]
    );
    
    await pool.execute(
      "INSERT INTO messages (room_id, user_id, text, message_type) VALUES (?, 0, ?, 'system')",
      [roomId, `تم حظر المستخدم من الغرفة${reason ? ` - السبب: ${reason}` : ''}`]
    );
    
    res.json({
      ok: true,
      message: "User banned successfully"
    });
    
  } catch (error) {
    console.error("Ban user error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/rooms/:id/unban", authMiddleware, async (req, res) => {
  try {
    const roomId = mustInt(req.params.id);
    const { target_user_id } = req.body;
    
    if (!target_user_id) {
      return res.status(400).json({ error: "INVALID_PARAMETERS" });
    }
    
    const canModerate = await canModerateRoom(roomId, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    await pool.execute(
      "UPDATE room_members SET is_banned = FALSE WHERE room_id = ? AND user_id = ?",
      [roomId, target_user_id]
    );
    
    res.json({
      ok: true,
      message: "User unbanned successfully"
    });
    
  } catch (error) {
    console.error("Unban user error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/rooms/:id/restrict", authMiddleware, async (req, res) => {
  try {
    const roomId = mustInt(req.params.id);
    const { target_user_id, reason } = req.body;
    
    if (!target_user_id) {
      return res.status(400).json({ error: "INVALID_PARAMETERS" });
    }
    
    const canModerate = await canModerateRoom(roomId, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    await pool.execute(
      "UPDATE room_members SET muted_until = '2030-01-01 00:00:00' WHERE room_id = ? AND user_id = ?",
      [roomId, target_user_id]
    );
    
    await pool.execute(
      "INSERT INTO messages (room_id, user_id, text, message_type) VALUES (?, 0, ?, 'system')",
      [roomId, `تم تقييد المستخدم${reason ? ` - السبب: ${reason}` : ''}`]
    );
    
    res.json({
      ok: true,
      message: "User restricted successfully"
    });
    
  } catch (error) {
    console.error("Restrict user error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/rooms/:id/chat-lock", authMiddleware, async (req, res) => {
  try {
    const roomId = mustInt(req.params.id);
    const { locked, reason } = req.body;
    
    const canModerate = await canModerateRoom(roomId, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    const room = await dbOne("SELECT settings_json FROM rooms WHERE id = ?", [roomId]);
    const settings = room ? safeJsonParse(room.settings_json) || {} : {};
    
    settings.chat_locked = locked === true || locked === 'true' || locked === 1;
    
    await pool.execute(
      "UPDATE rooms SET settings_json = ? WHERE id = ?",
      [JSON.stringify(settings), roomId]
    );
    
    await pool.execute(
      "INSERT INTO messages (room_id, user_id, text, message_type) VALUES (?, 0, ?, 'system')",
      [roomId, `تم ${settings.chat_locked ? 'قفل' : 'فتح'} الدردشة${reason ? ` - السبب: ${reason}` : ''}`]
    );
    
    res.json({
      ok: true,
      message: `Chat ${settings.chat_locked ? 'locked' : 'unlocked'} successfully`
    });
    
  } catch (error) {
    console.error("Chat lock error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/rooms/:id/autodelete", authMiddleware, async (req, res) => {
  try {
    const roomId = mustInt(req.params.id);
    const { limit } = req.body;
    
    const autoDeleteLimit = mustInt(limit, 0);
    
    const canModerate = await canModerateRoom(roomId, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    const room = await dbOne("SELECT settings_json FROM rooms WHERE id = ?", [roomId]);
    const settings = room ? safeJsonParse(room.settings_json) || {} : {};
    
    settings.auto_delete_limit = autoDeleteLimit;
    
    await pool.execute(
      "UPDATE rooms SET settings_json = ? WHERE id = ?",
      [JSON.stringify(settings), roomId]
    );
    
    if (autoDeleteLimit > 0) {
      await cleanupOldMessages(roomId, autoDeleteLimit);
    }
    
    res.json({
      ok: true,
      message: `Auto-delete limit set to ${autoDeleteLimit} messages`
    });
    
  } catch (error) {
    console.error("Auto-delete error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ===== Frames Routes =====
app.get("/api/frames", authMiddleware, async (req, res) => {
  try {
    const frames = await dbAll(`
      SELECT f.*, 
             u.username as creator_name,
             (SELECT COUNT(*) FROM user_frames uf WHERE uf.frame_id = f.id) as users_count
      FROM frames f
      LEFT JOIN users u ON f.created_by = u.id
      WHERE f.available = TRUE
      ORDER BY f.created_at DESC
    `);
    
    const userFrames = await dbAll(
      "SELECT frame_id FROM user_frames WHERE user_id = ?",
      [req.user.id]
    );
    
    const ownedFrameIds = userFrames.map(f => f.frame_id);
    
    const framesWithOwnership = frames.map(frame => ({
      ...frame,
      owned: ownedFrameIds.includes(frame.id),
      selected: req.user.frame_id === frame.id
    }));
    
    res.json({
      ok: true,
      frames: framesWithOwnership
    });
    
  } catch (error) {
    console.error("Get frames error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/frames", authMiddleware, async (req, res) => {
  try {
    const { name, description, css_class, image_url, price_points, category } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: "FRAME_NAME_REQUIRED" });
    }
    
    if (!req.user.is_developer) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    const [result] = await pool.execute(
      `INSERT INTO frames (name, description, css_class, image_url, price_points, category, created_by, available)
       VALUES (?, ?, ?, ?, ?, ?, ?, TRUE)`,
      [
        name,
        description || "",
        css_class || "",
        image_url || "",
        price_points || 0,
        category || "basic",
        req.user.id
      ]
    );
    
    const frameId = result.insertId;
    
    res.json({
      ok: true,
      frame_id: frameId,
      message: "Frame created successfully"
    });
    
  } catch (error) {
    console.error("Create frame error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/frames/purchase", authMiddleware, async (req, res) => {
  try {
    const { frame_id } = req.body;
    
    if (!frame_id) {
      return res.status(400).json({ error: "FRAME_ID_REQUIRED" });
    }
    
    const frame = await dbOne(
      "SELECT id, price_points, available FROM frames WHERE id = ?",
      [frame_id]
    );
    
    if (!frame) {
      return res.status(404).json({ error: "FRAME_NOT_FOUND" });
    }
    
    if (!frame.available) {
      return res.status(400).json({ error: "FRAME_NOT_AVAILABLE" });
    }
    
    const alreadyOwned = await dbOne(
      "SELECT id FROM user_frames WHERE user_id = ? AND frame_id = ?",
      [req.user.id, frame_id]
    );
    
    if (alreadyOwned) {
      return res.status(400).json({ error: "FRAME_ALREADY_OWNED" });
    }
    
    if (frame.price_points > 0 && req.user.points < frame.price_points) {
      return res.status(400).json({ error: "INSUFFICIENT_POINTS" });
    }
    
    if (frame.price_points > 0) {
      await pool.execute(
        "UPDATE users SET points = points - ? WHERE id = ?",
        [frame.price_points, req.user.id]
      );
      
      await pool.execute(
        "INSERT INTO point_transactions (to_user_id, amount, reason) VALUES (?, ?, ?)",
        [req.user.id, -frame.price_points, `شراء إطار: ${frame_id}`]
      );
    }
    
    await pool.execute(
      "INSERT INTO user_frames (user_id, frame_id) VALUES (?, ?)",
      [req.user.id, frame_id]
    );
    
    res.json({
      ok: true,
      message: "Frame purchased successfully"
    });
    
  } catch (error) {
    console.error("Purchase frame error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/frames/select", authMiddleware, async (req, res) => {
  try {
    const { frame_id } = req.body;
    
    if (frame_id === null) {
      await pool.execute(
        "UPDATE users SET frame_id = NULL WHERE id = ?",
        [req.user.id]
      );
      
      return res.json({
        ok: true,
        message: "Frame removed successfully"
      });
    }
    
    const ownsFrame = await dbOne(
      "SELECT id FROM user_frames WHERE user_id = ? AND frame_id = ?",
      [req.user.id, frame_id]
    );
    
    if (!ownsFrame) {
      return res.status(403).json({ error: "FRAME_NOT_OWNED" });
    }
    
    await pool.execute(
      "UPDATE users SET frame_id = ? WHERE id = ?",
      [frame_id, req.user.id]
    );
    
    res.json({
      ok: true,
      message: "Frame selected successfully"
    });
    
  } catch (error) {
    console.error("Select frame error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/frames/grant", authMiddleware, async (req, res) => {
  try {
    const { user_id, frame_id } = req.body;
    
    if (!user_id || !frame_id) {
      return res.status(400).json({ error: "INVALID_PARAMETERS" });
    }
    
    if (!req.user.is_developer) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    const frame = await dbOne("SELECT id FROM frames WHERE id = ?", [frame_id]);
    if (!frame) {
      return res.status(404).json({ error: "FRAME_NOT_FOUND" });
    }
    
    const user = await dbOne("SELECT id FROM users WHERE id = ?", [user_id]);
    if (!user) {
      return res.status(404).json({ error: "USER_NOT_FOUND" });
    }
    
    const alreadyOwned = await dbOne(
      "SELECT id FROM user_frames WHERE user_id = ? AND frame_id = ?",
      [user_id, frame_id]
    );
    
    if (alreadyOwned) {
      return res.status(400).json({ error: "FRAME_ALREADY_OWNED" });
    }
    
    await pool.execute(
      "INSERT INTO user_frames (user_id, frame_id) VALUES (?, ?)",
      [user_id, frame_id]
    );
    
    res.json({
      ok: true,
      message: "Frame granted successfully"
    });
    
  } catch (error) {
    console.error("Grant frame error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ===== Subscriptions Routes =====
app.get("/api/subscriptions", authMiddleware, async (req, res) => {
  try {
    const subscriptions = await dbAll(`
      SELECT * FROM subscriptions 
      WHERE is_active = TRUE 
      ORDER BY price_usd ASC, price_points ASC
    `);
    
    res.json({
      ok: true,
      subscriptions
    });
    
  } catch (error) {
    console.error("Get subscriptions error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.get("/api/payment-methods", authMiddleware, async (req, res) => {
  try {
    const paymentMethods = await dbAll(`
      SELECT * FROM payment_methods 
      WHERE is_active = TRUE 
      ORDER BY id ASC
    `);
    
    res.json({
      ok: true,
      payment_methods: paymentMethods
    });
    
  } catch (error) {
    console.error("Get payment methods error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/subscriptions/subscribe", authMiddleware, async (req, res) => {
  try {
    const { subscription_id, payment_method, months } = req.body;
    
    if (!subscription_id || !payment_method) {
      return res.status(400).json({ error: "INVALID_PARAMETERS" });
    }
    
    const subscription = await dbOne(
      "SELECT * FROM subscriptions WHERE id = ? AND is_active = TRUE",
      [subscription_id]
    );
    
    if (!subscription) {
      return res.status(404).json({ error: "SUBSCRIPTION_NOT_FOUND" });
    }
    
    const paymentMethod = await dbOne(
      "SELECT * FROM payment_methods WHERE method_key = ? AND is_active = TRUE",
      [payment_method]
    );
    
    if (!paymentMethod) {
      return res.status(400).json({ error: "PAYMENT_METHOD_NOT_AVAILABLE" });
    }
    
    const numMonths = Math.max(1, mustInt(months, 1));
    const durationDays = subscription.duration_days * numMonths;
    
    const startDate = new Date();
    const endDate = new Date(startDate);
    endDate.setDate(endDate.getDate() + durationDays);
    
    const [result] = await pool.execute(
      `INSERT INTO user_subscriptions (user_id, subscription_id, status, start_date, end_date, payment_method, transaction_id)
       VALUES (?, ?, 'pending', ?, ?, ?, ?)`,
      [
        req.user.id,
        subscription_id,
        startDate,
        endDate,
        payment_method,
        `TXN-${Date.now()}-${req.user.id}`
      ]
    );
    
    res.json({
      ok: true,
      subscription_id: result.insertId,
      message: "Subscription request submitted"
    });
    
  } catch (error) {
    console.error("Subscribe error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ===== Bots Routes =====
app.get("/api/rooms/:id/bots", authMiddleware, async (req, res) => {
  try {
    const roomId = mustInt(req.params.id);
    
    const isMember = await dbOne(
      "SELECT id FROM room_members WHERE room_id = ? AND user_id = ? AND is_banned = FALSE",
      [roomId, req.user.id]
    );
    
    if (!isMember) {
      return res.status(403).json({ error: "NOT_ROOM_MEMBER" });
    }
    
    const bots = await dbAll(`
      SELECT b.*, u.username as creator_name
      FROM bots b
      LEFT JOIN users u ON b.created_by = u.id
      WHERE b.room_id = ? AND b.enabled = TRUE
      ORDER BY b.created_at ASC
    `, [roomId]);
    
    const botsWithCommands = await Promise.all(
      bots.map(async (bot) => {
        const commands = await dbAll(
          "SELECT * FROM bot_commands WHERE bot_id = ? AND enabled = TRUE ORDER BY created_at ASC",
          [bot.id]
        );
        return { ...bot, commands };
      })
    );
    
    res.json({
      ok: true,
      bots: botsWithCommands
    });
    
  } catch (error) {
    console.error("Get bots error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/bots", authMiddleware, async (req, res) => {
  try {
    const { room_id, name, avatar_url, settings_json } = req.body;
    
    if (!room_id || !name) {
      return res.status(400).json({ error: "INVALID_PARAMETERS" });
    }
    
    const canModerate = await canModerateRoom(room_id, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    const [result] = await pool.execute(
      `INSERT INTO bots (room_id, name, avatar_url, created_by, settings_json)
       VALUES (?, ?, ?, ?, ?)`,
      [
        room_id,
        name,
        avatar_url || "",
        req.user.id,
        JSON.stringify(settings_json || {})
      ]
    );
    
    const botId = result.insertId;
    
    res.json({
      ok: true,
      bot_id: botId,
      message: "Bot created successfully"
    });
    
  } catch (error) {
    console.error("Create bot error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/bots/:id/commands", authMiddleware, async (req, res) => {
  try {
    const botId = mustInt(req.params.id);
    const { trigger_text, response_text, match_type } = req.body;
    
    if (!trigger_text || !response_text) {
      return res.status(400).json({ error: "INVALID_PARAMETERS" });
    }
    
    const bot = await dbOne("SELECT * FROM bots WHERE id = ?", [botId]);
    if (!bot) {
      return res.status(404).json({ error: "BOT_NOT_FOUND" });
    }
    
    const canModerate = await canModerateRoom(bot.room_id, req.user.id);
    const isCreator = bot.created_by === req.user.id;
    
    if (!canModerate && !isCreator) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    const [result] = await pool.execute(
      `INSERT INTO bot_commands (bot_id, trigger_text, response_text, match_type)
       VALUES (?, ?, ?, ?)`,
      [
        botId,
        trigger_text,
        response_text,
        match_type || "exact"
      ]
    );
    
    res.json({
      ok: true,
      command_id: result.insertId,
      message: "Bot command added successfully"
    });
    
  } catch (error) {
    console.error("Add bot command error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ===== Admin Routes =====
app.get("/api/admin/users", authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_developer) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    const users = await dbAll(`
      SELECT id, username, email, is_developer, verified, points, banned, created_at, last_seen
      FROM users
      ORDER BY created_at DESC
      LIMIT 100
    `);
    
    res.json({
      ok: true,
      users
    });
    
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/admin/users/:id/toggle-ban", authMiddleware, async (req, res) => {
  try {
    const userId = mustInt(req.params.id);
    
    if (!req.user.is_developer) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    if (userId === req.user.id) {
      return res.status(400).json({ error: "CANNOT_BAN_SELF" });
    }
    
    const user = await dbOne("SELECT banned FROM users WHERE id = ?", [userId]);
    if (!user) {
      return res.status(404).json({ error: "USER_NOT_FOUND" });
    }
    
    const newBanStatus = !user.banned;
    
    await pool.execute(
      "UPDATE users SET banned = ? WHERE id = ?",
      [newBanStatus, userId]
    );
    
    res.json({
      ok: true,
      banned: newBanStatus,
      message: `User ${newBanStatus ? 'banned' : 'unbanned'} successfully`
    });
    
  } catch (error) {
    console.error("Toggle ban error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/admin/users/:id/toggle-verify", authMiddleware, async (req, res) => {
  try {
    const userId = mustInt(req.params.id);
    
    if (!req.user.is_developer) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    const user = await dbOne("SELECT verified FROM users WHERE id = ?", [userId]);
    if (!user) {
      return res.status(404).json({ error: "USER_NOT_FOUND" });
    }
    
    const newVerifyStatus = !user.verified;
    
    await pool.execute(
      "UPDATE users SET verified = ? WHERE id = ?",
      [newVerifyStatus, userId]
    );
    
    res.json({
      ok: true,
      verified: newVerifyStatus,
      message: `User ${newVerifyStatus ? 'verified' : 'unverified'} successfully`
    });
    
  } catch (error) {
    console.error("Toggle verify error:", error);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ================== SOCKET.IO SERVER ==================
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  },
  transports: ["websocket", "polling"]
});

// Store connected users
const onlineUsers = new Map(); // userId -> socketId
const userRooms = new Map(); // userId -> Set<roomId>

async function cleanupOldMessages(roomId, limit) {
  try {
    const messages = await dbAll(`
      SELECT id FROM messages 
      WHERE room_id = ? AND deleted = FALSE 
      ORDER BY id DESC 
      LIMIT 18446744073709551615 OFFSET ?
    `, [roomId, limit]);
    
    if (messages.length > 0) {
      const ids = messages.map(m => m.id);
      await pool.execute(
        "UPDATE messages SET deleted = TRUE WHERE id IN (?)",
        [ids]
      );
    }
  } catch (error) {
    console.error("Cleanup messages error:", error);
  }
}

// Middleware for socket authentication
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error("Authentication error: No token provided"));
    }
    
    const decoded = verifyToken(token);
    if (!decoded) {
      return next(new Error("Authentication error: Invalid token"));
    }
    
    const user = await dbOne(
      "SELECT id, username, email, is_developer, verified, points, banned FROM users WHERE id = ?",
      [decoded.id]
    );
    
    if (!user || user.banned) {
      return next(new Error("Authentication error: User not found or banned"));
    }
    
    socket.userId = user.id;
    socket.userData = {
      id: user.id,
      username: user.username,
      email: user.email,
      is_developer: user.is_developer,
      verified: user.verified,
      points: user.points
    };
    
    next();
  } catch (error) {
    next(new Error("Authentication error"));
  }
});

io.on("connection", (socket) => {
  console.log(`User connected: ${socket.userId} (${socket.userData.username})`);
  
  // Add user to online users
  onlineUsers.set(socket.userId, socket.id);
  
  // Update user last seen
  pool.execute(
    "UPDATE users SET last_seen = ? WHERE id = ?",
    [nowIso(), socket.userId]
  ).catch(console.error);
  
  // Send welcome message
  socket.emit("welcome", {
    message: "Connected to ProfileHub Socket.IO server",
    user: socket.userData
  });
  
  // Handle joining a room
  socket.on("join_room", async (data) => {
    try {
      const { room_id } = data;
      const roomId = mustInt(room_id);
      
      if (!roomId) {
        socket.emit("error", { message: "Invalid room ID" });
        return;
      }
      
      const room = await dbOne("SELECT * FROM rooms WHERE id = ?", [roomId]);
      if (!room) {
        socket.emit("error", { message: "Room not found" });
        return;
      }
      
      // Check if user is banned from room
      const isBanned = await dbOne(
        "SELECT id FROM room_members WHERE room_id = ? AND user_id = ? AND is_banned = TRUE",
        [roomId, socket.userId]
      );
      
      if (isBanned) {
        socket.emit("error", { message: "You are banned from this room" });
        return;
      }
      
      // Check if room is full
      const memberCount = await dbOne(
        "SELECT COUNT(*) as count FROM room_members WHERE room_id = ? AND is_banned = FALSE",
        [roomId]
      );
      
      if (memberCount.count >= room.max_members) {
        socket.emit("error", { message: "Room is full" });
        return;
      }
      
      // Check if user has enough points to join (if room has price)
      if (room.price_points > 0) {
        const user = await dbOne("SELECT points FROM users WHERE id = ?", [socket.userId]);
        if (user.points < room.price_points) {
          socket.emit("error", { message: "Insufficient points to join this room" });
          return;
        }
        
        // Deduct points
        await pool.execute(
          "UPDATE users SET points = points - ? WHERE id = ?",
          [room.price_points, socket.userId]
        );
        
        // Record transaction
        await pool.execute(
          "INSERT INTO point_transactions (to_user_id, amount, reason) VALUES (?, ?, ?)",
          [socket.userId, -room.price_points, `رسوم الانضمام للغرفة: ${room.name}`]
        );
      }
      
      // Add user to room members if not already a member
      const existingMember = await dbOne(
        "SELECT id FROM room_members WHERE room_id = ? AND user_id = ?",
        [roomId, socket.userId]
      );
      
      if (!existingMember) {
        await pool.execute(
          "INSERT INTO room_members (room_id, user_id, role) VALUES (?, ?, 'member')",
          [roomId, socket.userId]
        );
        
        // Add system message
        await pool.execute(
          "INSERT INTO messages (room_id, user_id, text, message_type) VALUES (?, 0, ?, 'system')",
          [roomId, `${socket.userData.username} انضم للغرفة`]
        );
      }
      
      // Join socket room
      socket.join(`room:${roomId}`);
      
      // Update user rooms tracking
      if (!userRooms.has(socket.userId)) {
        userRooms.set(socket.userId, new Set());
      }
      userRooms.get(socket.userId).add(roomId);
      
      // Get room members
      const members = await dbAll(`
        SELECT rm.*, 
               u.username, 
               u.avatar_url,
               u.is_developer,
               u.verified,
               u.points
        FROM room_members rm
        LEFT JOIN users u ON rm.user_id = u.id
        WHERE rm.room_id = ? AND rm.is_banned = FALSE
      `, [roomId]);
      
      // Get messages
      const messages = await dbAll(`
        SELECT m.*, 
               u.username,
               u.avatar_url,
               u.is_developer,
               u.verified,
               rm.label_text,
               rm.label_color
        FROM messages m
        LEFT JOIN users u ON m.user_id = u.id
        LEFT JOIN room_members rm ON m.room_id = rm.room_id AND m.user_id = rm.user_id
        WHERE m.room_id = ? AND m.deleted = FALSE
        ORDER BY m.id DESC
        LIMIT 100
      `, [roomId]);
      
      // Get voice seats if voice room
      let seats = [];
      if (room.type === "voice") {
        seats = await dbAll(
          "SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_index ASC",
          [roomId]
        );
      }
      
      // Send room data to user
      socket.emit("room_joined", {
        room: {
          ...room,
          members: members.map(m => ({
            user_id: m.user_id,
            username: m.username,
            avatar_url: m.avatar_url,
            role: m.role,
            muted_until: m.muted_until,
            label_text: m.label_text,
            label_color: m.label_color,
            is_developer: m.is_developer,
            verified: m.verified,
            points: m.points
          }))
        },
        messages: messages.reverse(),
        seats
      });
      
      // Notify others in the room
      socket.to(`room:${roomId}`).emit("user_joined", {
        user: {
          id: socket.userId,
          username: socket.userData.username,
          avatar_url: socket.userData.avatar_url,
          is_developer: socket.userData.is_developer,
          verified: socket.userData.verified
        }
      });
      
    } catch (error) {
      console.error("Join room error:", error);
      socket.emit("error", { message: "Server error" });
    }
  });
  
  // Handle leaving a room
  socket.on("leave_room", async (data) => {
    try {
      const { room_id } = data;
      const roomId = mustInt(room_id);
      
      if (!roomId) return;
      
      // Leave socket room
      socket.leave(`room:${roomId}`);
      
      // Update user rooms tracking
      if (userRooms.has(socket.userId)) {
        userRooms.get(socket.userId).delete(roomId);
      }
      
      // Remove from voice seat
      await pool.execute(
        "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND user_id = ?",
        [roomId, socket.userId]
      );
      
      // Notify others
      socket.to(`room:${roomId}`).emit("user_left", {
        user_id: socket.userId,
        username: socket.userData.username
      });
      
      socket.emit("room_left", { room_id: roomId });
      
    } catch (error) {
      console.error("Leave room error:", error);
    }
  });
  
  // Handle chat messages
  socket.on("chat", async (data) => {
    try {
      const { room_id, text, message_type, metadata } = data;
      const roomId = mustInt(room_id);
      
      if (!roomId || !text || text.trim().length === 0) {
        socket.emit("error", { message: "Invalid message" });
        return;
      }
      
      // Check if user is member of room
      const member = await dbOne(
        "SELECT * FROM room_members WHERE room_id = ? AND user_id = ? AND is_banned = FALSE",
        [roomId, socket.userId]
      );
      
      if (!member) {
        socket.emit("error", { message: "You are not a member of this room" });
        return;
      }
      
      // Check if user is muted
      if (member.muted_until && new Date(member.muted_until) > new Date()) {
        socket.emit("error", { message: "You are muted" });
        return;
      }
      
      // Check if chat is locked
      const room = await dbOne(
        "SELECT settings_json FROM rooms WHERE id = ?",
        [roomId]
      );
      
      if (room) {
        const settings = safeJsonParse(room.settings_json) || {};
        if (settings.chat_locked) {
          const canModerate = await canModerateRoom(roomId, socket.userId);
          if (!canModerate) {
            socket.emit("error", { message: "Chat is locked" });
            return;
          }
        }
      }
      
      // Process bot commands
      const bots = await dbAll(`
        SELECT b.*, c.trigger_text, c.response_text, c.match_type
        FROM bots b
        LEFT JOIN bot_commands c ON b.id = c.bot_id
        WHERE b.room_id = ? AND b.enabled = TRUE AND c.enabled = TRUE
      `, [roomId]);
      
      let botResponse = null;
      for (const bot of bots) {
        if (!bot.trigger_text || !bot.response_text) continue;
        
        let shouldRespond = false;
        const messageText = text.trim().toLowerCase();
        const triggerText = bot.trigger_text.toLowerCase();
        
        switch (bot.match_type) {
          case "exact":
            shouldRespond = messageText === triggerText;
            break;
          case "starts_with":
            shouldRespond = messageText.startsWith(triggerText);
            break;
          case "contains":
            shouldRespond = messageText.includes(triggerText);
            break;
        }
        
        if (shouldRespond) {
          botResponse = {
            bot_id: bot.id,
            bot_name: bot.name,
            avatar_url: bot.avatar_url,
            response: bot.response_text
          };
          break;
        }
      }
      
      // Insert message
      const [result] = await pool.execute(
        `INSERT INTO messages (room_id, user_id, text, message_type, metadata_json)
         VALUES (?, ?, ?, ?, ?)`,
        [
          roomId,
          socket.userId,
          text.trim(),
          message_type || "text",
          JSON.stringify(metadata || {})
        ]
      );
      
      const messageId = result.insertId;
      
      // Get message with user info
      const message = await dbOne(`
        SELECT m.*, 
               u.username,
               u.avatar_url,
               u.is_developer,
               u.verified,
               rm.label_text,
               rm.label_color
        FROM messages m
        LEFT JOIN users u ON m.user_id = u.id
        LEFT JOIN room_members rm ON m.room_id = rm.room_id AND m.user_id = rm.user_id
        WHERE m.id = ?
      `, [messageId]);
      
      // Broadcast message to room
      io.to(`room:${roomId}`).emit("chat", { message });
      
      // Send bot response if any
      if (botResponse) {
        // Insert bot message
        const [botResult] = await pool.execute(
          `INSERT INTO messages (room_id, user_id, text, message_type, metadata_json)
           VALUES (?, 0, ?, 'bot', ?)`,
          [
            roomId,
            botResponse.response,
            JSON.stringify({
              bot_id: botResponse.bot_id,
              bot_name: botResponse.bot_name,
              avatar_url: botResponse.avatar_url
            })
          ]
        );
        
        const botMessageId = botResult.insertId;
        const botMessage = await dbOne(
          "SELECT * FROM messages WHERE id = ?",
          [botMessageId]
        );
        
        io.to(`room:${roomId}`).emit("chat", {
          message: {
            ...botMessage,
            username: botResponse.bot_name,
            avatar_url: botResponse.avatar_url,
            is_developer: false,
            verified: false
          }
        });
      }
      
      // Auto-delete old messages if limit is set
      if (room) {
        const settings = safeJsonParse(room.settings_json) || {};
        if (settings.auto_delete_limit > 0) {
          await cleanupOldMessages(roomId, settings.auto_delete_limit);
        }
      }
      
    } catch (error) {
      console.error("Chat error:", error);
      socket.emit("error", { message: "Server error" });
    }
  });
  
  // Handle typing indicator
  socket.on("typing", async (data) => {
    try {
      const { room_id, is_typing } = data;
      const roomId = mustInt(room_id);
      
      if (!roomId) return;
      
      socket.to(`room:${roomId}`).emit("typing", {
        user_id: socket.userId,
        username: socket.userData.username,
        is_typing: !!is_typing
      });
      
    } catch (error) {
      console.error("Typing error:", error);
    }
  });
  
  // Handle voice seat operations
  socket.on("seat_join", async (data) => {
    try {
      const { room_id, seat_index } = data;
      const roomId = mustInt(room_id);
      const seatIndex = mustInt(seat_index);
      
      if (!roomId || !seatIndex) {
        socket.emit("error", { message: "Invalid parameters" });
        return;
      }
      
      // Check if user is room member
      const isMember = await dbOne(
        "SELECT id FROM room_members WHERE room_id = ? AND user_id = ? AND is_banned = FALSE",
        [roomId, socket.userId]
      );
      
      if (!isMember) {
        socket.emit("error", { message: "You are not a member of this room" });
        return;
      }
      
      // Check if room is voice room
      const room = await dbOne("SELECT type FROM rooms WHERE id = ?", [roomId]);
      if (!room || room.type !== "voice") {
        socket.emit("error", { message: "This is not a voice room" });
        return;
      }
      
      // Check if seat exists and is available
      const seat = await dbOne(
        "SELECT * FROM voice_seats WHERE room_id = ? AND seat_index = ?",
        [roomId, seatIndex]
      );
      
      if (!seat) {
        socket.emit("error", { message: "Seat not found" });
        return;
      }
      
      if (seat.user_id !== null && seat.user_id !== socket.userId) {
        socket.emit("error", { message: "Seat is occupied" });
        return;
      }
      
      if (seat.is_locked) {
        socket.emit("error", { message: "Seat is locked" });
        return;
      }
      
      // Remove user from any other seat
      await pool.execute(
        "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND user_id = ?",
        [roomId, socket.userId]
      );
      
      // Occupy seat
      await pool.execute(
        "UPDATE voice_seats SET user_id = ? WHERE room_id = ? AND seat_index = ?",
        [socket.userId, roomId, seatIndex]
      );
      
      // Get updated seats
      const seats = await dbAll(
        "SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_index ASC",
        [roomId]
      );
      
      // Broadcast seat update
      io.to(`room:${roomId}`).emit("seats_update", { seats });
      
    } catch (error) {
      console.error("Seat join error:", error);
      socket.emit("error", { message: "Server error" });
    }
  });
  
  socket.on("seat_leave", async (data) => {
    try {
      const { room_id, seat_index } = data;
      const roomId = mustInt(room_id);
      const seatIndex = mustInt(seat_index);
      
      if (!roomId) return;
      
      if (seatIndex) {
        await pool.execute(
          "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND seat_index = ? AND user_id = ?",
          [roomId, seatIndex, socket.userId]
        );
      } else {
        await pool.execute(
          "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND user_id = ?",
          [roomId, socket.userId]
        );
      }
      
      const seats = await dbAll(
        "SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_index ASC",
        [roomId]
      );
      
      io.to(`room:${roomId}`).emit("seats_update", { seats });
      
    } catch (error) {
      console.error("Seat leave error:", error);
    }
  });
  
  // Handle WebRTC signaling
  socket.on("webrtc_offer", (data) => {
    const { target_user_id, offer } = data;
    const targetSocketId = onlineUsers.get(target_user_id);
    
    if (targetSocketId) {
      io.to(targetSocketId).emit("webrtc_offer", {
        from_user_id: socket.userId,
        offer
      });
    }
  });
  
  socket.on("webrtc_answer", (data) => {
    const { target_user_id, answer } = data;
    const targetSocketId = onlineUsers.get(target_user_id);
    
    if (targetSocketId) {
      io.to(targetSocketId).emit("webrtc_answer", {
        from_user_id: socket.userId,
        answer
      });
    }
  });
  
  socket.on("webrtc_ice_candidate", (data) => {
    const { target_user_id, candidate } = data;
    const targetSocketId = onlineUsers.get(target_user_id);
    
    if (targetSocketId) {
      io.to(targetSocketId).emit("webrtc_ice_candidate", {
        from_user_id: socket.userId,
        candidate
      });
    }
  });
  
  // Handle disconnection
  socket.on("disconnect", async () => {
    console.log(`User disconnected: ${socket.userId} (${socket.userData.username})`);
    
    // Remove from online users
    onlineUsers.delete(socket.userId);
    
    // Remove user from all rooms and clear voice seats
    if (userRooms.has(socket.userId)) {
      const rooms = userRooms.get(socket.userId);
      
      for (const roomId of rooms) {
        // Clear voice seats
        await pool.execute(
          "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND user_id = ?",
          [roomId, socket.userId]
        ).catch(console.error);
        
        // Notify room members
        io.to(`room:${roomId}`).emit("user_left", {
          user_id: socket.userId,
          username: socket.userData.username
        });
      }
      
      userRooms.delete(socket.userId);
    }
  });
});

// ================== ERROR HANDLING ==================
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "INTERNAL_SERVER_ERROR" });
});

app.use((req, res) => {
  res.status(404).json({ error: "NOT_FOUND" });
});

// ================== START SERVER ==================
async function startServer() {
  const dbInitialized = await initializeDatabase();
  
  if (!dbInitialized) {
    console.error("❌ Failed to initialize database. Exiting...");
    process.exit(1);
  }
  
  server.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🌐 Socket.IO server ready`);
    console.log(`📊 Database: ${DB_CONFIG.database}@${DB_CONFIG.host}`);
  });
}

// Handle graceful shutdown
process.on("SIGINT", async () => {
  console.log("Shutting down gracefully...");
  
  if (pool) {
    await pool.end();
  }
  
  io.close(() => {
    console.log("Socket.IO server closed");
    process.exit(0);
  });
});

// Start the server
startServer();
