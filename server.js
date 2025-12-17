/**
 * COMPLETE SERVER FILE - ProfileHub v2.0
 * Express + WebSocket + MySQL + JWT + Full API
 * Supports: Chat, Voice Rooms, Frames, Points, Moderation, Bots, Subscriptions
 */

require("dotenv").config();
const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
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
  
  // Check if user exists and is not banned
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
    developer: 3, // Developer has same rank as owner
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
    
    // Create tables if they don't exist
    await createTables();
    
    // Create default admin user if not exists
    await createDefaultAdmin();
    
    return true;
  } catch (error) {
    console.error("❌ Database initialization failed:", error);
    return false;
  }
}

async function createTables() {
  const tables = [
    // Users table
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
    
    // Frames table
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
    
    // User frames (purchased frames)
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
    
    // Rooms table
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
    
    // Room members table
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
    
    // Messages table
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
    
    // Points transactions table
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
    
    // Voice seats table
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
    
    // Bots table
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
    
    // Bot commands table
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
    
    // Subscriptions table
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
    
    // User subscriptions table
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
    
    // Payment methods table
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
    
    // Server settings table
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
    
    // Check if username or email already exists
    const existingUser = await dbOne(
      "SELECT id FROM users WHERE username = ? OR email = ?",
      [username, email.toLowerCase()]
    );
    
    if (existingUser) {
      return res.status(400).json({ error: "USER_ALREADY_EXISTS" });
    }
    
    // Hash password
    const passwordHash = await hashPassword(password);
    const referralCode = crypto.randomBytes(6).toString("hex").toUpperCase();
    
    // Check referral code
    let referredBy = null;
    let bonusPoints = 0;
    
    if (referral_code) {
      const referrer = await dbOne(
        "SELECT id FROM users WHERE referral_code = ?",
        [referral_code]
      );
      
      if (referrer) {
        referredBy = referrer.id;
        bonusPoints = 1000; // Give 1000 points for using referral code
        
        // Give points to referrer as well
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
    
    // Create user
    const [result] = await pool.execute(
      `INSERT INTO users (username, email, password_hash, points, referral_code, referred_by, settings_json) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        username,
        email.toLowerCase(),
        passwordHash,
        100 + bonusPoints, // Starting points + referral bonus
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
    
    // Add referral transaction if bonus points given
    if (bonusPoints > 0) {
      await pool.execute(
        "INSERT INTO point_transactions (to_user_id, amount, reason) VALUES (?, ?, ?)",
        [userId, bonusPoints, "مكافأة التسجيل بكود دعوة"]
      );
    }
    
    // Get user data
    const user = await dbOne(
      "SELECT id, username, email, is_developer, verified, points, avatar_url, bio, frame_id, created_at FROM users WHERE id = ?",
      [userId]
    );
    
    // Generate token
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
    
    // Find user by email or username
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
    
    // Verify password
    const validPassword = await verifyPassword(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "INVALID_CREDENTIALS" });
    }
    
    // Update last seen
    await pool.execute(
      "UPDATE users SET last_seen = ? WHERE id = ?",
      [nowIso(), user.id]
    );
    
    // Remove password hash from response
    delete user.password_hash;
    
    // Generate token
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
      // Check if user owns the frame
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
    
    // Get updated user
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
    
    // Add creator as owner member
    await pool.execute(
      "INSERT INTO room_members (room_id, user_id, role) VALUES (?, ?, 'owner')",
      [roomId, req.user.id]
    );
    
    // Create voice seats if voice room
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
    
    // Get created room
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
    
    // Get room members
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
    
    // Get voice seats if voice room
    let seats = [];
    if (room.type === "voice") {
      seats = await dbAll(
        "SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_index ASC",
        [roomId]
      );
    }
    
    // Check if user is member
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
    
    // Check if user is owner or developer
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
    
    // Check if user is room member
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
    
    // Reverse to get chronological order
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
    
    // Get message
    const message = await dbOne(
      "SELECT * FROM messages WHERE id = ? AND deleted = FALSE",
      [messageId]
    );
    
    if (!message) {
      return res.status(404).json({ error: "MESSAGE_NOT_FOUND" });
    }
    
    // Check permissions
    const isOwner = message.user_id === req.user.id;
    const canModerate = await canModerateRoom(message.room_id, req.user.id);
    
    if (!isOwner && !canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    // Update message
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
    
    // Get message
    const message = await dbOne("SELECT * FROM messages WHERE id = ?", [messageId]);
    
    if (!message) {
      return res.status(404).json({ error: "MESSAGE_NOT_FOUND" });
    }
    
    // Check permissions
    const isOwner = message.user_id === req.user.id;
    const canModerate = await canModerateRoom(message.room_id, req.user.id);
    
    if (!isOwner && !canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    // Delete message
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
    
    // Only developers can grant points
    if (!req.user.is_developer) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    // Check if target user exists
    const targetUser = await dbOne("SELECT id FROM users WHERE id = ?", [to_user_id]);
    if (!targetUser) {
      return res.status(404).json({ error: "USER_NOT_FOUND" });
    }
    
    // Grant points
    await pool.execute(
      "UPDATE users SET points = points + ? WHERE id = ?",
      [amount, to_user_id]
    );
    
    // Record transaction
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
    
    // Only developers can deduct points
    if (!req.user.is_developer) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    // Check if target user exists
    const targetUser = await dbOne("SELECT id, points FROM users WHERE id = ?", [to_user_id]);
    if (!targetUser) {
      return res.status(404).json({ error: "USER_NOT_FOUND" });
    }
    
    // Ensure user doesn't go below 0
    const newPoints = Math.max(0, targetUser.points - amount);
    
    // Deduct points
    await pool.execute(
      "UPDATE users SET points = ? WHERE id = ?",
      [newPoints, to_user_id]
    );
    
    // Record transaction
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
    
    // Check permissions
    const canModerate = await canModerateRoom(roomId, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    // Calculate mute until time
    const muteUntil = new Date(Date.now() + minutes * 60000);
    
    // Update user mute status
    await pool.execute(
      "UPDATE room_members SET muted_until = ? WHERE room_id = ? AND user_id = ?",
      [muteUntil, roomId, target_user_id]
    );
    
    // Add system message
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
    
    // Check permissions
    const canModerate = await canModerateRoom(roomId, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    // Ban user
    await pool.execute(
      "UPDATE room_members SET is_banned = TRUE WHERE room_id = ? AND user_id = ?",
      [roomId, target_user_id]
    );
    
    // Remove from voice seats
    await pool.execute(
      "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND user_id = ?",
      [roomId, target_user_id]
    );
    
    // Add system message
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
    
    // Check permissions
    const canModerate = await canModerateRoom(roomId, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    // Unban user
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
    
    // Check permissions
    const canModerate = await canModerateRoom(roomId, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    // Restrict user (mute indefinitely)
    await pool.execute(
      "UPDATE room_members SET muted_until = '2030-01-01 00:00:00' WHERE room_id = ? AND user_id = ?",
      [roomId, target_user_id]
    );
    
    // Add system message
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
    
    // Check permissions
    const canModerate = await canModerateRoom(roomId, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    // Update room settings
    const room = await dbOne("SELECT settings_json FROM rooms WHERE id = ?", [roomId]);
    const settings = room ? safeJsonParse(room.settings_json) || {} : {};
    
    settings.chat_locked = locked === true || locked === 'true' || locked === 1;
    
    await pool.execute(
      "UPDATE rooms SET settings_json = ? WHERE id = ?",
      [JSON.stringify(settings), roomId]
    );
    
    // Add system message
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
    
    // Check permissions
    const canModerate = await canModerateRoom(roomId, req.user.id);
    if (!canModerate) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    // Update room settings
    const room = await dbOne("SELECT settings_json FROM rooms WHERE id = ?", [roomId]);
    const settings = room ? safeJsonParse(room.settings_json) || {} : {};
    
    settings.auto_delete_limit = autoDeleteLimit;
    
    await pool.execute(
      "UPDATE rooms SET settings_json = ? WHERE id = ?",
      [JSON.stringify(settings), roomId]
    );
    
    // If auto-delete limit is set, run cleanup
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
    
    // Check which frames user owns
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
    
    // Only developers can create frames
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
    
    // Get frame
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
    
    // Check if already owned
    const alreadyOwned = await dbOne(
      "SELECT id FROM user_frames WHERE user_id = ? AND frame_id = ?",
      [req.user.id, frame_id]
    );
    
    if (alreadyOwned) {
      return res.status(400).json({ error: "FRAME_ALREADY_OWNED" });
    }
    
    // Check if user has enough points
    if (frame.price_points > 0 && req.user.points < frame.price_points) {
      return res.status(400).json({ error: "INSUFFICIENT_POINTS" });
    }
    
    // Deduct points if frame costs points
    if (frame.price_points > 0) {
      await pool.execute(
        "UPDATE users SET points = points - ? WHERE id = ?",
        [frame.price_points, req.user.id]
      );
      
      // Record transaction
      await pool.execute(
        "INSERT INTO point_transactions (to_user_id, amount, reason) VALUES (?, ?, ?)",
        [req.user.id, -frame.price_points, `شراء إطار: ${frame_id}`]
      );
    }
    
    // Add frame to user
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
    
    // If frame_id is null, user wants to remove frame
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
    
    // Check if user owns the frame
    const ownsFrame = await dbOne(
      "SELECT id FROM user_frames WHERE user_id = ? AND frame_id = ?",
      [req.user.id, frame_id]
    );
    
    if (!ownsFrame) {
      return res.status(403).json({ error: "FRAME_NOT_OWNED" });
    }
    
    // Select frame
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
    
    // Only developers can grant frames
    if (!req.user.is_developer) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    // Check if frame exists
    const frame = await dbOne("SELECT id FROM frames WHERE id = ?", [frame_id]);
    if (!frame) {
      return res.status(404).json({ error: "FRAME_NOT_FOUND" });
    }
    
    // Check if user exists
    const user = await dbOne("SELECT id FROM users WHERE id = ?", [user_id]);
    if (!user) {
      return res.status(404).json({ error: "USER_NOT_FOUND" });
    }
    
    // Check if already owned
    const alreadyOwned = await dbOne(
      "SELECT id FROM user_frames WHERE user_id = ? AND frame_id = ?",
      [user_id, frame_id]
    );
    
    if (alreadyOwned) {
      return res.status(400).json({ error: "FRAME_ALREADY_OWNED" });
    }
    
    // Grant frame
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
    
    // Get subscription
    const subscription = await dbOne(
      "SELECT * FROM subscriptions WHERE id = ? AND is_active = TRUE",
      [subscription_id]
    );
    
    if (!subscription) {
      return res.status(404).json({ error: "SUBSCRIPTION_NOT_FOUND" });
    }
    
    // Check payment method
    const paymentMethod = await dbOne(
      "SELECT * FROM payment_methods WHERE method_key = ? AND is_active = TRUE",
      [payment_method]
    );
    
    if (!paymentMethod) {
      return res.status(400).json({ error: "PAYMENT_METHOD_NOT_AVAILABLE" });
    }
    
    const numMonths = Math.max(1, mustInt(months, 1));
    const durationDays = subscription.duration_days * numMonths;
    
    // Calculate dates
    const startDate = new Date();
    const endDate = new Date(startDate);
    endDate.setDate(endDate.getDate() + durationDays);
    
    // Create subscription record
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
    
    // Check if user is room member
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
    
    // Get commands for each bot
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
    
    // Check if user can create bots in this room
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
    
    // Get bot
    const bot = await dbOne("SELECT * FROM bots WHERE id = ?", [botId]);
    if (!bot) {
      return res.status(404).json({ error: "BOT_NOT_FOUND" });
    }
    
    // Check if user can manage this bot
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
    // Only developers can access this
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
    
    // Only developers can ban users
    if (!req.user.is_developer) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    // Cannot ban yourself
    if (userId === req.user.id) {
      return res.status(400).json({ error: "CANNOT_BAN_SELF" });
    }
    
    const user = await dbOne("SELECT banned FROM users WHERE id = ?", [userId]);
    if (!user) {
      return res.status(404).json({ error: "USER_NOT_FOUND" });
    }
    
    // Toggle ban status
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
    
    // Only developers can verify users
    if (!req.user.is_developer) {
      return res.status(403).json({ error: "PERMISSION_DENIED" });
    }
    
    const user = await dbOne("SELECT verified FROM users WHERE id = ?", [userId]);
    if (!user) {
      return res.status(404).json({ error: "USER_NOT_FOUND" });
    }
    
    // Toggle verify status
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

// ================== WEBSOCKET SERVER ==================
const wss = new WebSocket.Server({ server });

// Store connected clients
const clients = new Map(); // userId -> { ws, rooms: Set<roomId> }
const roomClients = new Map(); // roomId -> Set<ws>

// Helper functions
function broadcastToRoom(roomId, message, excludeUserId = null) {
  const clientsInRoom = roomClients.get(roomId);
  if (!clientsInRoom) return;
  
  const messageStr = JSON.stringify(message);
  
  clientsInRoom.forEach(client => {
    const clientData = Array.from(clients.values()).find(c => c.ws === client);
    if (clientData && clientData.userId !== excludeUserId && client.readyState === WebSocket.OPEN) {
      client.send(messageStr);
    }
  });
}

function sendToUser(userId, message) {
  const clientData = clients.get(userId);
  if (clientData && clientData.ws.readyState === WebSocket.OPEN) {
    clientData.ws.send(JSON.stringify(message));
  }
}

// WebSocket connection handler
wss.on("connection", (ws) => {
  let userId = null;
  let userData = null;
  
  ws.on("message", async (message) => {
    try {
      const data = JSON.parse(message.toString());
      
      switch (data.type) {
        case "auth":
          await handleAuth(ws, data);
          break;
        
        case "join_room":
          await handleJoinRoom(ws, data, userId);
          break;
        
        case "leave_room":
          await handleLeaveRoom(ws, data, userId);
          break;
        
        case "chat":
          await handleChat(ws, data, userId);
          break;
        
        case "typing":
          await handleTyping(ws, data, userId);
          break;
        
        case "edit_message":
          await handleEditMessage(ws, data, userId);
          break;
        
        case "delete_message":
          await handleDeleteMessage(ws, data, userId);
          break;
        
        case "moderate":
          await handleModerate(ws, data, userId);
          break;
        
        case "set_label":
          await handleSetLabel(ws, data, userId);
          break;
        
        case "transfer_owner":
          await handleTransferOwner(ws, data, userId);
          break;
        
        case "seat_join":
          await handleSeatJoin(ws, data, userId);
          break;
        
        case "seat_leave":
          await handleSeatLeave(ws, data, userId);
          break;
        
        case "seat_kick":
          await handleSeatKick(ws, data, userId);
          break;
        
        case "seat_lock":
        case "seat_unlock":
          await handleSeatLock(ws, data, userId);
          break;
        
        case "seat_mute":
        case "seat_unmute":
          await handleSeatMute(ws, data, userId);
          break;
        
        case "webrtc_offer":
        case "webrtc_answer":
        case "webrtc_ice":
          await handleWebRTCSignal(ws, data, userId);
          break;
        
        case "ping":
          ws.send(JSON.stringify({ type: "pong" }));
          break;
      }
    } catch (error) {
      console.error("WebSocket message error:", error);
      ws.send(JSON.stringify({ type: "error", error: "INVALID_MESSAGE" }));
    }
  });
  
  ws.on("close", () => {
    if (userId && clients.has(userId)) {
      const clientData = clients.get(userId);
      
      // Leave all rooms
      if (clientData.rooms) {
        clientData.rooms.forEach(roomId => {
          const roomSet = roomClients.get(roomId);
          if (roomSet) {
            roomSet.delete(ws);
            if (roomSet.size === 0) {
              roomClients.delete(roomId);
            }
          }
        });
      }
      
      // Remove from voice seats
      if (userData) {
        pool.execute(
          "UPDATE voice_seats SET user_id = NULL WHERE user_id = ?",
          [userId]
        ).catch(console.error);
      }
      
      clients.delete(userId);
      
      // Notify rooms about user leaving
      if (clientData.rooms) {
        clientData.rooms.forEach(roomId => {
          broadcastToRoom(roomId, {
            type: "user_left",
            user_id: userId,
            username: userData?.username,
            room_id: roomId
          });
        });
      }
    }
  });
  
  // Handle authentication
  async function handleAuth(ws, data) {
    const token = data.token;
    if (!token) {
      ws.send(JSON.stringify({ type: "auth", ok: false, error: "NO_TOKEN" }));
      return;
    }
    
    const decoded = verifyToken(token);
    if (!decoded) {
      ws.send(JSON.stringify({ type: "auth", ok: false, error: "INVALID_TOKEN" }));
      return;
    }
    
    const user = await dbOne(
      "SELECT id, username, email, is_developer, verified, points, banned FROM users WHERE id = ?",
      [decoded.id]
    );
    
    if (!user || user.banned) {
      ws.send(JSON.stringify({ type: "auth", ok: false, error: "USER_NOT_FOUND_OR_BANNED" }));
      return;
    }
    
    userId = user.id;
    userData = user;
    
    clients.set(userId, {
      ws,
      rooms: new Set(),
      userId: user.id,
      username: user.username
    });
    
    ws.send(JSON.stringify({
      type: "auth",
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        is_developer: user.is_developer,
        verified: user.verified,
        points: user.points
      }
    }));
  }
  
  // Handle joining a room
  async function handleJoinRoom(ws, data, userId) {
    if (!userId) {
      ws.send(JSON.stringify({ type: "join_room", ok: false, error: "NOT_AUTHENTICATED" }));
      return;
    }
    
    const roomId = mustInt(data.room_id);
    if (!roomId) {
      ws.send(JSON.stringify({ type: "join_room", ok: false, error: "INVALID_ROOM_ID" }));
      return;
    }
    
    // Check if room exists
    const room = await dbOne("SELECT * FROM rooms WHERE id = ?", [roomId]);
    if (!room) {
      ws.send(JSON.stringify({ type: "join_room", ok: false, error: "ROOM_NOT_FOUND" }));
      return;
    }
    
    // Check if user is banned from room
    const isBanned = await dbOne(
      "SELECT id FROM room_members WHERE room_id = ? AND user_id = ? AND is_banned = TRUE",
      [roomId, userId]
    );
    
    if (isBanned) {
      ws.send(JSON.stringify({ type: "join_room", ok: false, error: "BANNED_FROM_ROOM" }));
      return;
    }
    
    // Check if room is full
    const memberCount = await dbOne(
      "SELECT COUNT(*) as count FROM room_members WHERE room_id = ? AND is_banned = FALSE",
      [roomId]
    );
    
    if (memberCount.count >= room.max_members) {
      ws.send(JSON.stringify({ type: "join_room", ok: false, error: "ROOM_FULL" }));
      return;
    }
    
    // Check if user has enough points to join (if room has price)
    if (room.price_points > 0) {
      const user = await dbOne("SELECT points FROM users WHERE id = ?", [userId]);
      if (user.points < room.price_points) {
        ws.send(JSON.stringify({ type: "join_room", ok: false, error: "INSUFFICIENT_POINTS" }));
        return;
      }
      
      // Deduct points
      await pool.execute(
        "UPDATE users SET points = points - ? WHERE id = ?",
        [room.price_points, userId]
      );
      
      // Record transaction
         await pool.execute(
        "INSERT INTO point_transactions (to_user_id, amount, reason) VALUES (?, ?, ?)",
          [userId, -room.price_points, `رسوم الانضمام للغرفة: ${room.name}`]
         );


         // ... (استمرار من الجزء السابق)

        // Add user to room members if not already a member
        const existingMember = await dbOne(
          "SELECT id FROM room_members WHERE room_id = ? AND user_id = ?",
          [roomId, userId]
        );

        if (!existingMember) {
          await pool.execute(
            "INSERT INTO room_members (room_id, user_id, role) VALUES (?, ?, 'member')",
            [roomId, userId]
          );

          // Add system message
          await pool.execute(
            "INSERT INTO messages (room_id, user_id, text, message_type) VALUES (?, 0, ?, 'system')",
            [roomId, `${userData.username} انضم للغرفة`]
          );
        }

        // Add to WebSocket room tracking
        const clientData = clients.get(userId);
        if (clientData) {
          clientData.rooms.add(roomId);
        }

        if (!roomClients.has(roomId)) {
          roomClients.set(roomId, new Set());
        }
        roomClients.get(roomId).add(ws);

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
                 u.verified
          FROM messages m
          LEFT JOIN users u ON m.user_id = u.id
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

        ws.send(JSON.stringify({
          type: "join_room",
          ok: true,
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
        }));

        // Notify others
        broadcastToRoom(roomId, {
          type: "user_joined",
          user: {
            id: userId,
            username: userData.username,
            avatar_url: userData.avatar_url,
            is_developer: userData.is_developer,
            verified: userData.verified
          }
        }, userId);
      }
      
      async function handleLeaveRoom(ws, data, userId) {
        if (!userId) {
          ws.send(JSON.stringify({ type: "error", error: "NOT_AUTHENTICATED" }));
          return;
        }
        
        const roomId = mustInt(data.room_id);
        if (!roomId) return;
        
        const clientData = clients.get(userId);
        if (clientData) {
          clientData.rooms.delete(roomId);
        }
        
        const roomSet = roomClients.get(roomId);
        if (roomSet) {
          roomSet.delete(ws);
          if (roomSet.size === 0) {
            roomClients.delete(roomId);
          }
        }
        
        // Remove from voice seat
        await pool.execute(
          "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND user_id = ?",
          [roomId, userId]
        );
        
        broadcastToRoom(roomId, {
          type: "user_left",
          user_id: userId,
          username: userData?.username
        });
        
        ws.send(JSON.stringify({
          type: "leave_room",
          ok: true,
          room_id: roomId
        }));
      }
      
      async function handleChat(ws, data, userId) {
        if (!userId) return;
        
        const { room_id, text, message_type, metadata } = data;
        const roomId = mustInt(room_id);
        
        if (!roomId || !text || text.trim().length === 0) {
          ws.send(JSON.stringify({ type: "error", error: "INVALID_MESSAGE" }));
          return;
        }
        
        // Check if user is member of room
        const member = await dbOne(
          "SELECT * FROM room_members WHERE room_id = ? AND user_id = ? AND is_banned = FALSE",
          [roomId, userId]
        );
        
        if (!member) {
          ws.send(JSON.stringify({ type: "error", error: "NOT_ROOM_MEMBER" }));
          return;
        }
        
        // Check if user is muted
        if (member.muted_until && new Date(member.muted_until) > new Date()) {
          ws.send(JSON.stringify({ type: "error", error: "USER_MUTED" }));
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
            // Check if user can bypass lock (moderator or owner)
            const canModerate = await canModerateRoom(roomId, userId);
            if (!canModerate) {
              ws.send(JSON.stringify({ type: "error", error: "CHAT_LOCKED" }));
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
            userId,
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
        
        // Broadcast message
        broadcastToRoom(roomId, {
          type: "chat",
          message
        });
        
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
          
          broadcastToRoom(roomId, {
            type: "chat",
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
      }
      
      async function handleTyping(ws, data, userId) {
        if (!userId) return;
        
        const { room_id, is_typing } = data;
        const roomId = mustInt(room_id);
        
        broadcastToRoom(roomId, {
          type: "typing",
          user_id: userId,
          username: userData?.username,
          is_typing: !!is_typing
        }, userId);
      }
      
      async function handleEditMessage(ws, data, userId) {
        if (!userId) return;
        
        const { message_id, text } = data;
        const messageId = mustInt(message_id);
        
        if (!messageId || !text || text.trim().length === 0) {
          ws.send(JSON.stringify({ type: "error", error: "INVALID_PARAMETERS" }));
          return;
        }
        
        // Get message
        const message = await dbOne(
          "SELECT * FROM messages WHERE id = ? AND deleted = FALSE",
          [messageId]
        );
        
        if (!message) {
          ws.send(JSON.stringify({ type: "error", error: "MESSAGE_NOT_FOUND" }));
          return;
        }
        
        // Check permissions
        const isOwner = message.user_id === userId;
        const canModerate = await canModerateRoom(message.room_id, userId);
        
        if (!isOwner && !canModerate) {
          ws.send(JSON.stringify({ type: "error", error: "PERMISSION_DENIED" }));
          return;
        }
        
        // Update message
        await pool.execute(
          "UPDATE messages SET text = ?, edited = TRUE, updated_at = ? WHERE id = ?",
          [text.trim(), nowIso(), messageId]
        );
        
        // Get updated message
        const updatedMessage = await dbOne(`
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
        
        broadcastToRoom(message.room_id, {
          type: "edit_message",
          message: updatedMessage
        });
      }
      
      async function handleDeleteMessage(ws, data, userId) {
        if (!userId) return;
        
        const { message_id, reason } = data;
        const messageId = mustInt(message_id);
        
        if (!messageId) {
          ws.send(JSON.stringify({ type: "error", error: "INVALID_MESSAGE_ID" }));
          return;
        }
        
        // Get message
        const message = await dbOne("SELECT * FROM messages WHERE id = ?", [messageId]);
        
        if (!message) {
          ws.send(JSON.stringify({ type: "error", error: "MESSAGE_NOT_FOUND" }));
          return;
        }
        
        // Check permissions
        const isOwner = message.user_id === userId;
        const canModerate = await canModerateRoom(message.room_id, userId);
        
        if (!isOwner && !canModerate) {
          ws.send(JSON.stringify({ type: "error", error: "PERMISSION_DENIED" }));
          return;
        }
        
        // Delete message
        await pool.execute(
          "UPDATE messages SET deleted = TRUE, deleted_by = ?, updated_at = ? WHERE id = ?",
          [userId, nowIso(), messageId]
        );
        
        broadcastToRoom(message.room_id, {
          type: "delete_message",
          message_id: messageId,
          deleted_by: userId,
          reason: reason || ""
        });
      }
      
      async function handleModerate(ws, data, userId) {
        if (!userId) return;
        
        const { room_id, action, target_user_id, duration, reason } = data;
        const roomId = mustInt(room_id);
        const targetUserId = mustInt(target_user_id);
        
        if (!roomId || !action || !targetUserId) {
          ws.send(JSON.stringify({ type: "error", error: "INVALID_PARAMETERS" }));
          return;
        }
        
        // Check permissions
        const canModerate = await canModerateRoom(roomId, userId);
        if (!canModerate) {
          ws.send(JSON.stringify({ type: "error", error: "PERMISSION_DENIED" }));
          return;
        }
        
        // Cannot moderate yourself
        if (targetUserId === userId) {
          ws.send(JSON.stringify({ type: "error", error: "CANNOT_MODERATE_SELF" }));
          return;
        }
        
        // Check target user's role
        const targetMember = await getRoomMember(roomId, targetUserId);
        if (!targetMember) {
          ws.send(JSON.stringify({ type: "error", error: "USER_NOT_IN_ROOM" }));
          return;
        }
        
        // Cannot moderate users with same or higher rank
        const userMember = await getRoomMember(roomId, userId);
        const userRank = roleRank(userMember?.role);
        const targetRank = roleRank(targetMember.role);
        
        if (targetRank >= userRank) {
          ws.send(JSON.stringify({ type: "error", error: "CANNOT_MODERATE_HIGHER_RANK" }));
          return;
        }
        
        let message = "";
        
        switch (action) {
          case "mute":
            const muteMinutes = mustInt(duration, 5);
            const muteUntil = new Date(Date.now() + muteMinutes * 60000);
            
            await pool.execute(
              "UPDATE room_members SET muted_until = ? WHERE room_id = ? AND user_id = ?",
              [muteUntil, roomId, targetUserId]
            );
            
            message = `تم كتم ${targetMember.username} لمدة ${muteMinutes} دقيقة${reason ? ` - السبب: ${reason}` : ''}`;
            break;
            
          case "unmute":
            await pool.execute(
              "UPDATE room_members SET muted_until = NULL WHERE room_id = ? AND user_id = ?",
              [roomId, targetUserId]
            );
            
            message = `تم إلغاء كتم ${targetMember.username}`;
            break;
            
          case "ban":
            await pool.execute(
              "UPDATE room_members SET is_banned = TRUE WHERE room_id = ? AND user_id = ?",
              [roomId, targetUserId]
            );
            
            // Remove from voice seats
            await pool.execute(
              "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND user_id = ?",
              [roomId, targetUserId]
            );
            
            // Disconnect user from room
            const targetClient = clients.get(targetUserId);
            if (targetClient) {
              targetClient.ws.send(JSON.stringify({
                type: "banned",
                room_id: roomId,
                reason: reason || ""
              }));
              
              // Remove from room tracking
              targetClient.rooms.delete(roomId);
            }
            
            message = `تم حظر ${targetMember.username} من الغرفة${reason ? ` - السبب: ${reason}` : ''}`;
            break;
            
          case "unban":
            await pool.execute(
              "UPDATE room_members SET is_banned = FALSE WHERE room_id = ? AND user_id = ?",
              [roomId, targetUserId]
            );
            
            message = `تم إلغاء حظر ${targetMember.username}`;
            break;
            
          case "kick":
            // Remove from voice seats
            await pool.execute(
              "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND user_id = ?",
              [roomId, targetUserId]
            );
            
            // Disconnect user from room
            const targetClient2 = clients.get(targetUserId);
            if (targetClient2) {
              targetClient2.ws.send(JSON.stringify({
                type: "kicked",
                room_id: roomId,
                reason: reason || ""
              }));
              
              // Remove from room tracking
              targetClient2.rooms.delete(roomId);
            }
            
            message = `تم طرد ${targetMember.username} من الغرفة${reason ? ` - السبب: ${reason}` : ''}`;
            break;
            
          case "promote":
            await pool.execute(
              "UPDATE room_members SET role = 'admin' WHERE room_id = ? AND user_id = ?",
              [roomId, targetUserId]
            );
            
            message = `تم ترقية ${targetMember.username} إلى مشرف`;
            break;
            
          case "demote":
            await pool.execute(
              "UPDATE room_members SET role = 'member' WHERE room_id = ? AND user_id = ?",
              [roomId, targetUserId]
            );
            
            message = `تم خفض رتبة ${targetMember.username} إلى عضو`;
            break;
        }
        
        // Add system message
        if (message) {
          await pool.execute(
            "INSERT INTO messages (room_id, user_id, text, message_type) VALUES (?, 0, ?, 'system')",
            [roomId, message]
          );
          
          const systemMessage = await dbOne(`
            SELECT * FROM messages 
            WHERE room_id = ? 
            ORDER BY id DESC 
            LIMIT 1
          `, [roomId]);
          
          broadcastToRoom(roomId, {
            type: "chat",
            message: systemMessage
          });
        }
        
        // Update member list
        const members = await dbAll(`
          SELECT rm.*, 
                 u.username, 
                 u.avatar_url,
                 u.is_developer,
                 u.verified
          FROM room_members rm
          LEFT JOIN users u ON rm.user_id = u.id
          WHERE rm.room_id = ? AND rm.is_banned = FALSE
        `, [roomId]);
        
        broadcastToRoom(roomId, {
          type: "members_update",
          members: members.map(m => ({
            user_id: m.user_id,
            username: m.username,
            avatar_url: m.avatar_url,
            role: m.role,
            muted_until: m.muted_until,
            label_text: m.label_text,
            label_color: m.label_color,
            is_developer: m.is_developer,
            verified: m.verified
          }))
        });
      }
      
      async function handleSetLabel(ws, data, userId) {
        if (!userId) return;
        
        const { room_id, target_user_id, label_text, label_color } = data;
        const roomId = mustInt(room_id);
        const targetUserId = mustInt(target_user_id);
        
        if (!roomId || !targetUserId) {
          ws.send(JSON.stringify({ type: "error", error: "INVALID_PARAMETERS" }));
          return;
        }
        
        // Check permissions
        const canModerate = await canModerateRoom(roomId, userId);
        if (!canModerate) {
          ws.send(JSON.stringify({ type: "error", error: "PERMISSION_DENIED" }));
          return;
        }
        
        // Update label
        await pool.execute(
          "UPDATE room_members SET label_text = ?, label_color = ? WHERE room_id = ? AND user_id = ?",
          [label_text || null, label_color || "#007AFF", roomId, targetUserId]
        );
        
        // Get updated member
        const member = await dbOne(`
          SELECT rm.*, 
                 u.username, 
                 u.avatar_url,
                 u.is_developer,
                 u.verified
          FROM room_members rm
          LEFT JOIN users u ON rm.user_id = u.id
          WHERE rm.room_id = ? AND rm.user_id = ?
        `, [roomId, targetUserId]);
        
        broadcastToRoom(roomId, {
          type: "member_update",
          member: {
            user_id: member.user_id,
            username: member.username,
            avatar_url: member.avatar_url,
            role: member.role,
            muted_until: member.muted_until,
            label_text: member.label_text,
            label_color: member.label_color,
            is_developer: member.is_developer,
            verified: member.verified
          }
        });
      }
      
      async function handleTransferOwner(ws, data, userId) {
        if (!userId) return;
        
        const { room_id, new_owner_id } = data;
        const roomId = mustInt(room_id);
        const newOwnerId = mustInt(new_owner_id);
        
        if (!roomId || !newOwnerId) {
          ws.send(JSON.stringify({ type: "error", error: "INVALID_PARAMETERS" }));
          return;
        }
        
        // Check if user is room owner
        const isOwner = await isRoomOwner(roomId, userId);
        if (!isOwner) {
          ws.send(JSON.stringify({ type: "error", error: "PERMISSION_DENIED" }));
          return;
        }
        
        // Check if new owner is room member
        const newOwnerMember = await getRoomMember(roomId, newOwnerId);
        if (!newOwnerMember) {
          ws.send(JSON.stringify({ type: "error", error: "USER_NOT_IN_ROOM" }));
          return;
        }
        
        // Transfer ownership
        await pool.execute(
          "UPDATE rooms SET owner_id = ? WHERE id = ?",
          [newOwnerId, roomId]
        );
        
        await pool.execute(
          "UPDATE room_members SET role = 'owner' WHERE room_id = ? AND user_id = ?",
          [roomId, newOwnerId]
        );
        
        await pool.execute(
          "UPDATE room_members SET role = 'admin' WHERE room_id = ? AND user_id = ?",
          [roomId, userId]
        );
        
        // Add system message
        await pool.execute(
          "INSERT INTO messages (room_id, user_id, text, message_type) VALUES (?, 0, ?, 'system')",
          [roomId, `تم نقل ملكية الغرفة إلى ${newOwnerMember.username}`]
        );
        
        broadcastToRoom(roomId, {
          type: "owner_transferred",
          old_owner_id: userId,
          new_owner_id: newOwnerId
        });
      }
      
      async function handleSeatJoin(ws, data, userId) {
        if (!userId) return;
        
        const { room_id, seat_index } = data;
        const roomId = mustInt(room_id);
        const seatIndex = mustInt(seat_index);
        
        if (!roomId || !seatIndex) {
          ws.send(JSON.stringify({ type: "error", error: "INVALID_PARAMETERS" }));
          return;
        }
        
        // Check if user is room member
        const isMember = await dbOne(
          "SELECT id FROM room_members WHERE room_id = ? AND user_id = ? AND is_banned = FALSE",
          [roomId, userId]
        );
        
        if (!isMember) {
          ws.send(JSON.stringify({ type: "error", error: "NOT_ROOM_MEMBER" }));
          return;
        }
        
        // Check if room is voice room
        const room = await dbOne("SELECT type FROM rooms WHERE id = ?", [roomId]);
        if (!room || room.type !== "voice") {
          ws.send(JSON.stringify({ type: "error", error: "NOT_VOICE_ROOM" }));
          return;
        }
        
        // Check if seat exists and is available
        const seat = await dbOne(
          "SELECT * FROM voice_seats WHERE room_id = ? AND seat_index = ?",
          [roomId, seatIndex]
        );
        
        if (!seat) {
          ws.send(JSON.stringify({ type: "error", error: "SEAT_NOT_FOUND" }));
          return;
        }
        
        if (seat.user_id !== null && seat.user_id !== userId) {
          ws.send(JSON.stringify({ type: "error", error: "SEAT_OCCUPIED" }));
          return;
        }
        
        if (seat.is_locked) {
          ws.send(JSON.stringify({ type: "error", error: "SEAT_LOCKED" }));
          return;
        }
        
        // Remove user from any other seat
        await pool.execute(
          "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND user_id = ?",
          [roomId, userId]
        );
        
        // Occupy seat
        await pool.execute(
          "UPDATE voice_seats SET user_id = ? WHERE room_id = ? AND seat_index = ?",
          [userId, roomId, seatIndex]
        );
        
        // Get updated seats
        const seats = await dbAll(
          "SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_index ASC",
          [roomId]
        );
        
        broadcastToRoom(roomId, {
          type: "seats_update",
          seats
        });
      }
      
      async function handleSeatLeave(ws, data, userId) {
        if (!userId) return;
        
        const { room_id, seat_index } = data;
        const roomId = mustInt(room_id);
        const seatIndex = mustInt(seat_index);
        
        if (!roomId) return;
        
        if (seatIndex) {
          // Leave specific seat
          await pool.execute(
            "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND seat_index = ? AND user_id = ?",
            [roomId, seatIndex, userId]
          );
        } else {
          // Leave all seats
          await pool.execute(
            "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND user_id = ?",
            [roomId, userId]
          );
        }
        
        // Get updated seats
        const seats = await dbAll(
          "SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_index ASC",
          [roomId]
        );
        
        broadcastToRoom(roomId, {
          type: "seats_update",
          seats
        });
      }
      
      async function handleSeatKick(ws, data, userId) {
        if (!userId) return;
        
        const { room_id, seat_index } = data;
        const roomId = mustInt(room_id);
        const seatIndex = mustInt(seat_index);
        
        if (!roomId || !seatIndex) {
          ws.send(JSON.stringify({ type: "error", error: "INVALID_PARAMETERS" }));
          return;
        }
        
        // Check permissions
        const canModerate = await canModerateRoom(roomId, userId);
        if (!canModerate) {
          ws.send(JSON.stringify({ type: "error", error: "PERMISSION_DENIED" }));
          return;
        }
        
        // Get seat
        const seat = await dbOne(
          "SELECT * FROM voice_seats WHERE room_id = ? AND seat_index = ?",
          [roomId, seatIndex]
        );
        
        if (!seat || !seat.user_id) {
          ws.send(JSON.stringify({ type: "error", error: "SEAT_EMPTY" }));
          return;
        }
        
        // Kick user from seat
        await pool.execute(
          "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND seat_index = ?",
          [roomId, seatIndex]
        );
        
        // Notify kicked user
        sendToUser(seat.user_id, {
          type: "seat_kicked",
          room_id: roomId,
          seat_index: seatIndex
        });
        
        // Get updated seats
        const seats = await dbAll(
          "SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_index ASC",
          [roomId]
        );
        
        broadcastToRoom(roomId, {
          type: "seats_update",
          seats
        });
      }
      
      async function handleSeatLock(ws, data, userId) {
        if (!userId) return;
        
        const { room_id, seat_index } = data;
        const roomId = mustInt(room_id);
        const seatIndex = mustInt(seat_index);
        
        if (!roomId || !seatIndex) {
          ws.send(JSON.stringify({ type: "error", error: "INVALID_PARAMETERS" }));
          return;
        }
        
        // Check permissions
        const canModerate = await canModerateRoom(roomId, userId);
        if (!canModerate) {
          ws.send(JSON.stringify({ type: "error", error: "PERMISSION_DENIED" }));
          return;
        }
        
        const action = data.type; // 'seat_lock' or 'seat_unlock'
        const isLocking = action === 'seat_lock';
        
        // Update seat lock status
        await pool.execute(
          "UPDATE voice_seats SET is_locked = ? WHERE room_id = ? AND seat_index = ?",
          [isLocking ? 1 : 0, roomId, seatIndex]
        );
        
        // If locking and seat is occupied, kick user
        if (isLocking) {
          const seat = await dbOne(
            "SELECT * FROM voice_seats WHERE room_id = ? AND seat_index = ?",
            [roomId, seatIndex]
          );
          
          if (seat && seat.user_id) {
            await pool.execute(
              "UPDATE voice_seats SET user_id = NULL WHERE room_id = ? AND seat_index = ?",
              [roomId, seatIndex]
            );
            
            // Notify kicked user
            sendToUser(seat.user_id, {
              type: "seat_locked_kick",
              room_id: roomId,
              seat_index: seatIndex
            });
          }
        }
        
        // Get updated seats
        const seats = await dbAll(
          "SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_index ASC",
          [roomId]
        );
        
        broadcastToRoom(roomId, {
          type: "seats_update",
          seats
        });
      }
      
      async function handleSeatMute(ws, data, userId) {
        if (!userId) return;
        
        const { room_id, seat_index } = data;
        const roomId = mustInt(room_id);
        const seatIndex = mustInt(seat_index);
        
        if (!roomId || !seatIndex) {
          ws.send(JSON.stringify({ type: "error", error: "INVALID_PARAMETERS" }));
          return;
        }
        
        // Check permissions
        const canModerate = await canModerateRoom(roomId, userId);
        if (!canModerate) {
          ws.send(JSON.stringify({ type: "error", error: "PERMISSION_DENIED" }));
          return;
        }
        
        const action = data.type; // 'seat_mute' or 'seat_unmute'
        const isMuting = action === 'seat_mute';
        
        // Update seat mute status
        await pool.execute(
          "UPDATE voice_seats SET is_muted = ? WHERE room_id = ? AND seat_index = ?",
          [isMuting ? 1 : 0, roomId, seatIndex]
        );
        
        // Get updated seats
        const seats = await dbAll(
          "SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_index ASC",
          [roomId]
        );
        
        broadcastToRoom(roomId, {
          type: "seats_update",
          seats
        });
      }
      
      async function handleWebRTCSignal(ws, data, userId) {
        if (!userId) return;
        
        const { room_id, target_user_id, signal } = data;
        const roomId = mustInt(room_id);
        const targetUserId = mustInt(target_user_id);
        
        if (!roomId || !targetUserId || !signal) return;
        
        // Forward signal to target user
        sendToUser(targetUserId, {
          type: data.type,
          from_user_id: userId,
          signal: signal
        });
      }
    });
    
    // Send initial welcome
    ws.send(JSON.stringify({
      type: "welcome",
      message: "Connected to ProfileHub WebSocket server"
    }));
  });
  
  // ================== HELPER FUNCTIONS ==================
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
  
  // ================== START SERVER ==================
  async function startServer() {
    const dbInitialized = await initializeDatabase();
    
    if (!dbInitialized) {
      console.error("❌ Failed to initialize database. Exiting...");
      process.exit(1);
    }
    
    server.listen(PORT, () => {
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`🌐 WebSocket server ready`);
      console.log(`📊 Database: ${DB_CONFIG.database}@${DB_CONFIG.host}`);
    });
  }
  
  // Handle graceful shutdown
  process.on("SIGINT", async () => {
    console.log("Shutting down gracefully...");
    
    if (pool) {
      await pool.end();
    }
    
    wss.close(() => {
      console.log("WebSocket server closed");
      process.exit(0);
    });
  });
  
  // ================== ERROR HANDLING ==================
  app.use((err, req, res, next) => {
    console.error("Unhandled error:", err);
    res.status(500).json({ error: "INTERNAL_SERVER_ERROR" });
  });
  
  // 404 handler
  app.use((req, res) => {
    res.status(404).json({ error: "NOT_FOUND" });
  });
  
  // ================== EXPORT FOR TESTING ==================
  if (require.main === module) {
    startServer();
  } else {
    module.exports = {
      app,
      server,
      wss,
      pool,
      initializeDatabase,
      startServer
    };
  }
});

// إذا كان الملف يتم تشغيله مباشرة
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  
  initializeDatabase().then(dbInitialized => {
    if (!dbInitialized) {
      console.error("❌ Failed to initialize database. Exiting...");
      process.exit(1);
    }
    
    server.listen(PORT, () => {
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`🌐 WebSocket server ready`);
      console.log(`📊 Database: ${DB_CONFIG.database}@${DB_CONFIG.host}`);
    });
  });
}
