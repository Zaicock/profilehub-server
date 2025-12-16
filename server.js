const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

// إنشاء تطبيق Express
const app = express();
const server = http.createServer(app);

// تكوين Socket.io مع CORS
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket', 'polling']
});

// تكوين CORS للتطبيق
app.use(cors({
  origin: "*",
  credentials: true
}));

// معالجة JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ========== معالجة Railway Environment Variables ==========
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || process.env.RAILWAY_JWT_SECRET || 'your-jwt-secret-key-change-this';

// تأكد من وجود متغيرات البيئة المطلوبة
if (!process.env.MYSQLHOST || !process.env.MYSQLUSER || !process.env.MYSQLPASSWORD || !process.env.MYSQLDATABASE) {
  console.error('❌ خطأ: متغيرات قاعدة البيانات مفقودة في بيئة Railway');
  console.error('يرجى تعيين MYSQLHOST, MYSQLUSER, MYSQLPASSWORD, MYSQLDATABASE');
  process.exit(1);
}

// تكوين اتصال قاعدة البيانات مباشرة من Railway
const DB_CONFIG = {
  host: process.env.MYSQLHOST,
  port: process.env.MYSQLPORT || 3306,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: process.env.MYSQL_SSL === 'true' ? { rejectUnauthorized: false } : false
};

// إنشاء تجمع اتصالات قاعدة البيانات
let pool;
async function initializeDatabase() {
  try {
    pool = mysql.createPool(DB_CONFIG);
    
    // اختبار الاتصال بقاعدة البيانات
    const connection = await pool.getConnection();
    console.log('✅ تم الاتصال بقاعدة البيانات بنجاح');
    connection.release();
    
    // إنشاء الجداول إذا لم تكن موجودة
    await createTablesIfNotExist();
    
  } catch (error) {
    console.error('❌ خطأ في الاتصال بقاعدة البيانات:', error.message);
    console.error('تأكد من أن متغيرات Railway صحيحة وأن قاعدة البيانات قيد التشغيل');
    process.exit(1);
  }
}

// ========== إنشاء الجداول إذا لم تكن موجودة ==========
async function createTablesIfNotExist() {
  const tables = [
    `CREATE TABLE IF NOT EXISTS users (
      id VARCHAR(36) PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role ENUM('owner', 'developer', 'member', 'admin') DEFAULT 'member',
      points INT DEFAULT 0,
      verified BOOLEAN DEFAULT FALSE,
      banned BOOLEAN DEFAULT FALSE,
      subscription_level ENUM('free', 'premium', 'vip') DEFAULT 'free',
      subscription_end_date DATETIME,
      referral_code VARCHAR(20) UNIQUE,
      referred_by VARCHAR(36),
      avatar_url TEXT,
      badges JSON DEFAULT '[]',
      custom_badges JSON DEFAULT '[]',
      settings JSON DEFAULT '{}',
      last_seen DATETIME,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_username (username),
      INDEX idx_email (email),
      INDEX idx_role (role)
    )`,
    
    `CREATE TABLE IF NOT EXISTS profiles (
      id VARCHAR(36) PRIMARY KEY,
      user_id VARCHAR(36) UNIQUE NOT NULL,
      name VARCHAR(100),
      bio TEXT,
      avatar_url TEXT,
      frame_id VARCHAR(36),
      name_color VARCHAR(7) DEFAULT '#007AFF',
      animated_name BOOLEAN DEFAULT FALSE,
      bg_color VARCHAR(7) DEFAULT '#667eea',
      text_effect VARCHAR(50),
      button_style VARCHAR(50) DEFAULT 'gradient',
      links JSON DEFAULT '[]',
      images JSON DEFAULT '[]',
      views INT DEFAULT 0,
      followers INT DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_user_id (user_id)
    )`,
    
    `CREATE TABLE IF NOT EXISTS rooms (
      id VARCHAR(36) PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      description TEXT,
      icon VARCHAR(10),
      owner_id VARCHAR(36) NOT NULL,
      type ENUM('public', 'private', 'premium') DEFAULT 'public',
      price INT DEFAULT 0,
      max_members INT DEFAULT 100,
      current_members INT DEFAULT 0,
      auto_delete_limit INT DEFAULT 1000,
      chat_locked BOOLEAN DEFAULT FALSE,
      voice_seats_count INT DEFAULT 8,
      voice_enabled BOOLEAN DEFAULT TRUE,
      settings JSON DEFAULT '{}',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_owner_id (owner_id),
      INDEX idx_type (type)
    )`,
    
    `CREATE TABLE IF NOT EXISTS room_members (
      id VARCHAR(36) PRIMARY KEY,
      room_id VARCHAR(36) NOT NULL,
      user_id VARCHAR(36) NOT NULL,
      role ENUM('owner', 'admin', 'moderator', 'member') DEFAULT 'member',
      joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      muted_until DATETIME,
      banned BOOLEAN DEFAULT FALSE,
      UNIQUE KEY unique_room_user (room_id, user_id),
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_room_id (room_id),
      INDEX idx_user_id (user_id)
    )`,
    
    `CREATE TABLE IF NOT EXISTS messages (
      id VARCHAR(36) PRIMARY KEY,
      room_id VARCHAR(36) NOT NULL,
      user_id VARCHAR(36) NOT NULL,
      text TEXT NOT NULL,
      type ENUM('text', 'image', 'system', 'command') DEFAULT 'text',
      metadata JSON DEFAULT '{}',
      edited_at DATETIME,
      deleted_at DATETIME,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_room_id (room_id),
      INDEX idx_user_id (user_id),
      INDEX idx_created_at (created_at)
    )`,
    
    `CREATE TABLE IF NOT EXISTS frames (
      id VARCHAR(36) PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      css_class VARCHAR(100) UNIQUE NOT NULL,
      image_url TEXT,
      type ENUM('css', 'image') DEFAULT 'css',
      price INT DEFAULT 0,
      category ENUM('basic', 'premium', 'special', 'exclusive') DEFAULT 'basic',
      available BOOLEAN DEFAULT TRUE,
      description TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_category (category),
      INDEX idx_available (available)
    )`,
    
    `CREATE TABLE IF NOT EXISTS user_frames (
      id VARCHAR(36) PRIMARY KEY,
      user_id VARCHAR(36) NOT NULL,
      frame_id VARCHAR(36) NOT NULL,
      purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      active BOOLEAN DEFAULT TRUE,
      UNIQUE KEY unique_user_frame (user_id, frame_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (frame_id) REFERENCES frames(id) ON DELETE CASCADE,
      INDEX idx_user_id (user_id)
    )`,
    
    `CREATE TABLE IF NOT EXISTS bots (
      id VARCHAR(36) PRIMARY KEY,
      room_id VARCHAR(36) NOT NULL,
      name VARCHAR(100) NOT NULL,
      avatar_url TEXT,
      owner_id VARCHAR(36) NOT NULL,
      commands JSON DEFAULT '[]',
      settings JSON DEFAULT '{}',
      enabled BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_room_id (room_id)
    )`,
    
    `CREATE TABLE IF NOT EXISTS voice_seats (
      id VARCHAR(36) PRIMARY KEY,
      room_id VARCHAR(36) NOT NULL,
      seat_number INT NOT NULL,
      user_id VARCHAR(36),
      is_locked BOOLEAN DEFAULT FALSE,
      is_muted BOOLEAN DEFAULT FALSE,
      joined_at DATETIME,
      UNIQUE KEY unique_room_seat (room_id, seat_number),
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
      INDEX idx_room_id (room_id),
      INDEX idx_user_id (user_id)
    )`,
    
    `CREATE TABLE IF NOT EXISTS subscriptions (
      id VARCHAR(36) PRIMARY KEY,
      user_id VARCHAR(36) NOT NULL,
      plan_type ENUM('monthly', 'yearly', 'lifetime') NOT NULL,
      payment_method VARCHAR(50),
      transaction_id VARCHAR(100),
      amount DECIMAL(10,2) NOT NULL,
      status ENUM('active', 'expired', 'cancelled', 'pending') DEFAULT 'pending',
      start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      end_date DATETIME,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_user_id (user_id),
      INDEX idx_status (status)
    )`,
    
    `CREATE TABLE IF NOT EXISTS moderation_logs (
      id VARCHAR(36) PRIMARY KEY,
      room_id VARCHAR(36) NOT NULL,
      target_user_id VARCHAR(36) NOT NULL,
      moderator_id VARCHAR(36) NOT NULL,
      action_type ENUM('mute', 'ban', 'kick', 'warn', 'restrict', 'chat_lock') NOT NULL,
      reason TEXT,
      duration_minutes INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (moderator_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_room_id (room_id),
      INDEX idx_target_user_id (target_user_id)
    )`,
    
    `CREATE TABLE IF NOT EXISTS user_points (
      id VARCHAR(36) PRIMARY KEY,
      user_id VARCHAR(36) NOT NULL,
      points INT NOT NULL,
      type ENUM('grant', 'deduct', 'purchase', 'reward') NOT NULL,
      reason TEXT,
      reference_id VARCHAR(36),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_user_id (user_id)
    )`
  ];
  
  try {
    for (const tableSQL of tables) {
      await pool.execute(tableSQL);
    }
    console.log('✅ تم إنشاء/تأكيد الجداول بنجاح');
  } catch (error) {
    console.error('❌ خطأ في إنشاء الجداول:', error);
  }
}

// ========== Middleware المصادقة ==========
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'توكن المصادقة مطلوب' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const [users] = await pool.execute(
      'SELECT id, username, email, role, points, verified, banned, subscription_level, avatar_url, badges, custom_badges, settings FROM users WHERE id = ?',
      [decoded.userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }

    if (users[0].banned) {
      return res.status(403).json({ error: 'الحساب محظور' });
    }

    req.user = users[0];
    next();
  } catch (error) {
    return res.status(403).json({ error: 'توكن غير صالح' });
  }
};

// ========== دوال المساعدة ==========
function generateId() {
  return 'xxxx-xxxx-xxxx-xxxx'.replace(/x/g, () => 
    Math.floor(Math.random() * 16).toString(16)
  );
}

function generateReferralCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

// ========== API Routes ==========

// 1. المسار الرئيسي للتحقق من السيرفر
app.get('/', (req, res) => {
  res.json({ 
    status: 'active', 
    message: 'ProfileHub Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// 2. تسجيل المستخدم الجديد
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, referralCode } = req.body;

    // التحقق من البيانات
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }

    // التحقق من أن المستخدم غير موجود
    const [existingUsers] = await pool.execute(
      'SELECT id FROM users WHERE username = ? OR email = ?',
      [username, email]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({ error: 'اسم المستخدم أو البريد الإلكتروني موجود بالفعل' });
    }

    // تجزئة كلمة المرور
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const userId = generateId();
    const userReferralCode = generateReferralCode();

    // إنشاء المستخدم
    await pool.execute(
      `INSERT INTO users (id, username, email, password_hash, referral_code, points, created_at) 
       VALUES (?, ?, ?, ?, ?, 1000, NOW())`,
      [userId, username, email, passwordHash, userReferralCode]
    );

    // إنشاء البروفايل الافتراضي
    await pool.execute(
      `INSERT INTO profiles (id, user_id, name, avatar_url, created_at) 
       VALUES (?, ?, ?, ?, NOW())`,
      [generateId(), userId, username, `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=007AFF&color=fff&size=150`]
    );

    // منح نقاط الإحالة إذا كان هناك كود إحالة
    if (referralCode) {
      const [referrers] = await pool.execute(
        'SELECT id FROM users WHERE referral_code = ?',
        [referralCode]
      );

      if (referrers.length > 0) {
        const referrerId = referrers[0].id;
        
        // تحديث نقاط المُحيل
        await pool.execute(
          'UPDATE users SET points = points + 500 WHERE id = ?',
          [referrerId]
        );

        // تسجيل عملية النقاط
        await pool.execute(
          'INSERT INTO user_points (id, user_id, points, type, reason, created_at) VALUES (?, ?, ?, ?, ?, NOW())',
          [generateId(), referrerId, 500, 'reward', 'مكافأة إحالة']
        );

        // تحديث المستخدم الجديد بالإحالة
        await pool.execute(
          'UPDATE users SET referred_by = ? WHERE id = ?',
          [referrerId, userId]
        );

        // منح المستخدم الجديد نقاط إضافية
        await pool.execute(
          'UPDATE users SET points = points + 500 WHERE id = ?',
          [userId]
        );

        await pool.execute(
          'INSERT INTO user_points (id, user_id, points, type, reason, created_at) VALUES (?, ?, ?, ?, ?, NOW())',
          [generateId(), userId, 500, 'reward', 'مكافأة التسجيل بكود دعوة']
        );
      }
    }

    // إنشاء التوكن
    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });

    // جلب بيانات المستخدم
    const [users] = await pool.execute(
      'SELECT id, username, email, role, points, verified, subscription_level, avatar_url FROM users WHERE id = ?',
      [userId]
    );

    res.status(201).json({
      message: 'تم إنشاء الحساب بنجاح',
      token,
      user: users[0]
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

// 3. تسجيل الدخول
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان' });
    }

    // البحث عن المستخدم
    const [users] = await pool.execute(
      'SELECT id, username, email, password_hash, role, points, verified, banned, subscription_level, avatar_url, badges, custom_badges FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    const user = users[0];

    // التحقق من الحظر
    if (user.banned) {
      return res.status(403).json({ error: 'الحساب محظور' });
    }

    // التحقق من كلمة المرور
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    // تحديث آخر ظهور
    await pool.execute(
      'UPDATE users SET last_seen = NOW() WHERE id = ?',
      [user.id]
    );

    // إنشاء التوكن
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

    // إزالة كلمة المرور من الاستجابة
    delete user.password_hash;

    res.json({
      message: 'تم تسجيل الدخول بنجاح',
      token,
      user
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

// 4. التحقق من التوكن
app.get('/api/verify', authenticateToken, (req, res) => {
  res.json({ 
    valid: true, 
    user: req.user 
  });
});

// 5. تحديث البروفايل
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { name, bio, avatar_url, name_color, animated_name, bg_color } = req.body;
    const userId = req.user.id;

    // التحقق من وجود البروفايل
    const [profiles] = await pool.execute(
      'SELECT id FROM profiles WHERE user_id = ?',
      [userId]
    );

    if (profiles.length === 0) {
      // إنشاء بروفايل جديد
      await pool.execute(
        `INSERT INTO profiles (id, user_id, name, bio, avatar_url, name_color, animated_name, bg_color, created_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [generateId(), userId, name || req.user.username, bio, avatar_url, name_color, animated_name, bg_color]
      );
    } else {
      // تحديث البروفايل الموجود
      await pool.execute(
        `UPDATE profiles SET 
         name = COALESCE(?, name),
         bio = COALESCE(?, bio),
         avatar_url = COALESCE(?, avatar_url),
         name_color = COALESCE(?, name_color),
         animated_name = COALESCE(?, animated_name),
         bg_color = COALESCE(?, bg_color),
         updated_at = NOW()
         WHERE user_id = ?`,
        [name, bio, avatar_url, name_color, animated_name, bg_color, userId]
      );
    }

    // جلب البروفايل المحدث
    const [updatedProfiles] = await pool.execute(
      'SELECT * FROM profiles WHERE user_id = ?',
      [userId]
    );

    res.json({
      message: 'تم تحديث البروفايل بنجاح',
      profile: updatedProfiles[0]
    });

  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'خطأ في تحديث البروفايل' });
  }
});

// 6. الحصول على البروفايل
app.get('/api/profile/:userId?', authenticateToken, async (req, res) => {
  try {
    const targetUserId = req.params.userId || req.user.id;

    const [profiles] = await pool.execute(
      'SELECT * FROM profiles WHERE user_id = ?',
      [targetUserId]
    );

    const [users] = await pool.execute(
      'SELECT id, username, email, role, points, verified, subscription_level, avatar_url, badges, custom_badges, created_at FROM users WHERE id = ?',
      [targetUserId]
    );

    if (profiles.length === 0 || users.length === 0) {
      return res.status(404).json({ error: 'البروفايل غير موجود' });
    }

    // زيادة عدد المشاهدات
    await pool.execute(
      'UPDATE profiles SET views = views + 1 WHERE user_id = ?',
      [targetUserId]
    );

    res.json({
      profile: profiles[0],
      user: users[0]
    });

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'خطأ في جلب البروفايل' });
  }
});

// 7. إدارة الغرف
app.get('/api/rooms', authenticateToken, async (req, res) => {
  try {
    const [rooms] = await pool.execute(
      `SELECT r.*, u.username as owner_name, 
       (SELECT COUNT(*) FROM room_members rm WHERE rm.room_id = r.id) as member_count
       FROM rooms r
       LEFT JOIN users u ON r.owner_id = u.id
       WHERE r.type = 'public' OR EXISTS (
         SELECT 1 FROM room_members rm 
         WHERE rm.room_id = r.id AND rm.user_id = ?
       )
       ORDER BY r.created_at DESC`,
      [req.user.id]
    );

    res.json({ rooms });
  } catch (error) {
    console.error('Get rooms error:', error);
    res.status(500).json({ error: 'خطأ في جلب الغرف' });
  }
});

app.post('/api/rooms', authenticateToken, async (req, res) => {
  try {
    const { name, description, icon, type, price, max_members } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'اسم الغرفة مطلوب' });
    }

    const roomId = generateId();
    
    await pool.execute(
      `INSERT INTO rooms (id, name, description, icon, owner_id, type, price, max_members, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [roomId, name, description, icon || '💬', req.user.id, type || 'public', price || 0, max_members || 100]
    );

    // إضافة المالك كعضو
    await pool.execute(
      `INSERT INTO room_members (id, room_id, user_id, role, joined_at)
       VALUES (?, ?, ?, 'owner', NOW())`,
      [generateId(), roomId, req.user.id]
    );

    res.status(201).json({
      message: 'تم إنشاء الغرفة بنجاح',
      roomId
    });

  } catch (error) {
    console.error('Create room error:', error);
    res.status(500).json({ error: 'خطأ في إنشاء الغرفة' });
  }
});

// 8. إدارة الرسائل
app.get('/api/rooms/:roomId/messages', authenticateToken, async (req, res) => {
  try {
    const { roomId } = req.params;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    // التحقق من عضوية الغرفة
    const [memberships] = await pool.execute(
      'SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?',
      [roomId, req.user.id]
    );

    if (memberships.length === 0 && req.user.role !== 'developer' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'ليس لديك صلاحية الوصول لهذه الغرفة' });
    }

    const [messages] = await pool.execute(
      `SELECT m.*, u.username, u.avatar_url, u.role as user_role
       FROM messages m
       LEFT JOIN users u ON m.user_id = u.id
       WHERE m.room_id = ? AND m.deleted_at IS NULL
       ORDER BY m.created_at DESC
       LIMIT ? OFFSET ?`,
      [roomId, limit, offset]
    );

    res.json({ messages: messages.reverse() });

  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'خطأ في جلب الرسائل' });
  }
});

// 9. WebSocket Handling
const connectedUsers = new Map();

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.query.token;
    
    if (!token) {
      return next(new Error('التوكن مطلوب'));
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const [users] = await pool.execute(
      'SELECT id, username, email, role, avatar_url FROM users WHERE id = ?',
      [decoded.userId]
    );

    if (users.length === 0) {
      return next(new Error('المستخدم غير موجود'));
    }

    socket.user = users[0];
    socket.userId = socket.user.id;
    next();
  } catch (error) {
    return next(new Error('مصادقة غير صالحة'));
  }
});

io.on('connection', (socket) => {
  console.log(`👤 مستخدم متصل: ${socket.user.username} (${socket.userId})`);
  
  // تخزين معلومات الاتصال
  connectedUsers.set(socket.userId, {
    socketId: socket.id,
    user: socket.user,
    rooms: new Set()
  });

  // إرسال تأكيد الاتصال
  socket.emit('auth_success', {
    user: socket.user
  });

  // 1. الانضمام للغرفة
  socket.on('join_room', async ({ roomId }) => {
    try {
      // التحقق من عضوية الغرفة
      const [membership] = await pool.execute(
        'SELECT * FROM room_members WHERE room_id = ? AND user_id = ?',
        [roomId, socket.userId]
      );

      if (membership.length === 0 && socket.user.role !== 'developer' && socket.user.role !== 'admin') {
        socket.emit('error', { error: 'ليس لديك صلاحية الانضمام لهذه الغرفة' });
        return;
      }

      // الانضمام لغرفة Socket.io
      socket.join(roomId);
      
      const userInfo = connectedUsers.get(socket.userId);
      userInfo.rooms.add(roomId);

      // إعلام الآخرين بانضمام المستخدم
      socket.to(roomId).emit('user_joined', {
        user: socket.user,
        roomId
      });

      // إرسال تأكيد الانضمام
      socket.emit('join_success', {
        roomId,
        user: socket.user
      });

      console.log(`🚪 ${socket.user.username} انضم للغرفة ${roomId}`);

    } catch (error) {
      console.error('Join room error:', error);
      socket.emit('error', { error: 'خطأ في الانضمام للغرفة' });
    }
  });

  // 2. إرسال رسالة
  socket.on('new_message', async ({ roomId, text, type = 'text', metadata = {} }) => {
    try {
      // التحقق من إقفال الدردشة
      const [room] = await pool.execute(
        'SELECT chat_locked FROM rooms WHERE id = ?',
        [roomId]
      );

      if (room.length > 0 && room[0].chat_locked && 
          socket.user.role !== 'owner' && 
          socket.user.role !== 'developer' && 
          socket.user.role !== 'admin') {
        socket.emit('error', { error: 'الدردشة مقفلة' });
        return;
      }

      // التحقق من الكتم
      const [muteStatus] = await pool.execute(
        'SELECT muted_until FROM room_members WHERE room_id = ? AND user_id = ?',
        [roomId, socket.userId]
      );

      if (muteStatus.length > 0 && muteStatus[0].muted_until && 
          new Date(muteStatus[0].muted_until) > new Date()) {
        socket.emit('error', { error: 'أنت مكتوم حالياً' });
        return;
      }

      // حفظ الرسالة
      const messageId = generateId();
      await pool.execute(
        `INSERT INTO messages (id, room_id, user_id, text, type, metadata, created_at)
         VALUES (?, ?, ?, ?, ?, ?, NOW())`,
        [messageId, roomId, socket.userId, text, type, JSON.stringify(metadata)]
      );

      // جلب الرسالة مع معلومات المستخدم
      const [messages] = await pool.execute(
        `SELECT m.*, u.username, u.avatar_url, u.role as user_role
         FROM messages m
         LEFT JOIN users u ON m.user_id = u.id
         WHERE m.id = ?`,
        [messageId]
      );

      const message = messages[0];

      // بث الرسالة للغرفة
      io.to(roomId).emit('new_message', {
        ...message,
        room: roomId
      });

      // التحقق من حد الحذف التلقائي
      await checkAutoDelete(roomId);

      console.log(`📨 ${socket.user.username} أرسل رسالة في ${roomId}`);

    } catch (error) {
      console.error('Send message error:', error);
      socket.emit('error', { error: 'خطأ في إرسال الرسالة' });
    }
  });

  // 3. تعديل رسالة
  socket.on('edit_message', async ({ messageId, text }) => {
    try {
      // التحقق من ملكية الرسالة
      const [messages] = await pool.execute(
        'SELECT user_id, room_id FROM messages WHERE id = ? AND deleted_at IS NULL',
        [messageId]
      );

      if (messages.length === 0) {
        socket.emit('error', { error: 'الرسالة غير موجودة' });
        return;
      }

      const message = messages[0];
      
      // التحقق من الصلاحيات
      if (message.user_id !== socket.userId && 
          socket.user.role !== 'owner' && 
          socket.user.role !== 'developer' && 
          socket.user.role !== 'admin') {
        socket.emit('error', { error: 'ليس لديك صلاحية تعديل هذه الرسالة' });
        return;
      }

      // تحديث الرسالة
      await pool.execute(
        'UPDATE messages SET text = ?, edited_at = NOW() WHERE id = ?',
        [text, messageId]
      );

      // بث التعديل
      io.to(message.room_id).emit('edit_message', {
        messageId,
        text,
        editedAt: new Date().toISOString()
      });

    } catch (error) {
      console.error('Edit message error:', error);
      socket.emit('error', { error: 'خطأ في تعديل الرسالة' });
    }
  });

  // 4. حذف رسالة
  socket.on('delete_message', async ({ messageId }) => {
    try {
      // التحقق من ملكية الرسالة
      const [messages] = await pool.execute(
        'SELECT user_id, room_id FROM messages WHERE id = ? AND deleted_at IS NULL',
        [messageId]
      );

      if (messages.length === 0) {
        socket.emit('error', { error: 'الرسالة غير موجودة' });
        return;
      }

      const message = messages[0];
      
      // التحقق من الصلاحيات
      if (message.user_id !== socket.userId && 
          socket.user.role !== 'owner' && 
          socket.user.role !== 'developer' && 
          socket.user.role !== 'admin') {
        socket.emit('error', { error: 'ليس لديك صلاحية حذف هذه الرسالة' });
        return;
      }

      // حذف الرسالة (soft delete)
      await pool.execute(
        'UPDATE messages SET deleted_at = NOW() WHERE id = ?',
        [messageId]
      );

      // بث الحذف
      io.to(message.room_id).emit('delete_message', {
        messageId,
        deletedAt: new Date().toISOString()
      });

    } catch (error) {
      console.error('Delete message error:', error);
      socket.emit('error', { error: 'خطأ في حذف الرسالة' });
    }
  });

  // 5. طلب الانضمام لمقعد صوتي
  socket.on('seat_join_request', async ({ roomId, seatNumber }) => {
    try {
      // التحقق من المقعد
      const [seat] = await pool.execute(
        'SELECT * FROM voice_seats WHERE room_id = ? AND seat_number = ?',
        [roomId, seatNumber]
      );

      if (seat.length > 0) {
        if (seat[0].is_locked) {
          socket.emit('error', { error: 'المقعد مقفل' });
          return;
        }
        
        if (seat[0].user_id) {
          socket.emit('error', { error: 'المقعد مشغول' });
          return;
        }
      }

      // التحقق من صلاحيات المستخدم
      const [room] = await pool.execute(
        'SELECT owner_id FROM rooms WHERE id = ?',
        [roomId]
      );

      if (room.length === 0) {
        socket.emit('error', { error: 'الغرفة غير موجودة' });
        return;
      }

      // إذا كان المقعد فارغاً، إنشاؤه
      if (seat.length === 0) {
        await pool.execute(
          `INSERT INTO voice_seats (id, room_id, seat_number, user_id, joined_at)
           VALUES (?, ?, ?, ?, NOW())`,
          [generateId(), roomId, seatNumber, socket.userId]
        );
      } else {
        // تحديث المقعد
        await pool.execute(
          'UPDATE voice_seats SET user_id = ?, joined_at = NOW() WHERE room_id = ? AND seat_number = ?',
          [socket.userId, roomId, seatNumber]
        );
      }

      // إرسال الموافقة للمستخدم
      socket.emit('seat_join_approved', {
        roomId,
        seatNumber,
        userId: socket.userId
      });

      // إرسال تحديث المقاعد للجميع
      const [seats] = await pool.execute(
        'SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_number',
        [roomId]
      );

      io.to(roomId).emit('seats_update', {
        roomId,
        seats
      });

    } catch (error) {
      console.error('Seat join error:', error);
      socket.emit('error', { error: 'خطأ في الانضمام للمقعد' });
    }
  });

  // 6. مغادرة المقعد الصوتي
  socket.on('seat_leave', async ({ roomId, seatNumber }) => {
    try {
      await pool.execute(
        'UPDATE voice_seats SET user_id = NULL, is_muted = FALSE WHERE room_id = ? AND seat_number = ? AND user_id = ?',
        [roomId, seatNumber, socket.userId]
      );

      // إرسال تحديث المقاعد
      const [seats] = await pool.execute(
        'SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_number',
        [roomId]
      );

      io.to(roomId).emit('seats_update', {
        roomId,
        seats
      });

    } catch (error) {
      console.error('Seat leave error:', error);
      socket.emit('error', { error: 'خطأ في مغادرة المقعد' });
    }
  });

  // 7. WebRTC Signaling
  socket.on('webrtc_offer', ({ targetUserId, offer, roomId }) => {
    const targetUser = connectedUsers.get(targetUserId);
    if (targetUser) {
      io.to(targetUser.socketId).emit('webrtc_offer', {
        fromUserId: socket.userId,
        offer,
        roomId
      });
    }
  });

  socket.on('webrtc_answer', ({ targetUserId, answer, roomId }) => {
    const targetUser = connectedUsers.get(targetUserId);
    if (targetUser) {
      io.to(targetUser.socketId).emit('webrtc_answer', {
        fromUserId: socket.userId,
        answer,
        roomId
      });
    }
  });

  socket.on('webrtc_ice_candidate', ({ targetUserId, candidate, roomId }) => {
    const targetUser = connectedUsers.get(targetUserId);
    if (targetUser) {
      io.to(targetUser.socketId).emit('webrtc_ice_candidate', {
        fromUserId: socket.userId,
        candidate,
        roomId
      });
    }
  });

  // 8. الكتابة (Typing Indicator)
  socket.on('typing_start', ({ roomId }) => {
    socket.to(roomId).emit('typing_start', {
      userId: socket.userId,
      username: socket.user.username,
      roomId
    });
  });

  socket.on('typing_end', ({ roomId }) => {
    socket.to(roomId).emit('typing_end', {
      userId: socket.userId,
      roomId
    });
  });

  // 9. قطع الاتصال
  socket.on('disconnect', () => {
    console.log(`👋 مستخدم انقطع: ${socket.user?.username || 'Unknown'} (${socket.userId})`);
    
    // إعلام الغرف بمغادرة المستخدم
    const userInfo = connectedUsers.get(socket.userId);
    if (userInfo) {
      userInfo.rooms.forEach(roomId => {
        socket.to(roomId).emit('user_left', {
          userId: socket.userId,
          username: socket.user?.username,
          roomId
        });

        // تحديث المقاعد الصوتية
        pool.execute(
          'UPDATE voice_seats SET user_id = NULL WHERE user_id = ?',
          [socket.userId]
        ).then(() => {
          // إرسال تحديث المقاعد
          pool.execute(
            'SELECT * FROM voice_seats WHERE room_id = ? ORDER BY seat_number',
            [roomId]
          ).then(([seats]) => {
            io.to(roomId).emit('seats_update', {
              roomId,
              seats
            });
          });
        });
      });
    }

    connectedUsers.delete(socket.userId);
  });
});

// ========== وظيفة الحذف التلقائي ==========
async function checkAutoDelete(roomId) {
  try {
    const [room] = await pool.execute(
      'SELECT auto_delete_limit FROM rooms WHERE id = ?',
      [roomId]
    );

    if (room.length === 0 || !room[0].auto_delete_limit) {
      return;
    }

    const autoDeleteLimit = room[0].auto_delete_limit;
    
    // حساب عدد الرسائل
    const [countResult] = await pool.execute(
      'SELECT COUNT(*) as count FROM messages WHERE room_id = ? AND deleted_at IS NULL',
      [roomId]
    );

    const messageCount = countResult[0].count;

    if (messageCount > autoDeleteLimit) {
      const messagesToDelete = messageCount - autoDeleteLimit;
      
      // حذف أقدم الرسائل
      const [oldMessages] = await pool.execute(
        `SELECT id FROM messages 
         WHERE room_id = ? AND deleted_at IS NULL 
         ORDER BY created_at ASC 
         LIMIT ?`,
        [roomId, messagesToDelete]
      );

      for (const msg of oldMessages) {
        await pool.execute(
          'UPDATE messages SET deleted_at = NOW() WHERE id = ?',
          [msg.id]
        );
      }

      // إرسال إشعار الحذف
      io.to(roomId).emit('auto_delete_notification', {
        deletedCount: messagesToDelete,
        message: 'تم حذف الرسائل لتوفير مساحة للدردشة'
      });

      console.log(`🗑️ حُذفت ${messagesToDelete} رسالة تلقائياً من الغرفة ${roomId}`);
    }

  } catch (error) {
    console.error('Auto delete error:', error);
  }
}

// ========== بدء السيرفر ==========
async function startServer() {
  try {
    // تهيئة قاعدة البيانات
    await initializeDatabase();
    
    // تشغيل السيرفر
    server.listen(PORT, () => {
      console.log(`🚀 السيرفر يعمل على المنفذ ${PORT}`);
      console.log(`🔗 رابط السيرفر: http://localhost:${PORT}`);
      console.log(`📊 قاعدة البيانات: ${DB_CONFIG.host}:${DB_CONFIG.port}/${DB_CONFIG.database}`);
      console.log(`🔐 JWT Secret: ${JWT_SECRET ? 'مضبوط' : 'غير مضبوط - تستخدم القيمة الافتراضية'}`);
    });

    // معالجة إغلاق التطبيق
    process.on('SIGTERM', async () => {
      console.log('🛑 إغلاق السيرفر...');
      if (pool) {
        await pool.end();
      }
      server.close(() => {
        console.log('✅ تم إغلاق السيرفر بنجاح');
        process.exit(0);
      });
    });

  } catch (error) {
    console.error('❌ فشل بدء السيرفر:', error);
    process.exit(1);
  }
}

// تشغيل السيرفر
startServer();
