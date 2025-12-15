const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const cors = require("cors");
const jwt = require("jsonwebtoken");

// ================== إعدادات ==================
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const PORT = process.env.PORT || 3000;

// ================== App ==================
const app = express();
app.use(cors());
app.use(express.json());
app.set("trust proxy", true);

// ================== تخزين مؤقت ==================
const registeredUsers = new Map(); // userId => user

// ================== API ==================

// إنشاء حساب
app.post("/api/register", (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "بيانات ناقصة" });
  }

  // تحقق من الاسم
  for (const u of registeredUsers.values()) {
    if (u.username === username) {
      return res.status(409).json({ error: "اسم المستخدم مستخدم بالفعل" });
    }
  }

  const user = {
    id: "u_" + Date.now(),
    username,
    email,
    role: "user",
    avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(
      username
    )}&background=007AFF&color=fff`,
    createdAt: new Date().toISOString()
  };

  registeredUsers.set(user.id, user);

  const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user });
});

// تسجيل دخول
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "بيانات ناقصة" });
  }

  // مؤقت (لاحقاً DB)
  let user = Array.from(registeredUsers.values()).find(u => u.email === email);

  if (!user) {
    user = {
      id: "u_" + Date.now(),
      username: "User",
      email,
      role: "user",
      avatar: `https://ui-avatars.com/api/?name=User&background=007AFF&color=fff`,
      createdAt: new Date().toISOString()
    };
    registeredUsers.set(user.id, user);
  }

  const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user });
});

// ================== Middleware ==================
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "غير مصرح" });

  const token = auth.split(" ")[1];
  if (!token) return res.status(401).json({ error: "توكن مفقود" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "توكن غير صالح" });
  }
}

// ================== تحديث البروفايل ==================
app.post("/api/profile/update", authMiddleware, (req, res) => {
  const { username, avatar } = req.body;
  const userId = req.user.id;

  const currentUser = registeredUsers.get(userId);
  if (!currentUser) {
    return res.status(404).json({ error: "المستخدم غير موجود" });
  }

  // تحقق من الاسم
  if (username) {
    for (const u of registeredUsers.values()) {
      if (u.username === username && u.id !== userId) {
        return res.status(409).json({
          error: "اسم المستخدم مستخدم بالفعل"
        });
      }
    }
  }

  if (username) currentUser.username = username;
  if (avatar) currentUser.avatar = avatar;

  registeredUsers.set(userId, currentUser);

  // بث التحديث
  rooms.forEach((_, roomId) => {
    broadcast(roomId, {
      type: "profile-updated",
      user: {
        id: currentUser.id,
        username: currentUser.username,
        avatar: currentUser.avatar
      },
      timestamp: new Date().toISOString()
    });
  });

  res.json({
    success: true,
    user: currentUser
  });
});

// ================== HTTP Server ==================
const server = http.createServer(app);

// ================== WebSocket ==================
const wss = new WebSocket.Server({ server, path: "/ws" });

// ===== تخزين =====
const rooms = new Map(); // roomId => Set<ws>
const users = new Map(); // ws => user

function getRoom(roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, new Set());
  }
  return rooms.get(roomId);
}

function broadcast(roomId, data) {
  const room = rooms.get(roomId);
  if (!room) return;

  const payload = JSON.stringify(data);
  room.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  });
}

// ================== WS Connection ==================
wss.on("connection", (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const roomId = url.searchParams.get("room") || "global";
  const token = url.searchParams.get("token");

  if (!token) {
    ws.close();
    return;
  }

  let user;
  try {
    user = jwt.verify(token, JWT_SECRET);
  } catch {
    ws.close();
    return;
  }

  const room = getRoom(roomId);
  room.add(ws);
  users.set(ws, user);

  console.log(`📡 CONNECT | ${user.username} | room=${roomId}`);

  ws.send(
    JSON.stringify({
      type: "welcome",
      room: roomId,
      user,
      timestamp: new Date().toISOString()
    })
  );

  broadcast(roomId, {
    type: "user-joined",
    user,
    timestamp: new Date().toISOString()
  });

  ws.on("message", raw => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }

    if (!data.text) return;

    // تحديث البيانات من التخزين
    const updatedUser = registeredUsers.get(user.id);
    if (updatedUser) {
      user.username = updatedUser.username;
      user.avatar = updatedUser.avatar;
    }

    const message = {
      type: "new-message",
      user: {
        id: user.id,
        username: user.username,
        avatar: user.avatar
      },
      text: data.text,
      room: roomId,
      timestamp: new Date().toISOString()
    };

    console.log(`💬 ${user.username}: ${data.text}`);
    broadcast(roomId, message);
  });

  ws.on("close", () => {
    room.delete(ws);
    users.delete(ws);

    console.log(`👋 LEAVE | ${user.username}`);

    broadcast(roomId, {
      type: "user-left",
      userId: user.id,
      room: roomId,
      timestamp: new Date().toISOString()
    });

    if (room.size === 0) {
      rooms.delete(roomId);
    }
  });

  ws.on("error", err => {
    console.error("💥 WS ERROR:", err);
  });
});

// ================== Status ==================
app.get("/", (req, res) => {
  const stats = {};
  rooms.forEach((set, roomId) => {
    stats[roomId] = set.size;
  });

  res.json({
    status: "running",
    rooms: stats,
    totalRooms: rooms.size,
    totalUsers: Array.from(rooms.values()).reduce((a, b) => a + b.size, 0),
    timestamp: new Date().toISOString()
  });
});

app.get("/status", (req, res) => {
  res.json({
    status: "online",
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// ================== تشغيل ==================
server.listen(PORT, () => {
  console.log(`🚀 ProfileHub Server running on ${PORT}`);
  console.log(`🔌 WS: /ws?room=global&token=JWT`);
});
