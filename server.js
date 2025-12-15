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

// مهم لـ Railway
app.set("trust proxy", true);

// ================== API ==================

// إنشاء حساب
app.post("/api/register", (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "بيانات ناقصة" });
  }

  const user = {
    id: "u_" + Date.now(),
    username,
    email,
    role: "user",
    avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=007AFF&color=fff`,
    createdAt: new Date().toISOString()
  };

  const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });

  res.json({ token, user });
});

// تسجيل دخول
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "بيانات ناقصة" });
  }

  // مؤقت – لاحقاً من DB
  const user = {
    id: "u_123456",
    username: "User",
    email,
    role: "user",
    avatar: `https://ui-avatars.com/api/?name=User&background=007AFF&color=fff`,
    createdAt: new Date().toISOString()
  };

  const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });

  res.json({ token, user });
});

// ================== HTTP Server ==================
const server = http.createServer(app);

// ================== WebSocket ==================
const wss = new WebSocket.Server({ server, path: "/ws" });

// تخزين مؤقت
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

  // ❌ لا اتصال بدون توكن
  if (!token) {
    ws.close();
    return;
  }

  let user;
  try {
    user = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    ws.close();
    return;
  }

  const room = getRoom(roomId);
  room.add(ws);
  users.set(ws, { ...user, roomId });

  console.log(`📡 WS CONNECT | ${user.username} | room=${roomId}`);

  // ترحيب
  ws.send(JSON.stringify({
    type: "welcome",
    room: roomId,
    user,
    timestamp: new Date().toISOString()
  }));

  // إشعار دخول
  broadcast(roomId, {
    type: "user-joined",
    user,
    timestamp: new Date().toISOString()
  });

  // استقبال الرسائل
  ws.on("message", raw => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }

    if (!data.text) return;

    const msg = {
      type: "new-message",
      user: {
        id: user.id,
        username: user.username,
        avatar: user.avatar
      },
     
