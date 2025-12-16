const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const cors = require("cors");
const jwt = require("jsonwebtoken");

// ================== إعدادات ==================
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const PORT = process.env.PORT || 3000;
const MAX_SEATS = 6;

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

// ================== HTTP Server ==================
const server = http.createServer(app);

// ================== WebSocket ==================
const wss = new WebSocket.Server({ server, path: "/ws" });

// ================== التخزين ==================
const rooms = new Map(); // roomId => { clients:Set, seats:Array, seatMap:Map }
const users = new Map(); // ws => user

function getRoom(roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, {
      clients: new Set(),
      seats: Array(MAX_SEATS).fill(null),
      seatMap: new Map() // ws => seatIndex
    });
  }
  return rooms.get(roomId);
}

function broadcast(roomId, data) {
  const room = rooms.get(roomId);
  if (!room) return;

  const payload = JSON.stringify(data);
  room.clients.forEach(client => {
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

  if (!token) return ws.close();

  let user;
  try {
    user = jwt.verify(token, JWT_SECRET);
  } catch {
    return ws.close();
  }

  const room = getRoom(roomId);
  room.clients.add(ws);
  users.set(ws, user);

  // ===== حجز مقعد =====
  const seatIndex = room.seats.findIndex(s => s === null);
  if (seatIndex !== -1) {
    room.seats[seatIndex] = user.id;
    room.seatMap.set(ws, seatIndex);

    ws.send(
      JSON.stringify({
        type: "seat-assigned",
        seat: seatIndex,
        seats: room.seats
      })
    );
  } else {
    ws.send(JSON.stringify({ type: "room-full" }));
  }

  broadcast(roomId, {
    type: "seats-update",
    seats: room.seats
  });

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

    const updatedUser = registeredUsers.get(user.id);
    if (updatedUser) {
      user.username = updatedUser.username;
      user.avatar = updatedUser.avatar;
    }

    broadcast(roomId, {
      type: "new-message",
      user: {
        id: user.id,
        username: user.username,
        avatar: user.avatar
      },
      text: data.text,
      room: roomId,
      timestamp: new Date().toISOString()
    });
  });

  ws.on("close", () => {
    room.clients.delete(ws);
    users.delete(ws);

    const seat = room.seatMap.get(ws);
    if (seat !== undefined) {
      room.seats[seat] = null;
      room.seatMap.delete(ws);
    }

    broadcast(roomId, {
      type: "seats-update",
      seats: room.seats
    });

    broadcast(roomId, {
      type: "user-left",
      userId: user.id,
      timestamp: new Date().toISOString()
    });

    if (room.clients.size === 0) {
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
  rooms.forEach((room, roomId) => {
    stats[roomId] = {
      users: room.clients.size,
      seats: room.seats
    };
  });

  res.json({
    status: "running",
    rooms: stats,
    totalRooms: rooms.size,
    timestamp: new Date().toISOString()
  });
});

// ================== تشغيل ==================
server.listen(PORT, () => {
  console.log(`🚀 ProfileHub Server running on ${PORT}`);
  console.log(`🔌 WS: /ws?room=global&token=JWT`);
});
