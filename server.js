const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// مهم لـ Railway
app.set('trust proxy', true);

const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

// ===== تخزين مؤقت =====
const rooms = new Map(); // roomId => Set<ws>
const users = new Map(); // ws => userInfo

// ===== أدوات =====
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

function createUser(ws, roomId, payload = {}) {
  return {
    id: payload.userId || `u_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    username: payload.username || 'مستخدم',
    avatar:
      payload.avatar ||
      `https://ui-avatars.com/api/?name=${encodeURIComponent(payload.username || 'User')}&background=007AFF&color=fff`,
    roomId
  };
}

// ===== WebSocket =====
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const roomId = url.searchParams.get('room') || 'global';

  const room = getRoom(roomId);
  room.add(ws);

  const user = createUser(ws, roomId);
  users.set(ws, user);

  console.log(`📡 اتصال جديد | room=${roomId} | user=${user.id}`);

  // ترحيب
  ws.send(JSON.stringify({
    type: 'welcome',
    room: roomId,
    user,
    timestamp: new Date().toISOString()
  }));

  // إشعار دخول
  broadcast(roomId, {
    type: 'user-joined',
    user,
    timestamp: new Date().toISOString()
  });

  // استقبال الرسائل
  ws.on('message', raw => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return ws.send(JSON.stringify({
        type: 'error',
        message: 'صيغة الرسالة غير صحيحة'
      }));
    }

    if (!data.text) return;

    const msg = {
      type: 'new-message',
      user: {
        id: user.id,
        username: data.username || user.username,
        avatar: data.avatar || user.avatar
      },
      text: data.text,
      room: roomId,
      timestamp: new Date().toISOString()
    };

    console.log('📩 رسالة:', msg.text);

    broadcast(roomId, msg);

    // ⬅️ هنا لاحقاً نضيف منطق البوت كنظام
  });

  ws.on('close', () => {
    console.log(`👋 غادر المستخدم | ${user.id}`);

    room.delete(ws);
    users.delete(ws);

    broadcast(roomId, {
      type: 'user-left',
      userId: user.id,
      room: roomId,
      timestamp: new Date().toISOString()
    });

    if (room.size === 0) {
      rooms.delete(roomId);
    }
  });

  ws.on('error', err => {
    console.error('💥 WebSocket Error:', err);
  });
});

// ===== HTTP =====
app.get('/', (req, res) => {
  const stats = {};
  rooms.forEach((set, roomId) => {
    stats[roomId] = set.size;
  });

  res.json({
    status: 'running',
    rooms: stats,
    totalRooms: rooms.size,
    totalUsers: Array.from(rooms.values()).reduce((a, b) => a + b.size, 0),
    timestamp: new Date().toISOString()
  });
});

app.get('/status', (req, res) => {
  res.json({
    status: 'online',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// ===== تشغيل =====
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 ProfileHub Server on ${PORT}`);
  console.log(`🔌 WS: /ws?room=global`);
});
