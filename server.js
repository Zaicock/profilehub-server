const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

const rooms = new Map();
const users = new Map();

wss.on('connection', (ws, req) => {
  const url = req.url;
  let roomId = 'global';
  
  if (url.includes('/ws/')) {
    roomId = url.split('/ws/')[1] || 'global';
  }
  
  console.log(`📡 مستخدم جديد متصل: ${roomId}`);
  
  if (!rooms.has(roomId)) {
    rooms.set(roomId, new Set());
  }
  
  const room = rooms.get(roomId);
  room.add(ws);
  
  const userId = Date.now() + '-' + Math.random().toString(36).substr(2, 9);
  users.set(ws, { id: userId, roomId });
  
  ws.send(JSON.stringify({
    type: 'welcome',
    message: 'مرحباً في الدردشة!',
    room: roomId,
    timestamp: new Date().toISOString()
  }));
  
  const joinMessage = {
    type: 'user-joined',
    userId: userId,
    username: 'مستخدم جديد',
    room: roomId,
    timestamp: new Date().toISOString()
  };
  
  room.forEach(client => {
    if (client !== ws && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(joinMessage));
    }
  });
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      console.log('📩 رسالة واردة:', data);
      
      const userInfo = users.get(ws);
      const broadcastData = {
        type: 'new-message',
        userId: data.userId || userInfo?.id || 'unknown',
        username: data.username || 'مستخدم',
        avatar: data.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(data.username || 'مستخدم')}&background=007AFF&color=fff`,
        text: data.text,
        room: data.room || roomId,
        timestamp: data.timestamp || new Date().toISOString()
      };
      
      room.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify(broadcastData));
        }
      });
      
    } catch (error) {
      console.error('❌ خطأ في معالجة الرسالة:', error);
      ws.send(JSON.stringify({
        type: 'error',
        message: 'خطأ في معالجة الرسالة'
      }));
    }
  });
  
  ws.on('close', () => {
    console.log(`👋 مستخدم غادر: ${roomId}`);
    
    const userInfo = users.get(ws);
    if (userInfo) {
      const leaveMessage = {
        type: 'user-left',
        userId: userInfo.id,
        username: 'مستخدم',
        room: userInfo.roomId,
        timestamp: new Date().toISOString()
      };
      
      const userRoom = rooms.get(userInfo.roomId);
      if (userRoom) {
        userRoom.forEach(client => {
          if (client !== ws && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(leaveMessage));
          }
        });
        
        userRoom.delete(ws);
        if (userRoom.size === 0) {
          rooms.delete(userInfo.roomId);
        }
      }
      
      users.delete(ws);
    }
  });
  
  ws.on('error', (error) => {
    console.error('💥 خطأ WebSocket:', error);
  });
});

app.get('/', (req, res) => {
  const roomStats = {};
  rooms.forEach((clients, roomId) => {
    roomStats[roomId] = clients.size;
  });
  
  res.json({
    status: 'running',
    message: 'ProfileHub WebSocket Server',
    timestamp: new Date().toISOString(),
    totalRooms: rooms.size,
    totalConnections: Array.from(rooms.values()).reduce((sum, set) => sum + set.size, 0),
    rooms: roomStats
  });
});

app.get('/status', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 خادم ProfileHub يعمل على المنفذ ${PORT}`);
  console.log(`🌐 WebSocket: ws://localhost:${PORT}/ws/{roomId}`);
});
