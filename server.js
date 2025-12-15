const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// تخزين المستخدمين حسب الغرف
const rooms = new Map();

wss.on('connection', (ws, req) => {
  const url = req.url;
  const roomMatch = url.match(/\/ws\/(.+)/);
  const roomId = roomMatch ? roomMatch[1] : 'global';
  
  console.log(`📡 مستخدم جديد في غرفة: ${roomId}`);
  
  // تأكد من وجود الغرفة
  if (!rooms.has(roomId)) {
    rooms.set(roomId, new Set());
  }
  
  const room = rooms.get(roomId);
  room.add(ws);
  
  // إرسال رسالة ترحيب
  ws.send(JSON.stringify({
    type: 'welcome',
    message: 'مرحباً في الدردشة!',
    room: roomId,
    timestamp: new Date().toISOString()
  }));
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      console.log('📩 رسالة واردة:', data);
      
      // إضافة معلومات إضافية
      const broadcastData = {
        type: 'new-message',
        ...data,
        timestamp: new Date().toISOString(),
        room: roomId
      };
      
      // بث الرسالة لجميع المستخدمين في نفس الغرفة (بما فيهم المرسل)
      room.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          console.log('📤 إرسال للعميل:', client === ws ? '(المرسل نفسه)' : 'عميل آخر');
          client.send(JSON.stringify(broadcastData));
        }
      });
      
      // أيضًا إرسال للمستخدمين الآخرين في نفس الخادم
      wss.clients.forEach((client) => {
        if (client !== ws && client.readyState === WebSocket.OPEN) {
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
    console.log(`👋 مستخدم غادر غرفة: ${roomId}`);
    if (room) {
      room.delete(ws);
      if (room.size === 0) {
        rooms.delete(roomId);
      }
    }
  });
  
  ws.on('error', (error) => {
    console.error('💥 خطأ WebSocket:', error);
  });
});

// نقطة نهاية للتحقق
app.get('/', (req, res) => {
  res.json({
    status: 'running',
    message: 'ProfileHub WebSocket Server',
    timestamp: new Date().toISOString(),
    rooms: Array.from(rooms.keys())
  });
});

// نقطة لفحص حالة الغرف
app.get('/status', (req, res) => {
  const roomStats = {};
  rooms.forEach((clients, roomId) => {
    roomStats[roomId] = clients.size;
  });
  
  res.json({
    status: 'active',
    totalRooms: rooms.size,
    rooms: roomStats,
    totalConnections: Array.from(rooms.values()).reduce((sum, set) => sum + set.size, 0)
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 خادم WebSocket يعمل على المنفذ ${PORT}`);
  console.log(`🌐 عنوان WebSocket: ws://localhost:${PORT}/ws/{roomId}`);
});
