const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// تخزين المستخدمين المتصلين
const connectedUsers = new Map();

wss.on('connection', (ws, req) => {
  const roomId = req.url.split('/ws/')[1] || 'global';
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      // إعادة بث الرسالة لجميع المستخدمين في نفس الغرفة
      wss.clients.forEach((client) => {
        if (client !== ws && client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({
            type: 'new-message',
            ...data
          }));
        }
      });
    } catch (error) {
      console.error('Error processing message:', error);
    }
  });
});

// نقطة نهاية للتحقق من صحة الخادم
app.get('/', (req, res) => {
  res.send('ProfileHub WebSocket Server is running');
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
