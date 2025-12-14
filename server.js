const express = require('express');
const cors = require('cors');
const app = express();

// السماح لجميع المواقع بالاتصال
app.use(cors());
app.use(express.json());

// صفحة ترحيبية
app.get('/', (req, res) => {
  res.send(`
    <h1>🚀 خادم ProfileHub يعمل!</h1>
    <p>الوقت: ${new Date().toLocaleString()}</p>
    <p>جرب إرسال POST إلى <code>/api/send</code></p>
  `);
});

// نقطة API لاختبار الدردشة
app.post('/api/send', (req, res) => {
  const { message, user } = req.body;
  
  console.log(`📨 رسالة من ${user}: ${message}`);
  
  res.json({
    success: true,
    received: { user, message },
    timestamp: new Date().toISOString(),
    server: 'ProfileHub على Render'
  });
});

// نقطة للتحقق من صحة الخادم
app.get('/health', (req, res) => {
  res.json({ 
    status: 'تعمل ✅', 
    time: new Date().toISOString() 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ الخادم يعمل على المنفذ ${PORT}`);
});