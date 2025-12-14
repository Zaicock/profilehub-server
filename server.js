const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.send(`<h1>خادم ProfileHub على Railway 🚂</h1><p>${new Date()}</p>`);
});

app.post('/api/send', (req, res) => {
  console.log('📨 رسالة:', req.body);
  res.json({ success: true, server: 'railway', time: new Date() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ يعمل على ${PORT}`));
