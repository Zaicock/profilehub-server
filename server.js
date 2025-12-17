{
  "name": "profilehub-server",
  "version": "4.0.0",
  "description": "Complete chat application server compatible with ProfileHub frontend",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest"
  },
  "dependencies": {
    "express": "^4.18.2",
    "socket.io": "^4.5.4",
    "jsonwebtoken": "^9.0.0",
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  },
  "keywords": [
    "chat",
    "profile",
    "socket.io",
    "arabic",
    "realtime"
  ],
  "author": "ProfileHub Team",
  "license": "MIT"
}
