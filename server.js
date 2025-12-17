/**
 * ProfileHub Server - Complete v3.0
 * Full-featured chat application with profiles, frames, voice rooms, moderation, bots, and more
 */

require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

// ================== CONFIGURATION ==================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const SALT_ROUNDS = 12;

// ================== MIDDLEWARE ==================
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

// ================== IN-MEMORY DATABASE (Replace with real DB for production) ==================
let users = [];
let rooms = [];
let frames = [];
let userFrames = [];
let messages = [];
let voiceSeats = [];
let roomMembers = [];
let bots = [];
let botCommands = [];
let pointTransactions = [];
let subscriptions = [];
let userSubscriptions = [];
let paymentMethods = [];
let notifications = [];

// ================== INITIALIZE DEFAULT DATA ==================
function initializeDefaultData() {
    console.log('🚀 Initializing default data...');

    // Create default admin user
    const adminPasswordHash = bcrypt.hashSync('admin123', SALT_ROUNDS);
    if (!users.find(u => u.username === 'admin')) {
        const adminUser = {
            id: 1,
            username: 'admin',
            email: 'admin@profilehub.com',
            password_hash: adminPasswordHash,
            avatar_url: 'https://ui-avatars.com/api/?name=Admin&background=007AFF&color=fff&size=150',
            bio: 'مدير النظام والمطور الرئيسي',
            points: 10000,
            verified: true,
            is_developer: true,
            banned: false,
            frame_id: 1,
            referral_code: crypto.randomBytes(8).toString('hex').toUpperCase(),
            settings_json: JSON.stringify({
                theme: 'auto',
                language: 'ar',
                notifications: true,
                sound: true,
                privacy: 'public'
            }),
            created_at: new Date().toISOString(),
            last_seen: new Date().toISOString()
        };
        users.push(adminUser);
        console.log('✅ Created admin user');
    }

    // Create default frames
    if (frames.length === 0) {
        frames = [
            {
                id: 1,
                name: 'إطار أساسي',
                description: 'إطار مجاني بسيط',
                css_class: 'frame-basic',
                image_url: '',
                price_points: 0,
                category: 'basic',
                available: true,
                created_by: 1,
                created_at: new Date().toISOString()
            },
            {
                id: 2,
                name: 'إطار ذهبي',
                description: 'إطار مميز ذهبي اللون',
                css_class: 'frame-gold',
                image_url: 'https://via.placeholder.com/150/FFD700/000000?text=Gold+Frame',
                price_points: 500,
                category: 'premium',
                available: true,
                created_by: 1,
                created_at: new Date().toISOString()
            },
            {
                id: 3,
                name: 'إطار ألماس',
                description: 'إطار فاخر بتأثيرات متلألئة',
                css_class: 'frame-diamond',
                image_url: 'https://via.placeholder.com/150/B9F2FF/000000?text=Diamond+Frame',
                price_points: 2000,
                category: 'premium',
                available: true,
                created_by: 1,
                created_at: new Date().toISOString()
            },
            {
                id: 4,
                name: 'إطار VIP',
                description: 'إطار خاص لأعضاء VIP',
                css_class: 'frame-vip',
                image_url: 'https://via.placeholder.com/150/9B30FF/000000?text=VIP+Frame',
                price_points: 5000,
                category: 'vip',
                available: true,
                created_by: 1,
                created_at: new Date().toISOString()
            },
            {
                id: 5,
                name: 'إطار مطور',
                description: 'إطار خاص للمطورين',
                css_class: 'frame-developer',
                image_url: 'https://via.placeholder.com/150/007AFF/000000?text=Developer+Frame',
                price_points: 0,
                category: 'developer',
                available: false,
                created_by: 1,
                created_at: new Date().toISOString()
            }
        ];
        console.log('✅ Created 5 frames');
    }

    // Give admin all frames
    frames.forEach(frame => {
        if (!userFrames.find(uf => uf.user_id === 1 && uf.frame_id === frame.id)) {
            userFrames.push({
                id: userFrames.length + 1,
                user_id: 1,
                frame_id: frame.id,
                purchased_at: new Date().toISOString()
            });
        }
    });

    // Create default rooms
    if (rooms.length === 0) {
        rooms = [
            {
                id: 1,
                name: '👋 الترحيب والمناقشات العامة',
                description: 'غرفة الترحيب بالجدد والمناقشات العامة',
                type: 'text',
                icon: '💬',
                owner_id: 1,
                price_points: 0,
                max_members: 100,
                voice_seats: 8,
                settings_json: JSON.stringify({
                    auto_delete_limit: 0,
                    chat_locked: false,
                    voice_enabled: true,
                    slow_mode: false,
                    slow_mode_delay: 5,
                    allow_images: true,
                    allow_links: true,
                    allow_voice: true
                }),
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            },
            {
                id: 2,
                name: '🎤 غرفة الصوت العامة',
                description: 'غرفة صوتية للمحادثات الصوتية',
                type: 'voice',
                icon: '🎤',
                owner_id: 1,
                price_points: 0,
                max_members: 50,
                voice_seats: 12,
                settings_json: JSON.stringify({
                    auto_delete_limit: 100,
                    chat_locked: false,
                    voice_enabled: true,
                    allow_voice_guests: true,
                    max_speakers: 5,
                    noise_suppression: true,
                    echo_cancellation: true
                }),
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            },
            {
                id: 3,
                name: '👑 غرفة VIP الخاصة',
                description: 'غرفة خاصة لأعضاء VIP فقط',
                type: 'text',
                icon: '👑',
                owner_id: 1,
                price_points: 1000,
                max_members: 30,
                voice_seats: 6,
                settings_json: JSON.stringify({
                    auto_delete_limit: 0,
                    chat_locked: true,
                    voice_enabled: true,
                    require_invite: true,
                    hide_from_public: false
                }),
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            }
        ];
        console.log('✅ Created 3 rooms');
    }

    // Create voice seats for voice rooms
    rooms.forEach(room => {
        if (room.type === 'voice') {
            for (let i = 1; i <= room.voice_seats; i++) {
                if (!voiceSeats.find(vs => vs.room_id === room.id && vs.seat_index === i)) {
                    voiceSeats.push({
                        id: voiceSeats.length + 1,
                        room_id: room.id,
                        seat_index: i,
                        user_id: null,
                        is_locked: false,
                        is_muted: false,
                        updated_at: new Date().toISOString()
                    });
                }
            }
        }
    });

    // Add admin as owner of all rooms
    rooms.forEach(room => {
        if (!roomMembers.find(rm => rm.room_id === room.id && rm.user_id === 1)) {
            roomMembers.push({
                id: roomMembers.length + 1,
                room_id: room.id,
                user_id: 1,
                role: 'owner',
                joined_at: new Date().toISOString(),
                muted_until: null,
                is_banned: false,
                label_text: 'المالك',
                label_color: '#FF9500'
            });
        }
    });

    // Create welcome messages
    if (messages.length === 0) {
        const welcomeMessages = [
            {
                id: 1,
                room_id: 1,
                user_id: 1,
                username: 'admin',
                text: 'مرحباً بكم في ProfileHub! هذا مجتمع للدردشة والتعارف والمشاركة.',
                message_type: 'text',
                edited: false,
                deleted: false,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            },
            {
                id: 2,
                room_id: 1,
                user_id: 1,
                username: 'admin',
                text: 'يمكنك تخصيص بروفايلك، شراء إطارات، والدردشة مع الآخرين.',
                message_type: 'text',
                edited: false,
                deleted: false,
                created_at: new Date(Date.now() - 3600000).toISOString(),
                updated_at: new Date(Date.now() - 3600000).toISOString()
            },
            {
                id: 3,
                room_id: 1,
                user_id: 1,
                username: 'admin',
                text: 'جرب الغرف الصوتية للدردشة الصوتية المباشرة!',
                message_type: 'text',
                edited: false,
                deleted: false,
                created_at: new Date(Date.now() - 7200000).toISOString(),
                updated_at: new Date(Date.now() - 7200000).toISOString()
            }
        ];
        messages.push(...welcomeMessages);
    }

    // Create default subscription plans
    if (subscriptions.length === 0) {
        subscriptions = [
            {
                id: 1,
                plan_key: 'basic',
                name: 'الخطة الأساسية',
                description: 'مزايا أساسية مجانية',
                price_usd: 0.00,
                price_points: 0,
                duration_days: 9999,
                features_json: JSON.stringify([
                    'دردشة نصية',
                    'غرف عامة',
                    'بروفايل أساسي',
                    'إطار مجاني واحد'
                ]),
                is_active: true,
                created_at: new Date().toISOString()
            },
            {
                id: 2,
                plan_key: 'premium',
                name: 'الخطة المميزة',
                description: 'مزايا متقدمة',
                price_usd: 9.99,
                price_points: 10000,
                duration_days: 30,
                features_json: JSON.stringify([
                    'جميع مزايا الأساسية',
                    'غرف صوتية خاصة',
                    'إطارات مميزة',
                    'نقاط شهرية',
                    'أولوية الدعم',
                    'شارات خاصة'
                ]),
                is_active: true,
                created_at: new Date().toISOString()
            },
            {
                id: 3,
                plan_key: 'vip',
                name: 'خطة VIP',
                description: 'مزايا حصرية',
                price_usd: 29.99,
                price_points: 30000,
                duration_days: 30,
                features_json: JSON.stringify([
                    'جميع مزايا المميزة',
                    'غرف VIP خاصة',
                    'إطارات حصرية',
                    'نقاط شهرية مضاعفة',
                    'دعم فوري 24/7',
                    'شارات ذهبية'
                ]),
                is_active: true,
                created_at: new Date().toISOString()
            }
        ];
    }

    // Create payment methods
    if (paymentMethods.length === 0) {
        paymentMethods = [
            {
                id: 1,
                method_key: 'stripe',
                name: 'بطاقة ائتمان',
                description: 'دفع آمن عبر Stripe',
                is_active: true,
                config_json: JSON.stringify({
                    public_key: process.env.STRIPE_PUBLIC_KEY || '',
                    currency: 'usd'
                }),
                created_at: new Date().toISOString()
            },
            {
                id: 2,
                method_key: 'points',
                name: 'النقاط',
                description: 'استخدام النقاط المتوفرة',
                is_active: true,
                config_json: JSON.stringify({}),
                created_at: new Date().toISOString()
            },
            {
                id: 3,
                method_key: 'paypal',
                name: 'PayPal',
                description: 'دفع عبر PayPal',
                is_active: true,
                config_json: JSON.stringify({
                    client_id: process.env.PAYPAL_CLIENT_ID || '',
                    currency: 'USD'
                }),
                created_at: new Date().toISOString()
            }
        ];
    }

    console.log('✅ Default data initialization completed');
    console.log(`👥 Users: ${users.length}`);
    console.log(`💬 Rooms: ${rooms.length}`);
    console.log(`🖼️ Frames: ${frames.length}`);
    console.log(`💎 Subscriptions: ${subscriptions.length}`);
}

// ================== UTILITY FUNCTIONS ==================
function generateToken(user) {
    return jwt.sign(
        {
            id: user.id,
            username: user.username,
            email: user.email,
            is_developer: user.is_developer || false,
            verified: user.verified || false,
        },
        JWT_SECRET,
        { expiresIn: '30d' }
    );
}

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch {
        return null;
    }
}

function nowIso() {
    return new Date().toISOString();
}

function mustInt(n, def = 0) {
    const x = Number(n);
    return Number.isFinite(x) ? Math.trunc(x) : def;
}

function safeJsonParse(str) {
    try {
        return JSON.parse(str);
    } catch {
        return null;
    }
}

async function hashPassword(password) {
    return await bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

// ================== AUTHENTICATION MIDDLEWARE ==================
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ ok: false, error: 'NO_TOKEN' });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);
    
    if (!decoded) {
        return res.status(401).json({ ok: false, error: 'INVALID_TOKEN' });
    }
    
    const user = users.find(u => u.id === decoded.id);
    
    if (!user || user.banned) {
        return res.status(401).json({ ok: false, error: 'USER_NOT_FOUND_OR_BANNED' });
    }
    
    req.user = user;
    next();
}

// ================== PERMISSION FUNCTIONS ==================
function getRoomMember(roomId, userId) {
    return roomMembers.find(rm => rm.room_id === roomId && rm.user_id === userId);
}

function canModerateRoom(roomId, userId) {
    const member = getRoomMember(roomId, userId);
    if (!member) return false;
    
    const user = users.find(u => u.id === userId);
    if (user?.is_developer) return true;
    
    return member.role === 'owner' || member.role === 'admin';
}

function isRoomOwner(roomId, userId) {
    const member = getRoomMember(roomId, userId);
    if (!member) return false;
    return member.role === 'owner';
}

// ================== REST API ROUTES ==================

// ===== Health & Info =====
app.get('/', (req, res) => {
    res.json({
        ok: true,
        name: 'ProfileHub API',
        version: '3.0.0',
        timestamp: new Date().toISOString(),
        features: [
            'User Profiles',
            'Chat Rooms',
            'Voice Rooms',
            'Profile Frames',
            'Points System',
            'Moderation Tools',
            'Bots & Commands',
            'Subscriptions',
            'Payment Methods'
        ],
        endpoints: [
            'GET    /health',
            'POST   /api/register',
            'POST   /api/login',
            'GET    /api/profile',
            'PUT    /api/profile',
            'GET    /api/rooms',
            'POST   /api/rooms',
            'GET    /api/rooms/:id',
            'GET    /api/rooms/:id/messages',
            'GET    /api/frames',
            'POST   /api/frames/select',
            'POST   /api/points/grant',
            'POST   /api/points/deduct',
            'POST   /api/rooms/:id/mute',
            'POST   /api/rooms/:id/ban',
            'POST   /api/rooms/:id/chat-lock',
            'POST   /api/rooms/:id/autodelete',
            'GET    /api/rooms/:id/bots',
            'POST   /api/bots',
            'POST   /api/bots/:id/commands',
            'GET    /api/subscriptions',
            'GET    /api/payment-methods',
            'POST   /api/subscriptions/subscribe',
            'GET    /api/admin/users',
            'POST   /api/admin/users/:id/toggle-ban',
            'POST   /api/admin/users/:id/toggle-verify'
        ]
    });
});

app.get('/health', (req, res) => {
    res.json({
        ok: true,
        status: 'healthy',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        memory: process.memoryUsage()
    });
});

// ===== Authentication =====
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password, referral_code } = req.body;
        
        // Validation
        if (!username || !email || !password) {
            return res.status(400).json({ ok: false, error: 'MISSING_FIELDS' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ ok: false, error: 'PASSWORD_TOO_SHORT' });
        }
        
        if (username.length < 3) {
            return res.status(400).json({ ok: false, error: 'USERNAME_TOO_SHORT' });
        }
        
        // Check if user already exists
        const existingUser = users.find(u => u.email === email.toLowerCase() || u.username === username);
        if (existingUser) {
            return res.status(400).json({ ok: false, error: 'USER_ALREADY_EXISTS' });
        }
        
        // Hash password
        const passwordHash = await hashPassword(password);
        
        // Generate referral code
        const userReferralCode = crypto.randomBytes(6).toString('hex').toUpperCase();
        
        // Handle referral bonus
        let referredBy = null;
        let bonusPoints = 0;
        
        if (referral_code) {
            const referrer = users.find(u => u.referral_code === referral_code);
            if (referrer) {
                referredBy = referrer.id;
                bonusPoints = 1000;
                
                // Give points to referrer
                referrer.points += 500;
                
                // Record transaction
                pointTransactions.push({
                    id: pointTransactions.length + 1,
                    from_user_id: null,
                    to_user_id: referrer.id,
                    amount: 500,
                    reason: `إحالة: ${username}`,
                    created_at: nowIso()
                });
            }
        }
        
        // Create new user
        const newUser = {
            id: users.length + 1,
            username,
            email: email.toLowerCase(),
            password_hash: passwordHash,
            avatar_url: `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=007AFF&color=fff&size=150`,
            bio: `مرحباً بكم! أنا ${username} 👋`,
            points: 100 + bonusPoints,
            verified: false,
            is_developer: false,
            banned: false,
            frame_id: 1, // Default frame
            referral_code: userReferralCode,
            referred_by: referredBy,
            settings_json: JSON.stringify({
                theme: 'auto',
                language: 'ar',
                notifications: true,
                sound: true,
                privacy: 'public',
                show_online_status: true,
                allow_dms: true
            }),
            created_at: nowIso(),
            last_seen: nowIso()
        };
        
        users.push(newUser);
        
        // Give default frame
        const defaultFrame = frames.find(f => f.id === 1);
        if (defaultFrame) {
            userFrames.push({
                id: userFrames.length + 1,
                user_id: newUser.id,
                frame_id: defaultFrame.id,
                purchased_at: nowIso()
            });
        }
        
        // Record bonus points transaction if any
        if (bonusPoints > 0) {
            pointTransactions.push({
                id: pointTransactions.length + 1,
                from_user_id: null,
                to_user_id: newUser.id,
                amount: bonusPoints,
                reason: 'مكافأة التسجيل بكود دعوة',
                created_at: nowIso()
            });
        }
        
        // Create user response without password
        const userResponse = { ...newUser };
        delete userResponse.password_hash;
        
        // Generate token
        const token = generateToken(userResponse);
        
        res.json({
            ok: true,
            token,
            user: userResponse
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ ok: false, error: 'MISSING_FIELDS' });
        }
        
        // Find user by email or username
        const user = users.find(u => u.email === email.toLowerCase() || u.username === email);
        
        if (!user) {
            return res.status(401).json({ ok: false, error: 'INVALID_CREDENTIALS' });
        }
        
        if (user.banned) {
            return res.status(403).json({ ok: false, error: 'ACCOUNT_BANNED' });
        }
        
        // Verify password
        const validPassword = await verifyPassword(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ ok: false, error: 'INVALID_CREDENTIALS' });
        }
        
        // Update last seen
        user.last_seen = nowIso();
        
        // Create user response without password
        const userResponse = { ...user };
        delete userResponse.password_hash;
        
        // Generate token
        const token = generateToken(userResponse);
        
        res.json({
            ok: true,
            token,
            user: userResponse
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

// ===== Profile Routes =====
app.get('/api/profile', authMiddleware, (req, res) => {
    try {
        const userResponse = { ...req.user };
        delete userResponse.password_hash;
        
        // Get user frames
        const ownedFrames = userFrames
            .filter(uf => uf.user_id === req.user.id)
            .map(uf => frames.find(f => f.id === uf.frame_id))
            .filter(Boolean);
        
        // Get user subscription if any
        const userSubscription = userSubscriptions.find(us => 
            us.user_id === req.user.id && us.status === 'active'
        );
        
        res.json({
            ok: true,
            user: userResponse,
            owned_frames: ownedFrames,
            subscription: userSubscription || null
        });
        
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.put('/api/profile', authMiddleware, (req, res) => {
    try {
        const { avatar_url, bio, links_json, frame_id } = req.body;
        
        const userIndex = users.findIndex(u => u.id === req.user.id);
        if (userIndex === -1) {
            return res.status(404).json({ ok: false, error: 'USER_NOT_FOUND' });
        }
        
        // Update avatar
        if (avatar_url !== undefined) {
            users[userIndex].avatar_url = avatar_url;
        }
        
        // Update bio
        if (bio !== undefined) {
            users[userIndex].bio = bio;
        }
        
        // Update links
        if (links_json !== undefined) {
            users[userIndex].links_json = links_json;
        }
        
        // Update frame
        if (frame_id !== undefined) {
            // Check if user owns the frame
            const ownsFrame = userFrames.find(uf => 
                uf.user_id === req.user.id && uf.frame_id === frame_id
            );
            
            if (!ownsFrame && frame_id !== null) {
                return res.status(403).json({ ok: false, error: 'FRAME_NOT_OWNED' });
            }
            
            users[userIndex].frame_id = frame_id;
        }
        
        const updatedUser = { ...users[userIndex] };
        delete updatedUser.password_hash;
        
        res.json({
            ok: true,
            user: updatedUser
        });
        
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

// ===== Rooms Routes =====
app.get('/api/rooms', authMiddleware, (req, res) => {
    try {
        const roomsWithDetails = rooms.map(room => {
            const memberCount = roomMembers.filter(rm => rm.room_id === room.id && !rm.is_banned).length;
            const isMember = roomMembers.some(rm => rm.room_id === room.id && rm.user_id === req.user.id);
            const owner = users.find(u => u.id === room.owner_id);
            
            const settings = safeJsonParse(room.settings_json) || {};
            
            return {
                ...room,
                owner_name: owner?.username || 'Unknown',
                owner_avatar: owner?.avatar_url,
                members_count: memberCount,
                is_member: isMember,
                chat_locked: settings.chat_locked || false
            };
        });
        
        res.json({
            ok: true,
            rooms: roomsWithDetails
        });
        
    } catch (error) {
        console.error('Get rooms error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/rooms', authMiddleware, (req, res) => {
    try {
        const { name, description, type, icon, price_points, max_members, voice_seats } = req.body;
        
        if (!name) {
            return res.status(400).json({ ok: false, error: 'ROOM_NAME_REQUIRED' });
        }
        
        const newRoom = {
            id: rooms.length + 1,
            name,
            description: description || '',
            type: type || 'text',
            icon: icon || (type === 'voice' ? '🎤' : '💬'),
            owner_id: req.user.id,
            price_points: price_points || 0,
            max_members: max_members || 100,
            voice_seats: voice_seats || 8,
            settings_json: JSON.stringify({
                auto_delete_limit: 0,
                chat_locked: false,
                voice_enabled: true,
                allow_images: true,
                allow_links: true,
                require_invite: false,
                hide_from_public: false
            }),
            created_at: nowIso(),
            updated_at: nowIso()
        };
        
        rooms.push(newRoom);
        
        // Add creator as owner
        roomMembers.push({
            id: roomMembers.length + 1,
            room_id: newRoom.id,
            user_id: req.user.id,
            role: 'owner',
            joined_at: nowIso(),
            muted_until: null,
            is_banned: false,
            label_text: 'المالك',
            label_color: '#FF9500'
        });
        
        // Create voice seats if voice room
        if (newRoom.type === 'voice') {
            for (let i = 1; i <= newRoom.voice_seats; i++) {
                voiceSeats.push({
                    id: voiceSeats.length + 1,
                    room_id: newRoom.id,
                    seat_index: i,
                    user_id: null,
                    is_locked: false,
                    is_muted: false,
                    updated_at: nowIso()
                });
            }
        }
        
        // Create welcome message
        messages.push({
            id: messages.length + 1,
            room_id: newRoom.id,
            user_id: req.user.id,
            username: req.user.username,
            text: `تم إنشاء الغرفة بواسطة ${req.user.username}! مرحباً بكم جميعاً 👋`,
            message_type: 'system',
            metadata_json: JSON.stringify({}),
            edited: false,
            deleted: false,
            created_at: nowIso(),
            updated_at: nowIso()
        });
        
        res.json({
            ok: true,
            room: newRoom,
            room_id: newRoom.id
        });
        
    } catch (error) {
        console.error('Create room error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.get('/api/rooms/:id', authMiddleware, (req, res) => {
    try {
        const roomId = mustInt(req.params.id);
        const room = rooms.find(r => r.id === roomId);
        
        if (!room) {
            return res.status(404).json({ ok: false, error: 'ROOM_NOT_FOUND' });
        }
        
        // Get room members with user details
        const members = roomMembers
            .filter(rm => rm.room_id === roomId && !rm.is_banned)
            .map(rm => {
                const user = users.find(u => u.id === rm.user_id);
                return {
                    ...rm,
                    username: user?.username,
                    avatar_url: user?.avatar_url,
                    is_developer: user?.is_developer,
                    verified: user?.verified,
                    points: user?.points,
                    frame_id: user?.frame_id
                };
            });
        
        // Get voice seats if voice room
        let seats = [];
        if (room.type === 'voice') {
            seats = voiceSeats.filter(vs => vs.room_id === roomId);
        }
        
        // Check if user is member
        const isMember = members.some(m => m.user_id === req.user.id);
        
        res.json({
            ok: true,
            room,
            members,
            seats,
            is_member: isMember
        });
        
    } catch (error) {
        console.error('Get room error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.delete('/api/rooms/:id', authMiddleware, (req, res) => {
    try {
        const roomId = mustInt(req.params.id);
        const room = rooms.find(r => r.id === roomId);
        
        if (!room) {
            return res.status(404).json({ ok: false, error: 'ROOM_NOT_FOUND' });
        }
        
        // Check permissions
        const isOwner = room.owner_id === req.user.id;
        const isDeveloper = req.user.is_developer;
        
        if (!isOwner && !isDeveloper) {
            return res.status(403).json({ ok: false, error: 'PERMISSION_DENIED' });
        }
        
        // Delete room and related data
        rooms = rooms.filter(r => r.id !== roomId);
        roomMembers = roomMembers.filter(rm => rm.room_id !== roomId);
        messages = messages.filter(m => m.room_id !== roomId);
        voiceSeats = voiceSeats.filter(vs => vs.room_id !== roomId);
        
        res.json({
            ok: true,
            message: 'Room deleted successfully'
        });
        
    } catch (error) {
        console.error('Delete room error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

// ===== Messages Routes =====
app.get('/api/rooms/:id/messages', authMiddleware, (req, res) => {
    try {
        const roomId = mustInt(req.params.id);
        const limit = mustInt(req.query.limit, 50);
        const beforeId = mustInt(req.query.before_id, 0);
        
        // Check if user is room member
        const isMember = roomMembers.some(rm => 
            rm.room_id === roomId && rm.user_id === req.user.id && !rm.is_banned
        );
        
        if (!isMember) {
            return res.status(403).json({ ok: false, error: 'NOT_ROOM_MEMBER' });
        }
        
        // Get messages
        let roomMessages = messages
            .filter(m => m.room_id === roomId && !m.deleted)
            .sort((a, b) => b.id - a.id);
        
        // Apply pagination
        if (beforeId > 0) {
            roomMessages = roomMessages.filter(m => m.id < beforeId);
        }
        
        roomMessages = roomMessages.slice(0, limit);
        
        res.json({
            ok: true,
            messages: roomMessages.reverse()
        });
        
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.put('/api/messages/:id', authMiddleware, (req, res) => {
    try {
        const messageId = mustInt(req.params.id);
        const { text } = req.body;
        
        if (!text || text.trim().length === 0) {
            return res.status(400).json({ ok: false, error: 'EMPTY_MESSAGE' });
        }
        
        const message = messages.find(m => m.id === messageId && !m.deleted);
        
        if (!message) {
            return res.status(404).json({ ok: false, error: 'MESSAGE_NOT_FOUND' });
        }
        
        // Check permissions
        const isOwner = message.user_id === req.user.id;
        const canModerate = canModerateRoom(message.room_id, req.user.id);
        
        if (!isOwner && !canModerate) {
            return res.status(403).json({ ok: false, error: 'PERMISSION_DENIED' });
        }
        
        // Update message
        message.text = text.trim();
        message.edited = true;
        message.updated_at = nowIso();
        
        res.json({
            ok: true,
            message: 'Message updated successfully'
        });
        
    } catch (error) {
        console.error('Update message error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.delete('/api/messages/:id', authMiddleware, (req, res) => {
    try {
        const messageId = mustInt(req.params.id);
        const message = messages.find(m => m.id === messageId);
        
        if (!message) {
            return res.status(404).json({ ok: false, error: 'MESSAGE_NOT_FOUND' });
        }
        
        // Check permissions
        const isOwner = message.user_id === req.user.id;
        const canModerate = canModerateRoom(message.room_id, req.user.id);
        
        if (!isOwner && !canModerate) {
            return res.status(403).json({ ok: false, error: 'PERMISSION_DENIED' });
        }
        
        // Soft delete
        message.deleted = true;
        message.updated_at = nowIso();
        
        res.json({
            ok: true,
            message: 'Message deleted successfully'
        });
        
    } catch (error) {
        console.error('Delete message error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

// ===== Frames Routes =====
app.get('/api/frames', authMiddleware, (req, res) => {
    try {
        const ownedFrameIds = userFrames
            .filter(uf => uf.user_id === req.user.id)
            .map(uf => uf.frame_id);
        
        const framesWithOwned = frames.map(frame => ({
            ...frame,
            owned: ownedFrameIds.includes(frame.id),
            can_purchase: !ownedFrameIds.includes(frame.id) && frame.available && 
                         (req.user.points >= frame.price_points || frame.price_points === 0)
        }));
        
        res.json({
            ok: true,
            frames: framesWithOwned
        });
        
    } catch (error) {
        console.error('Get frames error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/frames/purchase', authMiddleware, (req, res) => {
    try {
        const { frame_id } = req.body;
        
        const frame = frames.find(f => f.id === frame_id);
        if (!frame) {
            return res.status(404).json({ ok: false, error: 'FRAME_NOT_FOUND' });
        }
        
        // Check if already owned
        const alreadyOwned = userFrames.find(uf => 
            uf.user_id === req.user.id && uf.frame_id === frame_id
        );
        
        if (alreadyOwned) {
            return res.status(400).json({ ok: false, error: 'FRAME_ALREADY_OWNED' });
        }
        
        // Check if available
        if (!frame.available) {
            return res.status(400).json({ ok: false, error: 'FRAME_NOT_AVAILABLE' });
        }
        
        // Check if user has enough points
        if (frame.price_points > req.user.points) {
            return res.status(400).json({ ok: false, error: 'INSUFFICIENT_POINTS' });
        }
        
        // Deduct points
        req.user.points -= frame.price_points;
        
        // Add to user frames
        userFrames.push({
            id: userFrames.length + 1,
            user_id: req.user.id,
            frame_id: frame_id,
            purchased_at: nowIso()
        });
        
        // Record transaction
        pointTransactions.push({
            id: pointTransactions.length + 1,
            from_user_id: req.user.id,
            to_user_id: frame.created_by,
            amount: frame.price_points,
            reason: `Purchase frame: ${frame.name}`,
            created_at: nowIso()
        });
        
        res.json({
            ok: true,
            message: 'Frame purchased successfully',
            new_balance: req.user.points
        });
        
    } catch (error) {
        console.error('Purchase frame error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/frames/select', authMiddleware, (req, res) => {
    try {
        const { frame_id } = req.body;
        
        // Check if user owns the frame
        const ownsFrame = userFrames.find(uf => 
            uf.user_id === req.user.id && uf.frame_id === frame_id
        );
        
        if (!ownsFrame && frame_id !== null) {
            return res.status(403).json({ ok: false, error: 'FRAME_NOT_OWNED' });
        }
        
        // Update user frame
        const userIndex = users.findIndex(u => u.id === req.user.id);
        users[userIndex].frame_id = frame_id;
        
        res.json({
            ok: true,
            message: 'Frame selected successfully'
        });
        
    } catch (error) {
        console.error('Select frame error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

// ===== Points System =====
app.get('/api/points/transactions', authMiddleware, (req, res) => {
    try {
        const userTransactions = pointTransactions
            .filter(pt => pt.from_user_id === req.user.id || pt.to_user_id === req.user.id)
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        
        res.json({
            ok: true,
            transactions: userTransactions
        });
        
    } catch (error) {
        console.error('Get transactions error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/points/grant', authMiddleware, (req, res) => {
    try {
        const { user_id, amount, reason } = req.body;
        
        // Only developers can grant points
        if (!req.user.is_developer) {
            return res.status(403).json({ ok: false, error: 'PERMISSION_DENIED' });
        }
        
        const targetUser = users.find(u => u.id === user_id);
        if (!targetUser) {
            return res.status(404).json({ ok: false, error: 'USER_NOT_FOUND' });
        }
        
        // Grant points
        targetUser.points += amount;
        
        // Record transaction
        pointTransactions.push({
            id: pointTransactions.length + 1,
            from_user_id: null,
            to_user_id: user_id,
            amount: amount,
            reason: reason || `Points granted by ${req.user.username}`,
            created_at: nowIso()
        });
        
        res.json({
            ok: true,
            message: 'Points granted successfully',
            new_balance: targetUser.points
        });
        
    } catch (error) {
        console.error('Grant points error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/points/transfer', authMiddleware, (req, res) => {
    try {
        const { to_user_id, amount, reason } = req.body;
        
        if (!to_user_id || !amount || amount <= 0) {
            return res.status(400).json({ ok: false, error: 'INVALID_PARAMETERS' });
        }
        
        if (amount > req.user.points) {
            return res.status(400).json({ ok: false, error: 'INSUFFICIENT_POINTS' });
        }
        
        const targetUser = users.find(u => u.id === to_user_id);
        if (!targetUser) {
            return res.status(404).json({ ok: false, error: 'USER_NOT_FOUND' });
        }
        
        // Transfer points
        req.user.points -= amount;
        targetUser.points += amount;
        
        // Record transaction
        pointTransactions.push({
            id: pointTransactions.length + 1,
            from_user_id: req.user.id,
            to_user_id: to_user_id,
            amount: amount,
            reason: reason || `Points transfer from ${req.user.username}`,
            created_at: nowIso()
        });
        
        res.json({
            ok: true,
            message: 'Points transferred successfully',
            new_balance: req.user.points
        });
        
    } catch (error) {
        console.error('Transfer points error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

// ===== Moderation Routes =====
app.post('/api/rooms/:id/mute', authMiddleware, (req, res) => {
    try {
        const roomId = mustInt(req.params.id);
        const { user_id, minutes, reason } = req.body;
        
        if (!canModerateRoom(roomId, req.user.id)) {
            return res.status(403).json({ ok: false, error: 'PERMISSION_DENIED' });
        }
        
        const targetMember = roomMembers.find(rm => 
            rm.room_id === roomId && rm.user_id === user_id
        );
        
        if (!targetMember) {
            return res.status(404).json({ ok: false, error: 'USER_NOT_IN_ROOM' });
        }
        
        // Calculate mute until time
        const muteUntil = new Date();
        muteUntil.setMinutes(muteUntil.getMinutes() + (minutes || 15));
        
        targetMember.muted_until = muteUntil.toISOString();
        
        // Create system message
        const systemMsg = {
            id: messages.length + 1,
            room_id: roomId,
            user_id: null,
            username: 'System',
            text: `تم كتم ${users.find(u => u.id === user_id)?.username} لمدة ${minutes} دقيقة. السبب: ${reason || 'غير محدد'}`,
            message_type: 'system',
            metadata_json: JSON.stringify({}),
            edited: false,
            deleted: false,
            created_at: nowIso(),
            updated_at: nowIso()
        };
        messages.push(systemMsg);
        
        res.json({
            ok: true,
            message: 'User muted successfully'
        });
        
    } catch (error) {
        console.error('Mute user error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/rooms/:id/ban', authMiddleware, (req, res) => {
    try {
        const roomId = mustInt(req.params.id);
        const { user_id, reason, permanent } = req.body;
        
        if (!canModerateRoom(roomId, req.user.id)) {
            return res.status(403).json({ ok: false, error: 'PERMISSION_DENIED' });
        }
        
        const targetMember = roomMembers.find(rm => 
            rm.room_id === roomId && rm.user_id === user_id
        );
        
        if (!targetMember) {
            return res.status(404).json({ ok: false, error: 'USER_NOT_IN_ROOM' });
        }
        
        // Ban user
        targetMember.is_banned = true;
        
        // Create system message
        const systemMsg = {
            id: messages.length + 1,
            room_id: roomId,
            user_id: null,
            username: 'System',
            text: `تم حظر ${users.find(u => u.id === user_id)?.username} من الغرفة. السبب: ${reason || 'غير محدد'}`,
            message_type: 'system',
            metadata_json: JSON.stringify({}),
            edited: false,
            deleted: false,
            created_at: nowIso(),
            updated_at: nowIso()
        };
        messages.push(systemMsg);
        
        res.json({
            ok: true,
            message: 'User banned successfully'
        });
        
    } catch (error) {
        console.error('Ban user error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/rooms/:id/unban', authMiddleware, (req, res) => {
    try {
        const roomId = mustInt(req.params.id);
        const { user_id } = req.body;
        
        if (!canModerateRoom(roomId, req.user.id)) {
            return res.status(403).json({ ok: false, error: 'PERMISSION_DENIED' });
        }
        
        const targetMember = roomMembers.find(rm => 
            rm.room_id === roomId && rm.user_id === user_id
        );
        
        if (!targetMember) {
            return res.status(404).json({ ok: false, error: 'USER_NOT_IN_ROOM' });
        }
        
        // Unban user
        targetMember.is_banned = false;
        
        res.json({
            ok: true,
            message: 'User unbanned successfully'
        });
        
    } catch (error) {
        console.error('Unban user error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/rooms/:id/chat-lock', authMiddleware, (req, res) => {
    try {
        const roomId = mustInt(req.params.id);
        const { locked } = req.body;
        
        if (!isRoomOwner(roomId, req.user.id)) {
            return res.status(403).json({ ok: false, error: 'PERMISSION_DENIED' });
        }
        
        const room = rooms.find(r => r.id === roomId);
        if (!room) {
            return res.status(404).json({ ok: false, error: 'ROOM_NOT_FOUND' });
        }
        
        const settings = safeJsonParse(room.settings_json) || {};
        settings.chat_locked = locked;
        room.settings_json = JSON.stringify(settings);
        room.updated_at = nowIso();
        
        res.json({
            ok: true,
            message: `Chat ${locked ? 'locked' : 'unlocked'} successfully`
        });
        
    } catch (error) {
        console.error('Chat lock error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

// ===== Bots & Commands =====
app.get('/api/bots', authMiddleware, (req, res) => {
    try {
        const publicBots = bots.filter(bot => bot.is_public);
        
        res.json({
            ok: true,
            bots: publicBots
        });
        
    } catch (error) {
        console.error('Get bots error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/bots', authMiddleware, (req, res) => {
    try {
        const { name, description, webhook_url, is_public, commands } = req.body;
        
        // Only developers can create bots
        if (!req.user.is_developer) {
            return res.status(403).json({ ok: false, error: 'PERMISSION_DENIED' });
        }
        
        const newBot = {
            id: bots.length + 1,
            name,
            description: description || '',
            webhook_url,
            is_public: is_public || false,
            created_by: req.user.id,
            created_at: nowIso(),
            updated_at: nowIso()
        };
        
        bots.push(newBot);
        
        // Add commands
        if (commands && Array.isArray(commands)) {
            commands.forEach(cmd => {
                botCommands.push({
                    id: botCommands.length + 1,
                    bot_id: newBot.id,
                    command: cmd.command,
                    description: cmd.description,
                    usage: cmd.usage,
                    requires_admin: cmd.requires_admin || false,
                    cooldown_seconds: cmd.cooldown_seconds || 5,
                    created_at: nowIso()
                });
            });
        }
        
        res.json({
            ok: true,
            bot: newBot
        });
        
    } catch (error) {
        console.error('Create bot error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/bots/:id/execute', authMiddleware, (req, res) => {
    try {
        const botId = mustInt(req.params.id);
        const { command, args } = req.body;
        
        const bot = bots.find(b => b.id === botId);
        if (!bot) {
            return res.status(404).json({ ok: false, error: 'BOT_NOT_FOUND' });
        }
        
        // Find command
        const botCommand = botCommands.find(bc => 
            bc.bot_id === botId && bc.command === command
        );
        
        if (!botCommand) {
            return res.status(404).json({ ok: false, error: 'COMMAND_NOT_FOUND' });
        }
        
        // Check admin permission if required
        if (botCommand.requires_admin && !req.user.is_developer) {
            return res.status(403).json({ ok: false, error: 'ADMIN_REQUIRED' });
        }
        
        // In a real implementation, this would call the bot's webhook
        // For now, simulate a response
        
        const responses = {
            'ping': '🏓 Pong!',
            'help': `🤖 **${bot.name} Commands:**\n` + 
                   botCommands.filter(bc => bc.bot_id === botId)
                    .map(bc => `• **${bc.command}** - ${bc.description}\n  Usage: ${bc.usage}`)
                    .join('\n'),
            'points': `💰 لديك ${req.user.points} نقطة`,
            'userinfo': `👤 **${req.user.username}**\n` +
                       `📧 ${req.user.email}\n` +
                       `🏆 النقاط: ${req.user.points}\n` +
                       `✅ ${req.user.verified ? 'مُـتحقق' : 'غير مُتحقق'}`,
            'time': `🕐 الوقت الحالي: ${new Date().toLocaleString('ar-SA')}`
        };
        
        const response = responses[command] || `✅ تم تنفيذ الأمر: ${command}`;
        
        res.json({
            ok: true,
            response,
            command,
            executed_at: nowIso()
        });
        
    } catch (error) {
        console.error('Execute bot command error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

// ===== Subscriptions & Payments =====
app.get('/api/subscriptions', authMiddleware, (req, res) => {
    try {
        res.json({
            ok: true,
            subscriptions: subscriptions.filter(sub => sub.is_active)
        });
        
    } catch (error) {
        console.error('Get subscriptions error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.get('/api/payment-methods', authMiddleware, (req, res) => {
    try {
        res.json({
            ok: true,
            methods: paymentMethods.filter(method => method.is_active)
        });
        
    } catch (error) {
        console.error('Get payment methods error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/subscriptions/subscribe', authMiddleware, (req, res) => {
    try {
        const { plan_id, payment_method, payment_data } = req.body;
        
        const plan = subscriptions.find(s => s.id === plan_id && s.is_active);
        if (!plan) {
            return res.status(404).json({ ok: false, error: 'PLAN_NOT_FOUND' });
        }
        
        const method = paymentMethods.find(pm => pm.id === payment_method && pm.is_active);
        if (!method) {
            return res.status(400).json({ ok: false, error: 'PAYMENT_METHOD_INVALID' });
        }
        
        // Handle different payment methods
        if (method.method_key === 'points') {
            // Pay with points
            if (req.user.points < plan.price_points) {
                return res.status(400).json({ ok: false, error: 'INSUFFICIENT_POINTS' });
            }
            
            req.user.points -= plan.price_points;
            
            // Record transaction
            pointTransactions.push({
                id: pointTransactions.length + 1,
                from_user_id: req.user.id,
                to_user_id: null,
                amount: plan.price_points,
                reason: `Subscription: ${plan.name}`,
                created_at: nowIso()
            });
        } else if (method.method_key === 'stripe') {
            // In real app, integrate with Stripe
            // For demo, simulate success
            console.log('Simulating Stripe payment:', payment_data);
        } else if (method.method_key === 'paypal') {
            // In real app, integrate with PayPal
            console.log('Simulating PayPal payment:', payment_data);
        }
        
        // Calculate expiration date
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + plan.duration_days);
        
        // Create subscription
        const subscriptionId = userSubscriptions.length + 1;
        userSubscriptions.push({
            id: subscriptionId,
            user_id: req.user.id,
            plan_id: plan.id,
            status: 'active',
            payment_method: method.method_key,
            amount_paid: plan.price_points,
            starts_at: nowIso(),
            expires_at: expiresAt.toISOString(),
            created_at: nowIso()
        });
        
        // Give subscription benefits
        if (plan.plan_key === 'premium') {
            req.user.points += 2000; // Monthly points
        } else if (plan.plan_key === 'vip') {
            req.user.points += 5000; // Monthly points
        }
        
        res.json({
            ok: true,
            subscription_id: subscriptionId,
            expires_at: expiresAt.toISOString(),
            message: 'Subscription activated successfully'
        });
        
    } catch (error) {
        console.error('Subscribe error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

// ===== Admin Routes =====
app.get('/api/admin/users', authMiddleware, (req, res) => {
    try {
        // Only developers can access admin routes
        if (!req.user.is_developer) {
            return res.status(403).json({ ok: false, error: 'PERMISSION_DENIED' });
        }
        
        const usersList = users.map(user => {
            const userCopy = { ...user };
            delete userCopy.password_hash;
            return userCopy;
        });
        
        res.json({
            ok: true,
            users: usersList
        });
        
    } catch (error) {
        console.error('Get admin users error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/admin/users/:id/toggle-ban', authMiddleware, (req, res) => {
    try {
        // Only developers can ban users
        if (!req.user.is_developer) {
            return res.status(403).json({ ok: false, error: 'PERMISSION_DENIED' });
        }
        
        const userId = mustInt(req.params.id);
        const user = users.find(u => u.id === userId);
        
        if (!user) {
            return res.status(404).json({ ok: false, error: 'USER_NOT_FOUND' });
        }
        
        // Cannot ban yourself
        if (user.id === req.user.id) {
            return res.status(400).json({ ok: false, error: 'CANNOT_BAN_SELF' });
        }
        
        // Toggle ban
        user.banned = !user.banned;
        
        res.json({
            ok: true,
            banned: user.banned,
            message: `User ${user.banned ? 'banned' : 'unbanned'} successfully`
        });
        
    } catch (error) {
        console.error('Toggle ban error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.post('/api/admin/users/:id/toggle-verify', authMiddleware, (req, res) => {
    try {
        // Only developers can verify users
        if (!req.user.is_developer) {
            return res.status(403).json({ ok: false, error: 'PERMISSION_DENIED' });
        }
        
        const userId = mustInt(req.params.id);
        const user = users.find(u => u.id === userId);
        
        if (!user) {
            return res.status(404).json({ ok: false, error: 'USER_NOT_FOUND' });
        }
        
        // Toggle verification
        user.verified = !user.verified;
        
        res.json({
            ok: true,
            verified: user.verified,
            message: `User ${user.verified ? 'verified' : 'unverified'} successfully`
        });
        
    } catch (error) {
        console.error('Toggle verify error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

// ===== Search Routes =====
app.get('/api/search/users', authMiddleware, (req, res) => {
    try {
        const { query } = req.query;
        
        if (!query || query.length < 2) {
            return res.json({ ok: true, users: [] });
        }
        
        const searchResults = users
            .filter(user => 
                user.username.toLowerCase().includes(query.toLowerCase()) ||
                (user.bio && user.bio.toLowerCase().includes(query.toLowerCase()))
            )
            .map(user => {
                const userCopy = { ...user };
                delete userCopy.password_hash;
                delete userCopy.email;
                return userCopy;
            });
        
        res.json({
            ok: true,
            users: searchResults
        });
        
    } catch (error) {
        console.error('Search users error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

app.get('/api/search/rooms', authMiddleware, (req, res) => {
    try {
        const { query } = req.query;
        
        if (!query || query.length < 2) {
            return res.json({ ok: true, rooms: [] });
        }
        
        const searchResults = rooms
            .filter(room => 
                room.name.toLowerCase().includes(query.toLowerCase()) ||
                (room.description && room.description.toLowerCase().includes(query.toLowerCase()))
            )
            .map(room => ({
                ...room,
                member_count: roomMembers.filter(rm => rm.room_id === room.id && !rm.is_banned).length
            }));
        
        res.json({
            ok: true,
            rooms: searchResults
        });
        
    } catch (error) {
        console.error('Search rooms error:', error);
        res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
});

// ===== Socket.IO Setup =====
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    },
    pingInterval: 25000,
    pingTimeout: 60000
});

// Socket connection tracking
const connectedUsersMap = new Map();

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) {
        return next(new Error("Authentication required"));
    }
    
    try {
        const decoded = verifyToken(token);
        if (!decoded) {
            return next(new Error("Invalid token"));
        }
        
        const user = users.find(u => u.id === decoded.id);
        if (!user || user.banned) {
            return next(new Error("User not found or banned"));
        }
        
        socket.user = user;
        next();
    } catch (error) {
        next(new Error("Authentication error"));
    }
});

io.on('connection', (socket) => {
    console.log(`🔌 User connected: ${socket.user.username} (ID: ${socket.id})`);
    
    // Track connected user
    connectedUsersMap.set(socket.user.id, {
        socketId: socket.id,
        user: socket.user,
        rooms: new Set(),
        voiceSeat: null
    });
    
    // Broadcast online status
    io.emit('user_online', {
        user_id: socket.user.id,
        username: socket.user.username,
        avatar_url: socket.user.avatar_url
    });
    
    // ===== Room Events =====
    socket.on('join_room', (data) => {
        try {
            const roomId = mustInt(data.room_id);
            const room = rooms.find(r => r.id === roomId);
            
            if (!room) {
                return socket.emit('error', { message: 'Room not found' });
            }
            
            // Check if user is banned from room
            const roomMember = roomMembers.find(rm => 
                rm.room_id === roomId && rm.user_id === socket.user.id
            );
            
            if (roomMember?.is_banned) {
                return socket.emit('error', { message: 'You are banned from this room' });
            }
            
            // Check if room requires points to join
            if (room.price_points > 0 && !roomMember) {
                if (socket.user.points < room.price_points) {
                    return socket.emit('error', { 
                        message: `Not enough points (${room.price_points} required)` 
                    });
                }
                
                // Deduct points
                socket.user.points -= room.price_points;
                
                pointTransactions.push({
                    id: pointTransactions.length + 1,
                    from_user_id: socket.user.id,
                    to_user_id: room.owner_id,
                    amount: room.price_points,
                    reason: `Join room: ${room.name}`,
                    created_at: nowIso()
                });
            }
            
            // Join room if not already member
            if (!roomMember) {
                const newMember = {
                    id: roomMembers.length + 1,
                    room_id: roomId,
                    user_id: socket.user.id,
                    role: 'member',
                    joined_at: nowIso(),
                    muted_until: null,
                    is_banned: false,
                    label_text: null,
                    label_color: null
                };
                roomMembers.push(newMember);
                
                // Send system message
                const systemMsg = {
                    id: messages.length + 1,
                    room_id: roomId,
                    user_id: null,
                    username: 'System',
                    text: `${socket.user.username} joined the room`,
                    message_type: 'system',
                    metadata_json: JSON.stringify({}),
                    edited: false,
                    deleted: false,
                    created_at: nowIso(),
                    updated_at: nowIso()
                };
                messages.push(systemMsg);
                
                io.to(`room_${roomId}`).emit('new_message', systemMsg);
            }
            
            // Join socket room
            socket.join(`room_${roomId}`);
            
            // Track user room
            const userConn = connectedUsersMap.get(socket.user.id);
            if (userConn) {
                userConn.rooms.add(roomId);
            }
            
            // Notify room
            socket.to(`room_${roomId}`).emit('user_joined_room', {
                user_id: socket.user.id,
                username: socket.user.username,
                avatar_url: socket.user.avatar_url,
                frame_id: socket.user.frame_id
            });
            
            // Send current room state
            const roomMessages = messages
                .filter(m => m.room_id === roomId && !m.deleted)
                .slice(-50);
            
            const roomUsers = roomMembers
                .filter(rm => rm.room_id === roomId && !rm.is_banned)
                .map(rm => {
                    const user = users.find(u => u.id === rm.user_id);
                    const isOnline = connectedUsersMap.has(rm.user_id);
                    return {
                        ...rm,
                        username: user?.username,
                        avatar_url: user?.avatar_url,
                        is_online: isOnline,
                        is_developer: user?.is_developer,
                        verified: user?.verified
                    };
                });
            
            let voiceSeatsData = [];
            if (room.type === 'voice') {
                voiceSeatsData = voiceSeats
                    .filter(vs => vs.room_id === roomId)
                    .map(vs => ({
                        ...vs,
                        username: vs.user_id ? users.find(u => u.id === vs.user_id)?.username : null,
                        avatar_url: vs.user_id ? users.find(u => u.id === vs.user_id)?.avatar_url : null
                    }));
            }
            
            socket.emit('room_state', {
                room,
                messages: roomMessages,
                users: roomUsers,
                voice_seats: voiceSeatsData
            });
            
        } catch (error) {
            console.error('Join room error:', error);
            socket.emit('error', { message: 'Internal server error' });
        }
    });
    
    socket.on('leave_room', (data) => {
        try {
            const roomId = mustInt(data.room_id);
            
            // Leave socket room
            socket.leave(`room_${roomId}`);
            
            // Update user connection tracking
            const userConn = connectedUsersMap.get(socket.user.id);
            if (userConn) {
                userConn.rooms.delete(roomId);
            }
            
            // Notify room
            socket.to(`room_${roomId}`).emit('user_left_room', {
                user_id: socket.user.id,
                username: socket.user.username
            });
            
            // Free voice seat if occupied
            const seatIndex = voiceSeats.findIndex(vs => 
                vs.room_id === roomId && vs.user_id === socket.user.id
            );
            if (seatIndex !== -1) {
                voiceSeats[seatIndex].user_id = null;
                voiceSeats[seatIndex].is_muted = false;
                voiceSeats[seatIndex].updated_at = nowIso();
                
                // Broadcast seat update
                io.to(`room_${roomId}`).emit('voice_seat_update', voiceSeats[seatIndex]);
            }
            
        } catch (error) {
            console.error('Leave room error:', error);
        }
    });
    
    // ===== Chat Events =====
    socket.on('send_message', (data) => {
        try {
            const roomId = mustInt(data.room_id);
            const { text, message_type, metadata } = data;
            
            // Validate
            if (!text || text.trim().length === 0) {
                return socket.emit('error', { message: 'Message cannot be empty' });
            }
            
            // Check if user is in room
            const roomMember = roomMembers.find(rm => 
                rm.room_id === roomId && rm.user_id === socket.user.id && !rm.is_banned
            );
            
            if (!roomMember) {
                return socket.emit('error', { message: 'You are not a member of this room' });
            }
            
            // Check if muted
            if (roomMember.muted_until && new Date(roomMember.muted_until) > new Date()) {
                return socket.emit('error', { message: 'You are muted in this room' });
            }
            
            // Check if chat is locked
            const room = rooms.find(r => r.id === roomId);
            if (room) {
                const settings = safeJsonParse(room.settings_json) || {};
                if (settings.chat_locked && roomMember.role !== 'owner' && roomMember.role !== 'admin') {
                    return socket.emit('error', { message: 'Chat is locked in this room' });
                }
            }
            
            // Create message
            const message = {
                id: messages.length + 1,
                room_id: roomId,
                user_id: socket.user.id,
                username: socket.user.username,
                text: text.trim(),
                message_type: message_type || 'text',
                metadata_json: metadata ? JSON.stringify(metadata) : '{}',
                edited: false,
                deleted: false,
                created_at: nowIso(),
                updated_at: nowIso()
            };
            
            messages.push(message);
            
            // Broadcast to room
            io.to(`room_${roomId}`).emit('new_message', message);
            
            // Apply auto-delete if configured
            if (room && room.settings_json) {
                const settings = safeJsonParse(room.settings_json);
                if (settings.auto_delete_limit > 0) {
                    const roomMessages = messages.filter(m => m.room_id === roomId);
                    if (roomMessages.length > settings.auto_delete_limit) {
                        const messagesToDelete = roomMessages
                            .slice(0, roomMessages.length - settings.auto_delete_limit);
                        
                        messagesToDelete.forEach(msg => {
                            msg.deleted = true;
                        });
                        
                        io.to(`room_${roomId}`).emit('messages_deleted', {
                            count: messagesToDelete.length
                        });
                    }
                }
            }
            
        } catch (error) {
            console.error('Send message error:', error);
            socket.emit('error', { message: 'Failed to send message' });
        }
    });
    
    socket.on('typing_start', (data) => {
        try {
            const roomId = mustInt(data.room_id);
            socket.to(`room_${roomId}`).emit('user_typing', {
                user_id: socket.user.id,
                username: socket.user.username
            });
        } catch (error) {
            console.error('Typing start error:', error);
        }
    });
    
    socket.on('typing_stop', (data) => {
        try {
            const roomId = mustInt(data.room_id);
            socket.to(`room_${roomId}`).emit('user_stopped_typing', {
                user_id: socket.user.id
            });
        } catch (error) {
            console.error('Typing stop error:', error);
        }
    });
    
    // ===== Voice Room Events =====
    socket.on('join_voice_seat', (data) => {
        try {
            const { room_id, seat_index } = data;
            const roomId = mustInt(room_id);
            const seatIdx = mustInt(seat_index);
            
            // Check if room is voice room
            const room = rooms.find(r => r.id === roomId && r.type === 'voice');
            if (!room) {
                return socket.emit('error', { message: 'Voice room not found' });
            }
            
            // Check if seat exists
            const seat = voiceSeats.find(vs => 
                vs.room_id === roomId && vs.seat_index === seatIdx
            );
            
            if (!seat) {
                return socket.emit('error', { message: 'Seat not found' });
            }
            
            // Check if seat is locked
            if (seat.is_locked) {
                return socket.emit('error', { message: 'Seat is locked' });
            }
            
            // Check if seat is already occupied
            if (seat.user_id && seat.user_id !== socket.user.id) {
                return socket.emit('error', { message: 'Seat already occupied' });
            }
            
            // Free previous seat if any
            const previousSeat = voiceSeats.find(vs => 
                vs.room_id === roomId && vs.user_id === socket.user.id
            );
            
            if (previousSeat) {
                previousSeat.user_id = null;
                previousSeat.is_muted = false;
                previousSeat.updated_at = nowIso();
                
                io.to(`room_${roomId}`).emit('voice_seat_update', previousSeat);
            }
            
            // Occupy new seat
            seat.user_id = socket.user.id;
            seat.is_muted = false;
            seat.updated_at = nowIso();
            
            // Update user connection tracking
            const userConn = connectedUsersMap.get(socket.user.id);
            if (userConn) {
                userConn.voiceSeat = { roomId, seatIndex: seatIdx };
            }
            
            // Broadcast seat update
            io.to(`room_${roomId}`).emit('voice_seat_update', {
                ...seat,
                username: socket.user.username,
                avatar_url: socket.user.avatar_url
            });
            
            // Send system message
            const systemMsg = {
                id: messages.length + 1,
                room_id: roomId,
                user_id: null,
                username: 'System',
                text: `${socket.user.username} joined voice seat ${seatIdx}`,
                message_type: 'system',
                metadata_json: JSON.stringify({}),
                edited: false,
                deleted: false,
                created_at: nowIso(),
                updated_at: nowIso()
            };
            messages.push(systemMsg);
            io.to(`room_${roomId}`).emit('new_message', systemMsg);
            
        } catch (error) {
            console.error('Join voice seat error:', error);
            socket.emit('error', { message: 'Failed to join voice seat' });
        }
    });
    
    socket.on('leave_voice_seat', (data) => {
        try {
            const { room_id } = data;
            const roomId = mustInt(room_id);
            
            // Find seat occupied by user
            const seat = voiceSeats.find(vs => 
                vs.room_id === roomId && vs.user_id === socket.user.id
            );
            
            if (!seat) {
                return; // Not in a seat
            }
            
            // Free the seat
            seat.user_id = null;
            seat.is_muted = false;
            seat.updated_at = nowIso();
            
            // Update user connection tracking
            const userConn = connectedUsersMap.get(socket.user.id);
            if (userConn) {
                userConn.voiceSeat = null;
            }
            
            // Broadcast seat update
            io.to(`room_${roomId}`).emit('voice_seat_update', seat);
            
            // Send system message
            const systemMsg = {
                id: messages.length + 1,
                room_id: roomId,
                user_id: null,
                username: 'System',
                text: `${socket.user.username} left voice`,
                message_type: 'system',
                metadata_json: JSON.stringify({}),
                edited: false,
                deleted: false,
                created_at: nowIso(),
                updated_at: nowIso()
            };
            messages.push(systemMsg);
            io.to(`room_${roomId}`).emit('new_message', systemMsg);
            
        } catch (error) {
            console.error('Leave voice seat error:', error);
        }
    });
    
    socket.on('toggle_mute_voice_seat', (data) => {
        try {
            const { room_id, seat_index, muted } = data;
            const roomId = mustInt(room_id);
            const seatIdx = mustInt(seat_index);
            
            // Find seat
            const seat = voiceSeats.find(vs => 
                vs.room_id === roomId && vs.seat_index === seatIdx
            );
            
            if (!seat) {
                return socket.emit('error', { message: 'Seat not found' });
            }
            
            // Check permissions
            const canModerate = canModerateRoom(roomId, socket.user.id);
            const isSeatOwner = seat.user_id === socket.user.id;
            
            if (!canModerate && !isSeatOwner) {
                return socket.emit('error', { message: 'Permission denied' });
            }
            
            // Toggle mute
            seat.is_muted = muted;
            seat.updated_at = nowIso();
            
            // Broadcast seat update
            io.to(`room_${roomId}`).emit('voice_seat_update', seat);
            
        } catch (error) {
            console.error('Toggle mute voice seat error:', error);
            socket.emit('error', { message: 'Failed to toggle mute' });
        }
    });
    
    socket.on('lock_voice_seat', (data) => {
        try {
            const { room_id, seat_index, locked } = data;
            const roomId = mustInt(room_id);
            const seatIdx = mustInt(seat_index);
            
            // Check permissions
            if (!canModerateRoom(roomId, socket.user.id)) {
                return socket.emit('error', { message: 'Permission denied' });
            }
            
            // Find seat
            const seat = voiceSeats.find(vs => 
                vs.room_id === roomId && vs.seat_index === seatIdx
            );
            
            if (!seat) {
                return socket.emit('error', { message: 'Seat not found' });
            }
            
            // Lock/unlock seat
            seat.is_locked = locked;
            seat.updated_at = nowIso();
            
            // If locking and seat is occupied, kick user
            if (locked && seat.user_id) {
                // Notify user
                const userSocketId = connectedUsersMap.get(seat.user_id)?.socketId;
                if (userSocketId) {
                    io.to(userSocketId).emit('voice_seat_locked', {
                        room_id: roomId,
                        seat_index: seatIdx
                    });
                }
                
                seat.user_id = null;
                seat.is_muted = false;
            }
            
            // Broadcast seat update
            io.to(`room_${roomId}`).emit('voice_seat_update', seat);
            
        } catch (error) {
            console.error('Lock voice seat error:', error);
            socket.emit('error', { message: 'Failed to lock seat' });
        }
    });
    
    // ===== WebRTC Signaling =====
    socket.on('voice_signal', (data) => {
        try {
            const { to_user_id, signal } = data;
            
            // Forward signal to target user
            const targetConn = connectedUsersMap.get(to_user_id);
            if (targetConn) {
                io.to(targetConn.socketId).emit('voice_signal', {
                    from_user_id: socket.user.id,
                    signal: signal
                });
            }
            
        } catch (error) {
            console.error('Voice signal error:', error);
        }
    });
    
    // ===== Notification Events =====
    socket.on('mark_notification_read', (data) => {
        try {
            const { notification_id } = data;
            
            const notification = notifications.find(n => 
                n.id === notification_id && n.user_id === socket.user.id
            );
            
            if (notification) {
                notification.read = true;
                notification.read_at = nowIso();
                
                socket.emit('notification_updated', notification);
            }
            
        } catch (error) {
            console.error('Mark notification read error:', error);
        }
    });
    
    // ===== Disconnection Handling =====
    socket.on('disconnect', () => {
        console.log(`🔌 User disconnected: ${socket.user.username}`);
        
        const userConn = connectedUsersMap.get(socket.user.id);
        if (!userConn) return;
        
        // Leave all rooms
        userConn.rooms.forEach(roomId => {
            // Free voice seat if occupied
            const seat = voiceSeats.find(vs => 
                vs.room_id === roomId && vs.user_id === socket.user.id
            );
            
            if (seat) {
                seat.user_id = null;
                seat.is_muted = false;
                seat.updated_at = nowIso();
                
                io.to(`room_${roomId}`).emit('voice_seat_update', seat);
            }
            
            // Notify room
            socket.to(`room_${roomId}`).emit('user_left_room', {
                user_id: socket.user.id,
                username: socket.user.username
            });
        });
        
        // Remove from connected users
        connectedUsersMap.delete(socket.user.id);
        
        // Update last seen
        const user = users.find(u => u.id === socket.user.id);
        if (user) {
            user.last_seen = nowIso();
        }
        
        // Broadcast offline status
        io.emit('user_offline', {
            user_id: socket.user.id,
            username: socket.user.username
        });
    });
    
    // ===== Heartbeat =====
    socket.on('heartbeat', () => {
        // Update last seen
        const userConn = connectedUsersMap.get(socket.user.id);
        if (userConn) {
            userConn.lastHeartbeat = Date.now();
        }
    });
});

// ================== START SERVER ==================
initializeDefaultData();

server.listen(PORT, () => {
    console.log(`🚀 ProfileHub Server v3.0 is running on port ${PORT}`);
    console.log(`📡 WebSocket server ready`);
    console.log(`🔄 REST API available at http://localhost:${PORT}`);
    console.log(`👨‍💻 Admin user: admin / admin123`);
});
