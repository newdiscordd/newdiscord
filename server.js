/**
 * Discord Clone - Full Stack Server with Voice Chat & Screen Sharing
 * ПОЛНАЯ ВЕРСИЯ С ИСПРАВЛЕНИЯМИ
 */

const express = require('express');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const http = require('http');

// ============================================
// КОНФИГУРАЦИЯ
// ============================================

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const BCRYPT_ROUNDS = 10;
const DATABASE_URL = process.env.DATABASE_URL;

// Расширенная конфигурация ICE серверов
const ICE_SERVERS = [
    // Google STUN серверы
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    // Твой TURN сервер
    {
        urls: 'turn:195.133.53.53:3478',
        username: 'discordclone',
        credential: '123456'
    },
    {
        urls: 'turn:195.133.53.53:3478?transport=tcp',
        username: 'discordclone',
        credential: '123456'
    }
];

// ============================================
// ИНИЦИАЛИЗАЦИЯ
// ============================================

const app = express();
const server = http.createServer(app);

app.use(cors());
app.use(express.json({ limit: '5mb' }));

const MAX_INLINE_IMAGE_SIZE = 4 * 1024 * 1024;

function sanitizeInlineImage(imageData) {
    if (!imageData || typeof imageData !== 'string') return null;
    const trimmed = imageData.trim();
    const match = trimmed.match(/^data:image\/(png|jpe?g|gif|webp);base64,([A-Za-z0-9+/=]+)$/i);
    if (!match) return null;
    const base64Payload = match[2];
    const byteLength = Buffer.byteLength(base64Payload, 'base64');
    if (!byteLength || byteLength > MAX_INLINE_IMAGE_SIZE) return null;
    return trimmed;
}

// ============================================
// POSTGRESQL
// ============================================

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

pool.on('connect', () => console.log('✅ PostgreSQL подключен'));
pool.on('error', (err) => console.error('❌ PostgreSQL ошибка:', err));

// ============================================
// ГОЛОСОВЫЕ КОМНАТЫ (в памяти)
// ============================================

const voiceRooms = new Map();
// Структура: Map<channelId, Map<odego, participant>>
// participant: { odego, visitorId, username, muted, deafened, streaming, streamType }

function getVoiceRoom(channelId) {
    if (!voiceRooms.has(channelId)) {
        voiceRooms.set(channelId, new Map());
    }
    return voiceRooms.get(channelId);
}

function getVoiceRoomParticipants(channelId) {
    const room = voiceRooms.get(channelId);
    if (!room) return [];
    return Array.from(room.values());
}

function getUserVoiceChannel(odego) {
    for (const [channelId, room] of voiceRooms.entries()) {
        if (room.has(odego)) {
            return channelId;
        }
    }
    return null;
}

// ============================================
// ИНИЦИАЛИЗАЦИЯ БД
// ============================================

async function initializeDatabase() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                username VARCHAR(32) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                avatar_url TEXT,
                status VARCHAR(20) DEFAULT 'offline',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS servers (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(100) NOT NULL,
                owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                icon_url TEXT,
                invite_code VARCHAR(10) UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS server_members (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                role VARCHAR(20) DEFAULT 'member',
                nickname VARCHAR(32),
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(server_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS channels (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                name VARCHAR(100) NOT NULL,
                type VARCHAR(20) DEFAULT 'text',
                topic TEXT,
                position INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS messages (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
                author_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                image_url TEXT,
                edited_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS direct_messages (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                image_url TEXT,
                read_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            ALTER TABLE messages ADD COLUMN IF NOT EXISTS image_url TEXT;
            ALTER TABLE direct_messages ADD COLUMN IF NOT EXISTS image_url TEXT;
            ALTER TABLE messages ALTER COLUMN content DROP NOT NULL;
            ALTER TABLE direct_messages ALTER COLUMN content DROP NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id);
            CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at DESC);
        `);
        console.log('✅ База данных инициализирована');
    } finally {
        client.release();
    }
}

// ============================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================

function generateInviteCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    return Array.from({ length: 8 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

// ============================================
// MIDDLEWARE
// ============================================

function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Токен не предоставлен' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Недействительный токен' });
        req.user = user;
        next();
    });
}

async function checkServerMembership(req, res, next) {
    const { serverId } = req.params;
    try {
        const result = await pool.query(
            'SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2',
            [serverId, req.user.id]
        );
        if (result.rows.length === 0) {
            return res.status(403).json({ error: 'Вы не участник этого сервера' });
        }
        req.membership = result.rows[0];
        next();
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
}

async function checkServerOwner(req, res, next) {
    const { serverId } = req.params;
    try {
        const result = await pool.query('SELECT * FROM servers WHERE id = $1', [serverId]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Сервер не найден' });
        if (result.rows[0].owner_id !== req.user.id) {
            return res.status(403).json({ error: 'Только владелец может это сделать' });
        }
        req.server = result.rows[0];
        next();
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
}

// ============================================
// WEBSOCKET
// ============================================

const wss = new WebSocketServer({ server });
const clients = new Map(); // Map<odego, Set<WebSocket>>
const wsUserMap = new Map(); // Map<WebSocket, odego>

function sendToUser(odego, data) {
    const sockets = clients.get(odego);
    if (sockets) {
        const msg = JSON.stringify(data);
        sockets.forEach(ws => {
            if (ws.readyState === ws.OPEN) {
                ws.send(msg);
            }
        });
    }
}

async function broadcastToServer(serverId, data) {
    try {
        const result = await pool.query('SELECT user_id FROM server_members WHERE server_id = $1', [serverId]);
        const msg = JSON.stringify(data);
        result.rows.forEach(row => {
            const sockets = clients.get(row.user_id);
            if (sockets) {
                sockets.forEach(ws => {
                    if (ws.readyState === ws.OPEN) {
                        ws.send(msg);
                    }
                });
            }
        });
    } catch (e) {
        console.error('Broadcast error:', e);
    }
}

function broadcastToVoiceChannel(channelId, data, excludeUserId = null) {
    const room = voiceRooms.get(channelId);
    if (!room) return;
    
    room.forEach((participant, odego) => {
        if (excludeUserId && odego === excludeUserId) return;
        sendToUser(odego, data);
    });
}

// ============================================
// ГОЛОСОВЫЕ ФУНКЦИИ
// ============================================

async function handleVoiceJoin(odego, username, channelId, ws) {
    const currentChannel = getUserVoiceChannel(odego);
    if (currentChannel && currentChannel !== channelId) {
        await handleVoiceLeave(odego);
    }
    
    const channelResult = await pool.query('SELECT * FROM channels WHERE id = $1 AND type = $2', [channelId, 'voice']);
    if (!channelResult.rows[0]) {
        sendToUser(odego, { type: 'VOICE_ERROR', error: 'Голосовой канал не найден' });
        return;
    }
    
    const channel = channelResult.rows[0];
    
    const memberResult = await pool.query('SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2', [channel.server_id, odego]);
    if (!memberResult.rows[0]) {
        sendToUser(odego, { type: 'VOICE_ERROR', error: 'Нет доступа к серверу' });
        return;
    }
    
    const room = getVoiceRoom(channelId);
    const userResult = await pool.query('SELECT avatar_url FROM users WHERE id = $1', [odego]);
    
    if (room.has(odego)) {
        console.log(`[VOICE] User ${username} already in channel ${channelId}, skipping`);
        return;
    }
    
    const existingParticipants = Array.from(room.values());
    
    const participant = {
        odego: odego,
        visitorId: odego,
        username: username,
        avatar_url: userResult.rows[0] ? userResult.rows[0].avatar_url : null,
        muted: false,
        deafened: false,
        streaming: false,
        streamType: null
    };
    
    room.set(odego, participant);
    
    console.log(`[VOICE] ${username} (${odego}) joined channel ${channelId}. Participants: ${room.size}`);
    
    sendToUser(odego, {
        type: 'VOICE_JOINED',
        channelId: channelId,
        participants: existingParticipants,
        iceServers: ICE_SERVERS
    });
    
    broadcastToVoiceChannel(channelId, {
        type: 'VOICE_USER_JOINED',
        channelId: channelId,
        user: participant
    }, odego);
    
    broadcastToServer(channel.server_id, {
        type: 'VOICE_STATE_UPDATE',
        channelId: channelId,
        visitorId: odego,
        username: username,
        action: 'join'
    });
}

async function handleVoiceLeave(odego) {
    const channelId = getUserVoiceChannel(odego);
    if (!channelId) return;
    
    const room = voiceRooms.get(channelId);
    if (!room) return;
    
    const user = room.get(odego);
    if (!user) return;
    
    room.delete(odego);
    
    console.log(`[VOICE] ${user.username} (${odego}) left channel ${channelId}. Participants: ${room.size}`);
    
    if (room.size === 0) {
        voiceRooms.delete(channelId);
    }
    
    broadcastToVoiceChannel(channelId, {
        type: 'VOICE_USER_LEFT',
        channelId: channelId,
        visitorId: odego
    });
    
    try {
        const channelResult = await pool.query('SELECT server_id FROM channels WHERE id = $1', [channelId]);
        if (channelResult.rows[0]) {
            broadcastToServer(channelResult.rows[0].server_id, {
                type: 'VOICE_STATE_UPDATE',
                channelId: channelId,
                visitorId: odego,
                action: 'leave'
            });
        }
    } catch (e) {
        console.error('Voice leave broadcast error:', e);
    }
    
    sendToUser(odego, { type: 'VOICE_LEFT', channelId: channelId });
}

// Обработка начала/остановки стрима
function handleStreamStart(odego, streamType) {
    const channelId = getUserVoiceChannel(odego);
    if (!channelId) return;
    
    const room = voiceRooms.get(channelId);
    if (!room || !room.has(odego)) return;
    
    const participant = room.get(odego);
    participant.streaming = true;
    participant.streamType = streamType;
    
    console.log(`[STREAM] ${participant.username} started ${streamType} stream`);
    
    broadcastToVoiceChannel(channelId, {
        type: 'VOICE_STREAM_START',
        channelId: channelId,
        visitorId: odego,
        username: participant.username,
        streamType: streamType
    });
}

function handleStreamStop(odego) {
    const channelId = getUserVoiceChannel(odego);
    if (!channelId) return;
    
    const room = voiceRooms.get(channelId);
    if (!room || !room.has(odego)) return;
    
    const participant = room.get(odego);
    participant.streaming = false;
    participant.streamType = null;
    
    console.log(`[STREAM] ${participant.username} stopped streaming`);
    
    broadcastToVoiceChannel(channelId, {
        type: 'VOICE_STREAM_STOP',
        channelId: channelId,
        visitorId: odego
    });
}

wss.on('connection', (ws) => {
    let odego = null;
    let username = null;
    const pingInterval = setInterval(() => {
        if (ws.readyState === ws.OPEN) ws.ping();
    }, 30000);

    ws.on('message', async (data) => {
        try {
            const msg = JSON.parse(data.toString());

            if (msg.type === 'AUTH') {
                try {
                    const decoded = jwt.verify(msg.token, JWT_SECRET);
                    odego = decoded.id;
                    username = decoded.username;
                    wsUserMap.set(ws, odego);
                    
                    if (!clients.has(odego)) {
                        clients.set(odego, new Set());
                    }
                    clients.get(odego).add(ws);
                    
                    await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['online', odego]);
                    
                    ws.send(JSON.stringify({ 
                        type: 'AUTH_SUCCESS', 
                        visitorId: odego,
                        username: username,
                        iceServers: ICE_SERVERS
                    }));
                    
                    const servers = await pool.query('SELECT server_id FROM server_members WHERE user_id = $1', [odego]);
                    servers.rows.forEach(r => {
                        broadcastToServer(r.server_id, { 
                            type: 'USER_STATUS_CHANGE', 
                            visitorId: odego, 
                            status: 'online' 
                        });
                    });
                } catch (e) {
                    ws.send(JSON.stringify({ type: 'AUTH_ERROR', error: 'Недействительный токен' }));
                }
                return;
            }

            if (!odego) {
                ws.send(JSON.stringify({ type: 'ERROR', error: 'Требуется аутентификация' }));
                return;
            }

            switch (msg.type) {
                case 'VOICE_JOIN':
                    if (msg.channelId) {
                        await handleVoiceJoin(odego, username, msg.channelId, ws);
                    }
                    break;

                case 'VOICE_LEAVE':
                    await handleVoiceLeave(odego);
                    break;

                case 'VOICE_SIGNAL':
                    if (msg.targetUserId && msg.signal) {
                        sendToUser(msg.targetUserId, {
                            type: 'VOICE_SIGNAL',
                            fromUserId: odego,
                            fromUsername: username,
                            signal: msg.signal,
                            signalType: msg.signalType || 'audio' // audio, video, screen
                        });
                    }
                    break;

                case 'VOICE_SPEAKING': {
                    const chId = getUserVoiceChannel(odego);
                    if (chId) {
                        broadcastToVoiceChannel(chId, {
                            type: 'VOICE_SPEAKING',
                            visitorId: odego,
                            speaking: msg.speaking
                        }, odego);
                    }
                    break;
                }

                case 'VOICE_TOGGLE_MUTE': {
                    const chId = getUserVoiceChannel(odego);
                    if (chId) {
                        const room = voiceRooms.get(chId);
                        if (room && room.has(odego)) {
                            const participant = room.get(odego);
                            participant.muted = msg.muted;
                            broadcastToVoiceChannel(chId, {
                                type: 'VOICE_USER_MUTE',
                                channelId: chId,
                                visitorId: odego,
                                muted: msg.muted
                            });
                        }
                    }
                    break;
                }

                case 'VOICE_TOGGLE_DEAFEN': {
                    const chId = getUserVoiceChannel(odego);
                    if (chId) {
                        const room = voiceRooms.get(chId);
                        if (room && room.has(odego)) {
                            const participant = room.get(odego);
                            participant.deafened = msg.deafened;
                            if (msg.deafened) participant.muted = true;
                            broadcastToVoiceChannel(chId, {
                                type: 'VOICE_USER_DEAFEN',
                                channelId: chId,
                                visitorId: odego,
                                deafened: msg.deafened,
                                muted: participant.muted
                            });
                        }
                    }
                    break;
                }

                case 'VOICE_STREAM_START':
                    handleStreamStart(odego, msg.streamType || 'screen');
                    break;

                case 'VOICE_STREAM_STOP':
                    handleStreamStop(odego);
                    break;

                case 'CHANNEL_MESSAGE': {
                    const { channelId, content, imageUrl } = msg;
                    const textContent = typeof content === 'string' ? content.trim() : '';
                    const safeImageUrl = sanitizeInlineImage(imageUrl);
                    if ((!textContent && !safeImageUrl) || textContent.length > 2000) break;
                    
                    const ch = await pool.query('SELECT * FROM channels WHERE id = $1', [channelId]);
                    if (!ch.rows[0]) break;
                    
                    const mem = await pool.query('SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2', [ch.rows[0].server_id, odego]);
                    if (!mem.rows[0]) break;
                    
                    const msgId = uuidv4();
                    await pool.query('INSERT INTO messages (id, channel_id, author_id, content, image_url) VALUES ($1, $2, $3, $4, $5)', [msgId, channelId, odego, textContent || null, safeImageUrl]);
                    
                    const newMsg = await pool.query('SELECT m.*, u.username, u.avatar_url FROM messages m JOIN users u ON m.author_id = u.id WHERE m.id = $1', [msgId]);
                    broadcastToServer(ch.rows[0].server_id, { type: 'NEW_CHANNEL_MESSAGE', message: newMsg.rows[0] });
                    break;
                }

                case 'DIRECT_MESSAGE': {
                    const { recipientId, content, imageUrl } = msg;
                    const textContent = typeof content === 'string' ? content.trim() : '';
                    const safeImageUrl = sanitizeInlineImage(imageUrl);
                    if ((!textContent && !safeImageUrl) || textContent.length > 2000) break;
                    
                    const recipient = await pool.query('SELECT id, username, avatar_url FROM users WHERE id = $1', [recipientId]);
                    if (!recipient.rows[0]) break;
                    
                    const msgId = uuidv4();
                    await pool.query('INSERT INTO direct_messages (id, sender_id, recipient_id, content, image_url) VALUES ($1, $2, $3, $4, $5)', [msgId, odego, recipientId, textContent || null, safeImageUrl]);
                    
                    const sender = await pool.query('SELECT username, avatar_url FROM users WHERE id = $1', [odego]);
                    const newMsg = {
                        id: msgId, sender_id: odego, recipient_id: recipientId, content: textContent || null, image_url: safeImageUrl,
                        created_at: new Date().toISOString(),
                        sender_username: sender.rows[0].username, sender_avatar: sender.rows[0].avatar_url,
                        recipient_username: recipient.rows[0].username, recipient_avatar: recipient.rows[0].avatar_url
                    };
                    sendToUser(odego, { type: 'NEW_DIRECT_MESSAGE', message: newMsg });
                    sendToUser(recipientId, { type: 'NEW_DIRECT_MESSAGE', message: newMsg });
                    break;
                }

                case 'TYPING_START': {
                    const { channelId, recipientId } = msg;
                    const user = await pool.query('SELECT username FROM users WHERE id = $1', [odego]);
                    if (channelId) {
                        const ch = await pool.query('SELECT server_id FROM channels WHERE id = $1', [channelId]);
                        if (ch.rows[0]) {
                            broadcastToServer(ch.rows[0].server_id, { 
                                type: 'USER_TYPING', 
                                channelId, 
                                visitorId: odego, 
                                username: user.rows[0]?.username 
                            });
                        }
                    } else if (recipientId) {
                        sendToUser(recipientId, { 
                            type: 'USER_TYPING', 
                            visitorId: odego, 
                            username: user.rows[0]?.username 
                        });
                    }
                    break;
                }

                case 'PING':
                    ws.send(JSON.stringify({ type: 'PONG', timestamp: Date.now() }));
                    break;
            }
        } catch (e) {
            console.error('WS Error:', e);
        }
    });

    ws.on('close', async () => {
        clearInterval(pingInterval);
        wsUserMap.delete(ws);
        
        if (odego) {
            await handleVoiceLeave(odego);
            
            const sockets = clients.get(odego);
            if (sockets) {
                sockets.delete(ws);
                if (sockets.size === 0) {
                    clients.delete(odego);
                    await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['offline', odego]);
                    const servers = await pool.query('SELECT server_id FROM server_members WHERE user_id = $1', [odego]);
                    servers.rows.forEach(r => {
                        broadcastToServer(r.server_id, { 
                            type: 'USER_STATUS_CHANGE', 
                            visitorId: odego, 
                            status: 'offline' 
                        });
                    });
                }
            }
        }
    });

    ws.on('error', (error) => console.error('WebSocket error:', error));
});

// ============================================
// REST API - AUTH
// ============================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).json({ error: 'Все поля обязательны' });
        if (username.length < 3 || username.length > 32) return res.status(400).json({ error: 'Имя: 3-32 символа' });
        if (password.length < 6) return res.status(400).json({ error: 'Пароль: минимум 6 символов' });
        
        const existing = await pool.query('SELECT id FROM users WHERE email = $1 OR username = $2', [email.toLowerCase(), username]);
        if (existing.rows.length > 0) return res.status(400).json({ error: 'Email или имя уже используется' });
        
        const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const result = await pool.query(
            'INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, username, email, avatar_url, status, created_at',
            [uuidv4(), username, email.toLowerCase(), hash]
        );
        
        const token = jwt.sign({ id: result.rows[0].id, username }, JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({ token, user: result.rows[0] });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Заполните все поля' });
        
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
        if (!result.rows[0]) return res.status(401).json({ error: 'Неверные данные' });
        
        const valid = await bcrypt.compare(password, result.rows[0].password_hash);
        if (!valid) return res.status(401).json({ error: 'Неверные данные' });
        
        await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['online', result.rows[0].id]);
        const token = jwt.sign({ id: result.rows[0].id, username: result.rows[0].username }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({ 
            token, 
            user: { 
                id: result.rows[0].id, 
                username: result.rows[0].username, 
                email: result.rows[0].email, 
                avatar_url: result.rows[0].avatar_url, 
                status: 'online' 
            } 
        });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, email, avatar_url, status, created_at FROM users WHERE id = $1', [req.user.id]);
        if (!result.rows[0]) return res.status(404).json({ error: 'Не найден' });
        res.json(result.rows[0]);
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.put('/api/users/me/profile', authenticateToken, async (req, res) => {
    try {
        const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
        const avatarUrl = req.body.avatar_url;

        if (!username || username.length < 3 || username.length > 32) {
            return res.status(400).json({ error: 'Имя: 3-32 символа' });
        }

        let normalizedAvatar = null;
        if (avatarUrl === null || avatarUrl === '') {
            normalizedAvatar = null;
        } else if (typeof avatarUrl === 'string') {
            const isValidDataImage = /^data:image\/(png|jpeg|jpg|webp|gif);base64,[A-Za-z0-9+/=\s]+$/i.test(avatarUrl);
            if (!isValidDataImage) {
                return res.status(400).json({ error: 'Аватар должен быть изображением в формате base64 data URL' });
            }
            if (avatarUrl.length > 2_000_000) {
                return res.status(400).json({ error: 'Аватар слишком большой (максимум 2MB)' });
            }
            normalizedAvatar = avatarUrl;
        } else {
            return res.status(400).json({ error: 'Некорректный формат аватара' });
        }

        const existing = await pool.query('SELECT id FROM users WHERE username = $1 AND id != $2', [username, req.user.id]);
        if (existing.rows.length > 0) {
            return res.status(400).json({ error: 'Это имя уже занято' });
        }

        const updated = await pool.query(
            'UPDATE users SET username = $1, avatar_url = $2 WHERE id = $3 RETURNING id, username, email, avatar_url, status, created_at',
            [username, normalizedAvatar, req.user.id]
        );

        const token = jwt.sign({ id: updated.rows[0].id, username: updated.rows[0].username }, JWT_SECRET, { expiresIn: '7d' });

        res.json({ user: updated.rows[0], token });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ============================================
// REST API - SERVERS
// ============================================

app.get('/api/servers', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT s.*, sm.role as my_role FROM servers s JOIN server_members sm ON s.id = sm.server_id WHERE sm.user_id = $1 ORDER BY s.created_at DESC',
            [req.user.id]
        );
        const servers = await Promise.all(result.rows.map(async (s) => {
            const ch = await pool.query('SELECT * FROM channels WHERE server_id = $1 ORDER BY type DESC, position', [s.id]);
            const channels = ch.rows.map(channel => {
                if (channel.type === 'voice') {
                    channel.voiceParticipants = getVoiceRoomParticipants(channel.id);
                }
                return channel;
            });
            return { ...s, channels };
        }));
        res.json(servers);
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/servers', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const { name } = req.body;
        if (!name?.trim()) return res.status(400).json({ error: 'Название обязательно' });
        
        const serverId = uuidv4();
        const textChannelId = uuidv4();
        const voiceChannelId = uuidv4();
        const inviteCode = generateInviteCode();
        
        await client.query('INSERT INTO servers (id, name, owner_id, invite_code) VALUES ($1, $2, $3, $4)', [serverId, name.trim(), req.user.id, inviteCode]);
        await client.query('INSERT INTO server_members (id, server_id, user_id, role) VALUES ($1, $2, $3, $4)', [uuidv4(), serverId, req.user.id, 'owner']);
        await client.query('INSERT INTO channels (id, server_id, name, type, position) VALUES ($1, $2, $3, $4, $5)', [textChannelId, serverId, 'general', 'text', 0]);
        await client.query('INSERT INTO channels (id, server_id, name, type, position) VALUES ($1, $2, $3, $4, $5)', [voiceChannelId, serverId, 'Голосовой', 'voice', 0]);
        
        await client.query('COMMIT');
        
        const server = await pool.query('SELECT * FROM servers WHERE id = $1', [serverId]);
        const channels = await pool.query('SELECT * FROM channels WHERE server_id = $1 ORDER BY type DESC, position', [serverId]);
        res.status(201).json({ ...server.rows[0], channels: channels.rows });
    } catch (e) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: 'Ошибка сервера' });
    } finally {
        client.release();
    }
});

app.get('/api/servers/:serverId', authenticateToken, checkServerMembership, async (req, res) => {
    try {
        const server = await pool.query('SELECT * FROM servers WHERE id = $1', [req.params.serverId]);
        const channels = await pool.query('SELECT * FROM channels WHERE server_id = $1 ORDER BY type DESC, position', [req.params.serverId]);
        const members = await pool.query(
            'SELECT u.id, u.username, u.avatar_url, u.status, sm.role, sm.joined_at FROM server_members sm JOIN users u ON sm.user_id = u.id WHERE sm.server_id = $1',
            [req.params.serverId]
        );
        
        const channelsWithVoice = channels.rows.map(channel => {
            if (channel.type === 'voice') {
                channel.voiceParticipants = getVoiceRoomParticipants(channel.id);
            }
            return channel;
        });
        
        res.json({ ...server.rows[0], channels: channelsWithVoice, members: members.rows });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/servers/:serverId', authenticateToken, checkServerOwner, async (req, res) => {
    try {
        broadcastToServer(req.params.serverId, { type: 'SERVER_DELETED', serverId: req.params.serverId });
        await pool.query('DELETE FROM servers WHERE id = $1', [req.params.serverId]);
        res.json({ message: 'Удалено' });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/servers/join/:inviteCode', authenticateToken, async (req, res) => {
    try {
        const server = await pool.query('SELECT * FROM servers WHERE invite_code = $1', [req.params.inviteCode]);
        if (!server.rows[0]) return res.status(404).json({ error: 'Сервер не найден' });
        
        const existing = await pool.query('SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2', [server.rows[0].id, req.user.id]);
        if (existing.rows[0]) return res.status(400).json({ error: 'Вы уже участник' });
        
        await pool.query('INSERT INTO server_members (id, server_id, user_id, role) VALUES ($1, $2, $3, $4)', [uuidv4(), server.rows[0].id, req.user.id, 'member']);
        
        const channels = await pool.query('SELECT * FROM channels WHERE server_id = $1 ORDER BY type DESC, position', [server.rows[0].id]);
        const user = await pool.query('SELECT id, username, avatar_url, status FROM users WHERE id = $1', [req.user.id]);
        
        const channelsWithVoice = channels.rows.map(channel => {
            if (channel.type === 'voice') {
                channel.voiceParticipants = getVoiceRoomParticipants(channel.id);
            }
            return channel;
        });
        
        broadcastToServer(server.rows[0].id, { type: 'MEMBER_JOINED', serverId: server.rows[0].id, member: { ...user.rows[0], role: 'member' } });
        res.json({ ...server.rows[0], channels: channelsWithVoice });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/servers/:serverId/leave', authenticateToken, checkServerMembership, async (req, res) => {
    try {
        const server = await pool.query('SELECT owner_id FROM servers WHERE id = $1', [req.params.serverId]);
        if (server.rows[0].owner_id === req.user.id) return res.status(400).json({ error: 'Владелец не может покинуть' });
        
        await pool.query('DELETE FROM server_members WHERE server_id = $1 AND user_id = $2', [req.params.serverId, req.user.id]);
        broadcastToServer(req.params.serverId, { type: 'MEMBER_LEFT', serverId: req.params.serverId, visitorId: req.user.id });
        res.json({ message: 'Вы покинули сервер' });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/servers/:serverId/members', authenticateToken, checkServerMembership, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT u.id, u.username, u.avatar_url, u.status, sm.role, sm.joined_at FROM server_members sm JOIN users u ON sm.user_id = u.id WHERE sm.server_id = $1',
            [req.params.serverId]
        );
        res.json(result.rows);
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/servers/:serverId/invite', authenticateToken, checkServerMembership, async (req, res) => {
    try {
        const result = await pool.query('SELECT invite_code FROM servers WHERE id = $1', [req.params.serverId]);
        res.json({ invite_code: result.rows[0].invite_code });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ============================================
// REST API - CHANNELS
// ============================================

app.get('/api/servers/:serverId/channels', authenticateToken, checkServerMembership, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM channels WHERE server_id = $1 ORDER BY type DESC, position', [req.params.serverId]);
        const channels = result.rows.map(channel => {
            if (channel.type === 'voice') {
                channel.voiceParticipants = getVoiceRoomParticipants(channel.id);
            }
            return channel;
        });
        res.json(channels);
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/servers/:serverId/channels', authenticateToken, checkServerOwner, async (req, res) => {
    try {
        const { name, type = 'text' } = req.body;
        if (!name?.trim()) return res.status(400).json({ error: 'Название обязательно' });
        if (!['text', 'voice'].includes(type)) return res.status(400).json({ error: 'Неверный тип канала' });
        
        const formatted = name.trim().toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-_а-яё]/gi, '');
        const channelId = uuidv4();
        
        const pos = await pool.query('SELECT COALESCE(MAX(position), -1) + 1 as p FROM channels WHERE server_id = $1 AND type = $2', [req.params.serverId, type]);
        const result = await pool.query(
            'INSERT INTO channels (id, server_id, name, type, position) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [channelId, req.params.serverId, type === 'voice' ? name.trim() : formatted, type, pos.rows[0].p]
        );
        
        const channel = result.rows[0];
        if (channel.type === 'voice') {
            channel.voiceParticipants = [];
        }
        
        broadcastToServer(req.params.serverId, { type: 'CHANNEL_CREATED', channel });
        res.status(201).json(channel);
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/channels/:channelId', authenticateToken, async (req, res) => {
    try {
        const channel = await pool.query('SELECT * FROM channels WHERE id = $1', [req.params.channelId]);
        if (!channel.rows[0]) return res.status(404).json({ error: 'Не найден' });
        
        const server = await pool.query('SELECT owner_id FROM servers WHERE id = $1', [channel.rows[0].server_id]);
        if (server.rows[0].owner_id !== req.user.id) return res.status(403).json({ error: 'Нет прав' });
        
        const count = await pool.query('SELECT COUNT(*) as c FROM channels WHERE server_id = $1 AND type = $2', [channel.rows[0].server_id, channel.rows[0].type]);
        if (parseInt(count.rows[0].c) <= 1) return res.status(400).json({ error: 'Нельзя удалить последний канал' });
        
        if (channel.rows[0].type === 'voice') {
            const room = voiceRooms.get(req.params.channelId);
            if (room) {
                room.forEach((_, odego) => {
                    sendToUser(odego, { type: 'VOICE_KICKED', channelId: req.params.channelId, reason: 'Канал удален' });
                });
                voiceRooms.delete(req.params.channelId);
            }
        }
        
        await pool.query('DELETE FROM channels WHERE id = $1', [req.params.channelId]);
        broadcastToServer(channel.rows[0].server_id, { type: 'CHANNEL_DELETED', channelId: req.params.channelId, serverId: channel.rows[0].server_id });
        res.json({ message: 'Удалено' });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ============================================
// REST API - MESSAGES
// ============================================

app.get('/api/channels/:channelId/messages', authenticateToken, async (req, res) => {
    try {
        const { limit = 50 } = req.query;
        const channel = await pool.query('SELECT * FROM channels WHERE id = $1', [req.params.channelId]);
        if (!channel.rows[0]) return res.status(404).json({ error: 'Канал не найден' });
        
        const mem = await pool.query('SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2', [channel.rows[0].server_id, req.user.id]);
        if (!mem.rows[0]) return res.status(403).json({ error: 'Нет доступа' });
        
        const result = await pool.query(
            'SELECT m.*, u.username, u.avatar_url FROM messages m JOIN users u ON m.author_id = u.id WHERE m.channel_id = $1 ORDER BY m.created_at DESC LIMIT $2',
            [req.params.channelId, parseInt(limit)]
        );
        res.json(result.rows.reverse());
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/channels/:channelId/messages', authenticateToken, async (req, res) => {
    try {
        const { content, imageUrl } = req.body;
        const textContent = typeof content === 'string' ? content.trim() : '';
        const safeImageUrl = sanitizeInlineImage(imageUrl);
        if ((!textContent && !safeImageUrl) || textContent.length > 2000) return res.status(400).json({ error: 'Некорректное сообщение' });
        
        const channel = await pool.query('SELECT * FROM channels WHERE id = $1', [req.params.channelId]);
        if (!channel.rows[0]) return res.status(404).json({ error: 'Канал не найден' });
        
        const mem = await pool.query('SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2', [channel.rows[0].server_id, req.user.id]);
        if (!mem.rows[0]) return res.status(403).json({ error: 'Нет доступа' });
        
        const msgId = uuidv4();
        await pool.query('INSERT INTO messages (id, channel_id, author_id, content, image_url) VALUES ($1, $2, $3, $4, $5)', [msgId, req.params.channelId, req.user.id, textContent || null, safeImageUrl]);
        
        const result = await pool.query('SELECT m.*, u.username, u.avatar_url FROM messages m JOIN users u ON m.author_id = u.id WHERE m.id = $1', [msgId]);
        broadcastToServer(channel.rows[0].server_id, { type: 'NEW_CHANNEL_MESSAGE', message: result.rows[0] });
        res.status(201).json(result.rows[0]);
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ============================================
// REST API - DIRECT MESSAGES
// ============================================

app.get('/api/dm', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            WITH conversations AS (
                SELECT DISTINCT CASE WHEN sender_id = $1 THEN recipient_id ELSE sender_id END as user_id,
                MAX(created_at) as last_message_at FROM direct_messages WHERE sender_id = $1 OR recipient_id = $1
                GROUP BY CASE WHEN sender_id = $1 THEN recipient_id ELSE sender_id END
            )
            SELECT u.id, u.username, u.avatar_url, u.status, c.last_message_at FROM conversations c JOIN users u ON c.user_id = u.id ORDER BY c.last_message_at DESC
        `, [req.user.id]);
        res.json(result.rows);
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/dm/:odego', authenticateToken, async (req, res) => {
    try {
        const { limit = 50 } = req.query;
        const result = await pool.query(`
            SELECT dm.*, s.username as sender_username, s.avatar_url as sender_avatar, r.username as recipient_username, r.avatar_url as recipient_avatar
            FROM direct_messages dm JOIN users s ON dm.sender_id = s.id JOIN users r ON dm.recipient_id = r.id
            WHERE (dm.sender_id = $1 AND dm.recipient_id = $2) OR (dm.sender_id = $2 AND dm.recipient_id = $1)
            ORDER BY dm.created_at DESC LIMIT $3
        `, [req.user.id, req.params.odego, parseInt(limit)]);
        res.json(result.rows.reverse());
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/dm/:odego', authenticateToken, async (req, res) => {
    try {
        const { content, imageUrl } = req.body;
        const textContent = typeof content === 'string' ? content.trim() : '';
        const safeImageUrl = sanitizeInlineImage(imageUrl);
        if ((!textContent && !safeImageUrl) || textContent.length > 2000) return res.status(400).json({ error: 'Некорректное сообщение' });
        
        const recipient = await pool.query('SELECT id, username, avatar_url FROM users WHERE id = $1', [req.params.odego]);
        if (!recipient.rows[0]) return res.status(404).json({ error: 'Пользователь не найден' });
        
        const msgId = uuidv4();
        await pool.query('INSERT INTO direct_messages (id, sender_id, recipient_id, content, image_url) VALUES ($1, $2, $3, $4, $5)', [msgId, req.user.id, req.params.odego, textContent || null, safeImageUrl]);
        
        const sender = await pool.query('SELECT username, avatar_url FROM users WHERE id = $1', [req.user.id]);
        const msg = {
            id: msgId, sender_id: req.user.id, recipient_id: req.params.odego, content: textContent || null, image_url: safeImageUrl, created_at: new Date().toISOString(),
            sender_username: sender.rows[0].username, sender_avatar: sender.rows[0].avatar_url,
            recipient_username: recipient.rows[0].username, recipient_avatar: recipient.rows[0].avatar_url
        };
        
        sendToUser(req.user.id, { type: 'NEW_DIRECT_MESSAGE', message: msg });
        sendToUser(req.params.odego, { type: 'NEW_DIRECT_MESSAGE', message: msg });
        res.status(201).json(msg);
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ============================================
// REST API - USERS
// ============================================

app.get('/api/users/search', authenticateToken, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q || q.length < 2) return res.json([]);
        const result = await pool.query('SELECT id, username, avatar_url, status FROM users WHERE username ILIKE $1 AND id != $2 LIMIT 20', ['%' + q + '%', req.user.id]);
        res.json(result.rows);
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/users/:odego', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, avatar_url, status, created_at FROM users WHERE id = $1', [req.params.odego]);
        if (!result.rows[0]) return res.status(404).json({ error: 'Не найден' });
        res.json(result.rows[0]);
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ============================================
// ICE CONFIG ENDPOINT
// ============================================

app.get('/api/ice-config', authenticateToken, (req, res) => {
    res.json({ iceServers: ICE_SERVERS });
});



app.use((err, req, res, next) => {
    if (err && (err.type === 'entity.too.large' || err.status === 413)) {
        return res.status(413).json({ error: 'Файл аватара слишком большой. Попробуйте изображение меньшего размера.' });
    }
    return next(err);
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        let totalVoiceUsers = 0;
        voiceRooms.forEach(room => totalVoiceUsers += room.size);
        res.json({ 
            status: 'ok', 
            database: 'connected', 
            connections: clients.size,
            voiceRooms: voiceRooms.size,
            voiceUsers: totalVoiceUsers
        });
    } catch (e) {
        res.status(500).json({ status: 'error', database: 'disconnected' });
    }
});

// Главная страница
app.get('/', (req, res) => {
    res.send(getClientHTML());
});

// ============================================
// ЗАПУСК СЕРВЕРА
// ============================================

initializeDatabase().then(() => {
    server.listen(PORT, () => {
        console.log('🚀 Discord Clone запущен на порту ' + PORT);
    });
}).catch(err => {
    console.error('Failed to initialize:', err);
    process.exit(1);
});

// ============================================
// CLIENT HTML - ЧАСТЬ 1
// ============================================

function getClientHTML() {
    return `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Discord Clone</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #2b2d31;
            --bg-secondary: #24262b;
            --bg-tertiary: #1a1b1e;
            --bg-floating: #111214;
            --text-primary: #f2f3f5;
            --text-secondary: #b5bac1;
            --text-muted: #949ba4;
            --accent: #5865f2;
            --accent-hover: #4752c4;
            --green: #23a559;
            --red: #f23f43;
            --yellow: #f0b232;
            --channel-text: #80848e;
            --voice-connected: #194b31;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            height: 100vh;
            overflow: hidden;
        }
        .auth-container { display: flex; align-items: center; justify-content: center; height: 100vh; background: var(--bg-tertiary); }
        .auth-box { background: var(--bg-primary); padding: 36px; border-radius: 14px; width: 100%; max-width: 500px; box-shadow: 0 18px 44px rgba(0,0,0,0.35); }
        .auth-box h1 { text-align: center; margin-bottom: 8px; font-size: 24px; }
        .auth-box p { text-align: center; color: var(--text-secondary); margin-bottom: 20px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-secondary); }
        .form-group input, .form-group select { width: 100%; padding: 12px 14px; border: 1px solid rgba(255,255,255,0.06); border-radius: 8px; background: var(--bg-tertiary); color: var(--text-primary); font-size: 16px; transition: all 0.2s ease; }
        .form-group input:hover, .form-group select:hover { border-color: rgba(255,255,255,0.14); }
        .form-group input:focus, .form-group select:focus { outline: 2px solid var(--accent); }
        .btn { width: 100%; padding: 12px; border: none; border-radius: 8px; background: linear-gradient(180deg, #6774ff 0%, var(--accent) 100%); color: white; font-size: 16px; font-weight: 500; cursor: pointer; transition: all 0.2s ease; box-shadow: 0 6px 16px rgba(88,101,242,0.25); }
        .btn:hover { background: linear-gradient(180deg, #7280ff 0%, var(--accent-hover) 100%); transform: translateY(-1px); }
        .btn:disabled { background: var(--bg-tertiary); cursor: not-allowed; }
        .btn.secondary { background: transparent; color: var(--text-primary); }
        .btn.secondary:hover { background: var(--bg-tertiary); }
        .btn.danger { background: var(--red); }
        .btn.danger:hover { background: #d63636; }
        .auth-switch { text-align: center; margin-top: 16px; color: var(--text-secondary); font-size: 14px; }
        .auth-switch a { color: var(--accent); text-decoration: none; cursor: pointer; }
        .error-msg { background: rgba(242,63,67,0.1); border: 1px solid var(--red); color: var(--red); padding: 10px; border-radius: 4px; margin-bottom: 16px; font-size: 14px; }
        .app-container { display: flex; height: 100vh; }
        .server-list { width: 72px; background: var(--bg-tertiary); padding: 12px 0; display: flex; flex-direction: column; align-items: center; gap: 8px; overflow-y: auto; box-shadow: inset -1px 0 0 rgba(255,255,255,0.04); }
        .server-icon { width: 48px; height: 48px; border-radius: 50%; background: var(--bg-primary); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s; font-size: 18px; color: var(--text-primary); flex-shrink: 0; position: relative; }
        .server-icon:hover, .server-icon.active { border-radius: 16px; background: var(--accent); }
        .server-icon.add { color: var(--green); font-size: 24px; }
        .server-icon.add:hover { background: var(--green); color: white; border-radius: 16px; }
        .separator { width: 32px; height: 2px; background: var(--bg-secondary); border-radius: 1px; margin: 4px 0; }
        .channel-sidebar { width: 240px; background: var(--bg-secondary); display: flex; flex-direction: column; box-shadow: 2px 0 14px rgba(0,0,0,0.24); }
        .server-header { padding: 12px 16px; font-weight: 600; font-size: 16px; border-bottom: 1px solid var(--bg-tertiary); display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
        .server-header:hover { background: var(--bg-tertiary); }
        .channel-list { flex: 1; overflow-y: auto; padding: 8px 0; }
        .channel-category { padding: 16px 8px 4px 16px; font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--channel-text); display: flex; justify-content: space-between; align-items: center; }
        .channel-category button { background: none; border: none; color: var(--channel-text); cursor: pointer; font-size: 16px; padding: 2px 6px; border-radius: 4px; }
        .channel-category button:hover { color: var(--text-primary); background: var(--bg-tertiary); }
        .channel-item { display: flex; align-items: center; padding: 7px 10px; margin: 2px 8px; border-radius: 8px; cursor: pointer; color: var(--channel-text); gap: 8px; position: relative; transition: all 0.2s ease; }
        .channel-item:hover { background: var(--bg-tertiary); color: var(--text-secondary); }
        .channel-item.active { background: var(--bg-tertiary); color: var(--text-primary); }
        .channel-item.active::before { content: ''; position: absolute; left: -8px; top: 6px; bottom: 6px; width: 3px; border-radius: 3px; background: var(--accent); }
        .channel-item .icon { width: 20px; height: 20px; display: inline-flex; align-items: center; justify-content: center; }
        .channel-item .name { flex: 1; font-size: 15px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .channel-item .delete-btn { opacity: 0; background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 2px 6px; border-radius: 4px; font-size: 16px; }
        .channel-item:hover .delete-btn { opacity: 1; }
        .channel-item .delete-btn:hover { color: var(--red); background: rgba(242,63,67,0.1); }
        .voice-channel { margin: 3px 8px; border-radius: 8px; }
        .voice-channel .channel-item { margin: 0; }
        .voice-channel.has-users .channel-item { border-radius: 4px 4px 0 0; background: var(--bg-tertiary); }
        .voice-participants { background: var(--bg-tertiary); border-radius: 0 0 4px 4px; padding: 4px 0; }
        .voice-participant { display: flex; align-items: center; padding: 5px 8px 5px 32px; gap: 8px; font-size: 13px; color: var(--text-secondary); border: 1px solid transparent; border-radius: 8px; margin: 2px 4px; transition: all 0.2s ease; }
        .voice-participant:hover { border-color: rgba(255,255,255,0.08); background: rgba(255,255,255,0.02); }
        .voice-participant .avatar { width: 24px; height: 24px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 10px; font-weight: 600; transition: box-shadow 0.15s ease; position: relative; }
        .avatar-image { width: 100%; height: 100%; object-fit: cover; border-radius: 50%; }
        .voice-participant .name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .voice-participant .status-icons { display: flex; gap: 4px; font-size: 12px; }
        .voice-participant.speaking .avatar { box-shadow: 0 0 0 2px var(--green); }
        .voice-participant .mute-icon, .voice-participant .deafen-icon { color: var(--red); }
        .voice-participant .stream-icon { color: var(--accent); }
        .voice-participant .conn-status { font-size: 10px; padding: 2px 4px; border-radius: 3px; }
        .voice-participant .conn-status.connected { background: var(--green); color: white; }
        .voice-participant .conn-status.connecting { background: var(--yellow); color: black; }
        .voice-participant .conn-status.failed { background: var(--red); color: white; }
        .user-panel { padding: 8px; background: var(--bg-tertiary); display: flex; align-items: center; gap: 8px; }
        .user-panel .avatar { width: 32px; height: 32px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; font-weight: 600; font-size: 12px; transition: box-shadow 0.15s ease; }
        .user-panel .avatar.speaking { box-shadow: 0 0 0 3px var(--green); }
        .user-panel .info { flex: 1; min-width: 0; }
        .user-panel .username { font-size: 14px; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .user-panel .status { font-size: 12px; color: var(--text-muted); }
        .user-panel .actions { display: flex; gap: 4px; }
        .user-panel .actions button { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 6px; border-radius: 4px; font-size: 16px; }
        .user-panel .actions button:hover { background: var(--bg-secondary); color: var(--text-primary); }
        .user-panel .actions button.muted { color: var(--red); }
        .voice-connected { background: var(--voice-connected); border-bottom: 1px solid var(--bg-primary); padding: 8px; }
        .voice-connected .voice-status { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
        .voice-connected .voice-status .indicator { width: 8px; height: 8px; border-radius: 50%; background: var(--green); animation: pulse 2s infinite; }
        .voice-connected .voice-status .indicator.relay { background: var(--yellow); }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .voice-connected .voice-status .text { flex: 1; }
        .voice-connected .voice-status .text .title { font-size: 13px; font-weight: 600; color: var(--green); }
        .voice-connected .voice-status .text .title.relay { color: var(--yellow); }
        .voice-connected .voice-status .text .channel { font-size: 12px; color: var(--text-secondary); }
        .voice-connected .voice-controls { display: flex; gap: 8px; flex-wrap: wrap; }
        .voice-connected .voice-controls button { flex: 1; min-width: 44px; padding: 10px; border: none; border-radius: 8px; background: rgba(0,0,0,0.2); color: var(--text-primary); cursor: pointer; font-size: 14px; transition: all 0.2s ease; }
        .voice-connected .voice-controls button:hover { background: rgba(0,0,0,0.4); }
        .voice-connected .voice-controls button.active { color: var(--red); background: rgba(242,63,67,0.3); }
        .voice-connected .voice-controls .disconnect { background: rgba(242,63,67,0.3); color: var(--red); }
        .voice-connected .voice-controls .disconnect:hover { background: var(--red); color: white; }
        .voice-connected .voice-controls .screen-share { background: rgba(88,101,242,0.3); color: var(--accent); }
        .voice-connected .voice-controls .screen-share:hover { background: var(--accent); color: white; }
        .voice-connected .voice-controls .screen-share.active { background: var(--accent); color: white; }
        .chat-area { flex: 1; display: flex; flex-direction: column; background: var(--bg-primary); min-width: 0; }
        .chat-header { padding: 12px 16px; border-bottom: 1px solid var(--bg-tertiary); display: flex; align-items: center; gap: 8px; font-weight: 600; flex-shrink: 0; }
        .chat-header .icon { color: var(--channel-text); }
        .messages-container { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 16px; }
        .message { display: flex; gap: 16px; padding: 6px 16px; border-radius: 8px; transition: background 0.2s ease; }
        .message:hover { background: rgba(255,255,255,0.02); }
        .message .avatar { width: 40px; height: 40px; border-radius: 50%; background: var(--accent); flex-shrink: 0; display: flex; align-items: center; justify-content: center; font-weight: 600; font-size: 14px; }
        .message .content { flex: 1; min-width: 0; }
        .message .header { display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; }
        .message .author { font-weight: 500; color: var(--text-primary); }
        .message .timestamp { font-size: 11px; color: #777d86; }
        .message .text { color: var(--text-secondary); word-wrap: break-word; line-height: 1.4; }
        .message .attachment { margin-top: 8px; border-radius: 10px; max-width: min(420px, 100%); max-height: 320px; object-fit: cover; border: 1px solid rgba(255,255,255,0.1); }
        .message-input-container { padding: 0 16px 24px; flex-shrink: 0; }
        .message-input { display: flex; align-items: center; gap: 8px; background: #3a3d44; border-radius: 10px; padding: 0 12px; min-height: 44px; box-shadow: inset 0 0 0 1px rgba(255,255,255,0.05); }
        .message-input input { flex: 1; background: none; border: none; padding: 12px 0; color: var(--text-primary); font-size: 16px; }
        .message-input input:focus { outline: none; }
        .message-input input::placeholder { color: var(--text-muted); }
        .message-input button { background: rgba(88,101,242,0.15); border: none; color: var(--accent); cursor: pointer; padding: 10px; font-size: 18px; border-radius: 8px; width: 38px; height: 38px; transition: all 0.2s ease; }
        .message-input button:hover { background: rgba(88,101,242,0.35); color: #fff; }
        .message-input button.attach-btn { color: var(--text-secondary); background: rgba(255,255,255,0.1); }
        .message-input button.attach-btn:hover { color: #fff; background: rgba(255,255,255,0.2); }
        .attachment-preview { margin: 0 16px 10px; padding: 10px; background: rgba(255,255,255,0.04); border-radius: 8px; border: 1px solid rgba(255,255,255,0.06); display: flex; align-items: center; gap: 12px; }
        .attachment-preview img { width: 64px; height: 64px; object-fit: cover; border-radius: 8px; }
        .attachment-preview .meta { flex: 1; color: var(--text-secondary); font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .attachment-preview button { border: none; background: rgba(242,63,67,0.15); color: var(--red); border-radius: 6px; cursor: pointer; width: 28px; height: 28px; }
        .typing-indicator { font-size: 12px; color: var(--text-muted); padding: 6px 16px; min-height: 24px; display: flex; align-items: center; gap: 6px; }
        .typing-indicator .dots { display: inline-flex; gap: 4px; }
        .typing-indicator .dot { width: 5px; height: 5px; border-radius: 50%; background: var(--text-muted); animation: typingBlink 1.2s infinite; }
        .typing-indicator .dot:nth-child(2) { animation-delay: 0.2s; }
        .typing-indicator .dot:nth-child(3) { animation-delay: 0.4s; }
        @keyframes typingBlink { 0%, 80%, 100% { opacity: 0.2; transform: translateY(0); } 40% { opacity: 1; transform: translateY(-2px); } }
        .members-sidebar { width: 240px; background: var(--bg-secondary); padding: 16px 8px; overflow-y: auto; }
        .members-category { padding: 8px; font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--channel-text); }
        .member-item { display: flex; align-items: center; padding: 6px 8px; border-radius: 4px; cursor: pointer; gap: 12px; }
        .member-item:hover { background: var(--bg-tertiary); }
        .member-item .avatar { width: 32px; height: 32px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; position: relative; font-size: 12px; font-weight: 600; }
        .member-item .avatar .status-dot { position: absolute; bottom: -2px; right: -2px; width: 12px; height: 12px; border-radius: 50%; border: 3px solid var(--bg-secondary); }
        .member-item .avatar .status-dot.online { background: var(--green); }
        .member-item .avatar .status-dot.offline { background: var(--text-muted); }
        .member-item .name { font-size: 15px; color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
        .member-item .voice-icon { font-size: 14px; color: var(--green); }
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.88); display: flex; align-items: center; justify-content: center; z-index: 1000; animation: modalFade 0.2s ease; }
        .modal { background: var(--bg-primary); border-radius: 14px; width: 100%; max-width: 480px; max-height: 90vh; overflow: hidden; box-shadow: 0 22px 48px rgba(0,0,0,0.56); animation: modalPop 0.2s ease; }
        @keyframes modalFade { from { opacity: 0; } to { opacity: 1; } }
        @keyframes modalPop { from { opacity: 0; transform: translateY(8px) scale(0.98); } to { opacity: 1; transform: translateY(0) scale(1); } }
        .modal-header { padding: 16px; text-align: center; }
        .modal-header h2 { font-size: 20px; margin-bottom: 8px; }
        .modal-header p { color: var(--text-secondary); font-size: 14px; }
        .modal-close { position: absolute; top: 10px; right: 10px; width: 32px; height: 32px; border: none; border-radius: 8px; background: transparent; color: var(--text-muted); cursor: pointer; transition: all 0.2s ease; }
        .modal-close:hover { background: var(--bg-tertiary); color: var(--text-primary); }
        .modal-body { padding: 0 16px 16px; max-height: 60vh; overflow-y: auto; }
        .modal-footer { padding: 16px; background: var(--bg-secondary); display: flex; justify-content: flex-end; gap: 8px; }
        .modal-footer .btn { width: auto; padding: 10px 24px; }
        .modal-tabs { display: flex; margin-bottom: 16px; }
        .modal-tabs button { flex: 1; padding: 12px; background: var(--bg-secondary); border: none; color: var(--text-secondary); cursor: pointer; font-size: 14px; }
        .modal-tabs button:first-child { border-radius: 4px 0 0 4px; }
        .modal-tabs button:last-child { border-radius: 0 4px 4px 0; }
        .modal-tabs button.active { background: var(--accent); color: white; }
        .invite-code { background: var(--bg-tertiary); padding: 12px; border-radius: 4px; font-family: monospace; font-size: 18px; text-align: center; margin: 16px 0; user-select: all; }
        .screen-settings { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 16px; }
        .screen-settings .setting-group { display: flex; flex-direction: column; gap: 4px; }
        .screen-settings label { font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--text-secondary); }
        .screen-settings select { padding: 8px; border: none; border-radius: 4px; background: var(--bg-tertiary); color: var(--text-primary); font-size: 14px; }
        .voice-grid-overlay { position: fixed; top: 0; left: 72px; right: 0; bottom: 0; background: var(--bg-floating); z-index: 100; display: flex; flex-direction: column; }
        .voice-grid-header { padding: 16px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--bg-tertiary); }
        .voice-grid-header h3 { font-size: 16px; }
        .voice-grid-header .close-btn { background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 24px; padding: 4px 8px; border-radius: 4px; }
        .voice-grid-header .close-btn:hover { background: var(--bg-tertiary); color: var(--text-primary); }
        .voice-grid-container { flex: 1; padding: 16px; overflow-y: auto; display: flex; flex-wrap: wrap; gap: 16px; justify-content: center; align-content: center; }
        .voice-grid-item { width: 200px; height: 200px; background: var(--bg-tertiary); border-radius: 10px; border: 1px solid rgba(255,255,255,0.08); display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; position: relative; cursor: pointer; transition: all 0.2s ease; }
        .voice-grid-item:hover { background: var(--bg-secondary); }
        .voice-grid-item.speaking { box-shadow: 0 0 0 3px var(--green); }
        .voice-grid-item.streaming { width: 400px; height: 300px; }
        .voice-grid-item .avatar { width: 80px; height: 80px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 32px; font-weight: 600; }
        .voice-grid-item .username { font-size: 14px; font-weight: 500; }
        .voice-grid-item .status-icons { position: absolute; bottom: 8px; right: 8px; display: flex; gap: 4px; }
        .voice-grid-item .status-icons span { font-size: 16px; }
        .voice-grid-item video { width: 100%; height: 100%; object-fit: contain; border-radius: 8px; }
        .voice-grid-item.focused { position: fixed; top: 60px; left: 80px; right: 8px; bottom: 8px; width: auto; height: auto; z-index: 200; }
        .dm-sidebar { width: 240px; background: var(--bg-secondary); display: flex; flex-direction: column; box-shadow: 2px 0 14px rgba(0,0,0,0.24); }
        .dm-header { padding: 12px 16px; border-bottom: 1px solid var(--bg-tertiary); }
        .dm-search { width: 100%; padding: 8px; border: none; border-radius: 4px; background: var(--bg-tertiary); color: var(--text-primary); font-size: 14px; }
        .dm-list { flex: 1; overflow-y: auto; padding: 8px; }
        .dm-item { display: flex; align-items: center; padding: 8px; border-radius: 4px; cursor: pointer; gap: 12px; margin-bottom: 2px; }
        .dm-item:hover, .dm-item.active { background: var(--bg-tertiary); }
        .dm-item .avatar { width: 32px; height: 32px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 600; }
        .dm-item .name { flex: 1; font-size: 15px; color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .empty-state { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: var(--text-muted); text-align: center; padding: 32px; }
        .empty-state .icon { width: 64px; height: 64px; margin-bottom: 16px; opacity: 0.65; color: var(--text-muted); }
        .empty-state h3 { margin-bottom: 8px; color: var(--text-primary); }
        .audio-select { width: 100%; padding: 10px; border: none; border-radius: 4px; background: var(--bg-tertiary); color: var(--text-primary); font-size: 14px; cursor: pointer; }
        .audio-select:focus { outline: 2px solid var(--accent); }
        .mic-test { margin-top: 8px; }
        .mic-level-bar { width: 100%; height: 20px; background: var(--bg-tertiary); border-radius: 4px; overflow: hidden; }
        .mic-level-fill { height: 100%; width: 0%; background: var(--green); transition: width 0.1s ease, background 0.2s ease; border-radius: 4px; }
        .profile-editor { display: grid; gap: 12px; }
        .profile-avatar-preview { width: 96px; height: 96px; border-radius: 50%; background: var(--bg-tertiary); display: flex; align-items: center; justify-content: center; font-size: 28px; font-weight: 700; overflow: hidden; margin: 0 auto; }
        .profile-help { font-size: 12px; color: var(--text-muted); }
        .ui-icon { width: 18px; height: 18px; display: inline-flex; align-items: center; justify-content: center; color: currentColor; }
        .ui-icon svg { width: 100%; height: 100%; fill: currentColor; }
        ::-webkit-scrollbar { width: 11px; height: 11px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #3f424a; border-radius: 10px; border: 2px solid transparent; background-clip: padding-box; }
        .debug-panel { position: fixed; bottom: 10px; right: 10px; background: rgba(0,0,0,0.95); color: #0f0; padding: 10px; font-family: monospace; font-size: 10px; max-width: 400px; max-height: 300px; overflow-y: auto; border-radius: 4px; z-index: 9999; display: none; }
        .debug-toggle-btn { position: fixed; bottom: 10px; right: 10px; z-index: 10000; border: none; border-radius: 8px; background: rgba(17,18,20,0.9); color: var(--text-secondary); cursor: pointer; padding: 6px 10px; font-size: 12px; }
        .debug-toggle-btn:hover { color: #fff; }
        .debug-panel.show { display: block; }
        .debug-panel .error { color: #f55; }
        .debug-panel .warn { color: #fa0; }
        .debug-panel .success { color: #0f0; }
        @media (max-width: 900px) { .members-sidebar { display: none; } }
        @media (max-width: 600px) { .channel-sidebar, .dm-sidebar { width: 200px; } }
    </style>
</head>
<body>
<div id="app"></div>
<button id="debugToggleBtn" class="debug-toggle-btn" type="button">Логи</button>
<div id="debugPanel" class="debug-panel"></div>
<script>
(function() {
    'use strict';

    var API_URL = window.location.origin;
    var WS_URL = (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + window.location.host;

    var currentUser = null;
    var token = null;
    var ws = null;
    var servers = [];
    var currentServer = null;
    var currentChannel = null;
    var currentDM = null;
    var messages = [];
    var typingUsers = {};
    var reconnectAttempts = 0;
    var wsReconnectTimer = null;

    // Voice state
    var localStream = null;
    var screenStream = null;
    var peerConnections = new Map();
    var screenPeerConnections = new Map();
    var currentVoiceChannel = null;
    var pendingVoiceRejoin = null; // НОВОЕ: канал для переподключения после WS reconnect
    var voiceParticipants = new Map();
    var isMuted = false;
    var isDeafened = false;
    var isScreenSharing = false;
    var pendingCandidates = new Map();
    var screenPendingCandidates = new Map(); // НОВОЕ: буфер кандидатов для screen PC
    var speakingUsers = new Set();
    var audioContext = null;
    var localAnalyser = null;
    var connectionStates = new Map();
    var usingRelay = false;
    var showVoiceGrid = false;
    var focusedStream = null;
    var remoteStreams = new Map();
    var iceServersConfig = null; // НОВОЕ: кешированная конфигурация ICE

    var screenShareSettings = { resolution: '720', frameRate: 30 };
    var selectedMicId = localStorage.getItem('selectedMicId') || '';
    var selectedOutputId = localStorage.getItem('selectedOutputId') || '';

    var debugMode = true;
    var isDebugPanelVisible = true;
    var debugLog = [];
    var pendingAttachment = null;
    var pendingAttachmentName = '';
    var micTestStream = null;
    var micTestInterval = null;
    var micTestCtx = null;

    // ============================================
    // УТИЛИТЫ
    // ============================================

    function debug(msg, type) {
        if (!debugMode) return;
        var time = new Date().toLocaleTimeString();
        var cls = type || '';
        var entry = '<span class="' + cls + '">[' + time + '] ' + msg + '</span>';
        debugLog.push(entry);
        if (debugLog.length > 150) debugLog.shift();
        console.log('[DEBUG][' + time + '] ' + msg);
        var panel = document.getElementById('debugPanel');
        if (panel) { panel.innerHTML = debugLog.join('<br>'); panel.scrollTop = panel.scrollHeight; }
    }

    function $(s) { return document.querySelector(s); }
    function $$(s) { return document.querySelectorAll(s); }
    function escapeHtml(t) { var d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

    function icon(name, cls) {
        var icons = {
            home: '<path d="M12 3l9 8h-3v10h-5v-6H11v6H6V11H3z"/>',
            plus: '<path d="M11 4h2v7h7v2h-7v7h-2v-7H4v-2h7z"/>',
            hash: '<path d="M9 3L7.8 8h4.2L13.2 3h2.1L14.1 8H19v2h-5.3l-1 5H17v2h-4.7L11 22H8.9l1.3-5H6l-1.3 5H2.6L3.9 17H0v-2h4.3l1-5H1V8h4.7L7 3zM8.2 10l-1 5h4.2l1-5z"/>',
            voice: '<path d="M12 14a4 4 0 004-4V5a4 4 0 10-8 0v5a4 4 0 004 4zm-7-4h2a5 5 0 0010 0h2a7 7 0 01-6 6.92V20h3v2H8v-2h3v-3.08A7 7 0 015 10z"/>',
            send: '<path d="M3 11.5L21 3l-5.7 18-3.6-6.9L3 11.5zm3.6.1l4.2 1.7 2.2 4.3 3.1-9.8-9.5 3.8z"/>',
            attach: '<path d="M16.5 6.5l-7.8 7.8a3 3 0 104.2 4.2l8.5-8.5a5 5 0 00-7.1-7.1L5.8 11.4a7 7 0 109.9 9.9l6.4-6.4-1.4-1.4-6.4 6.4a5 5 0 11-7.1-7.1l8.5-8.5a3 3 0 114.2 4.2l-8.5 8.5a1 1 0 11-1.4-1.4l7.8-7.8-1.4-1.4z"/>',
            close: '<path d="M18.3 5.7l-1.4-1.4L12 9.2 7.1 4.3 5.7 5.7 10.6 10.6 5.7 15.5l1.4 1.4 4.9-4.9 4.9 4.9 1.4-1.4-4.9-4.9z"/>',
            at: '<path d="M12 4a8 8 0 100 16c1.7 0 3.2-.5 4.4-1.3l-1.1-1.6A5.9 5.9 0 0112 18a6 6 0 116-6v1.5a1.5 1.5 0 01-3 0V12a3 3 0 10-1.1 2.3A3.5 3.5 0 0019.5 13V12A7.5 7.5 0 0012 4zm0 6a1.5 1.5 0 110 3 1.5 1.5 0 010-3z"/>',
            settings: '<path d="M19.4 13a7.8 7.8 0 000-2l2-1.5-2-3.4-2.4 1a7.4 7.4 0 00-1.7-1l-.3-2.6h-4l-.3 2.6a7.4 7.4 0 00-1.7 1l-2.4-1-2 3.4 2 1.5a7.8 7.8 0 000 2l-2 1.5 2 3.4 2.4-1c.5.4 1.1.7 1.7 1l.3 2.6h4l.3-2.6c.6-.3 1.2-.6 1.7-1l2.4 1 2-3.4-2-1.5zM12 15a3 3 0 110-6 3 3 0 010 6z"/>',
            logout: '<path d="M16 17l1.4-1.4L14.8 13H21v-2h-6.2l2.6-2.6L16 7l-5 5 5 5zM3 5h8V3H3a2 2 0 00-2 2v14a2 2 0 002 2h8v-2H3z"/>',
            users: '<path d="M8 11a4 4 0 100-8 4 4 0 000 8zm8 2a3 3 0 100-6 3 3 0 000 6zM8 13c-3.3 0-6 1.8-6 4v3h12v-3c0-2.2-2.7-4-6-4zm8 1c-.9 0-1.8.1-2.6.4 1 .8 1.6 1.8 1.6 2.9V20h7v-2c0-2.2-2.7-4-6-4z"/>',
            video: '<path d="M4 6h10a2 2 0 012 2v8a2 2 0 01-2 2H4a2 2 0 01-2-2V8a2 2 0 012-2zm14 4l4-3v10l-4-3V10z"/>',
            muted: '<path d="M3 10h3l4-4v12l-4-4H3v-4zm10.6-.6L16 12l-2.4 2.6 1.4 1.4L17.4 13l2.6 2.6 1.4-1.4-2.6-2.6 2.6-2.6-1.4-1.4-2.6 2.6-2.4-2.6z"/>',
            deafen: '<path d="M12 3a4 4 0 00-4 4v5a4 4 0 108 0V7a4 4 0 00-4-4zm-7 7h2a5 5 0 0010 0h2a7 7 0 01-5 6.7V19h3v2H7v-2h3v-2.3A7 7 0 015 10zm14.3 8.3l-1.4 1.4-2.6-2.6-2.6 2.6-1.4-1.4 2.6-2.6-2.6-2.6 1.4-1.4 2.6 2.6 2.6-2.6 1.4 1.4-2.6 2.6 2.6 2.6z"/>',
            unmute: '<path d="M3 10h3l4-4v12l-4-4H3v-4zm10-3l6 6m0-6l-6 6"/>',
            message: '<path d="M4 4h16a2 2 0 012 2v9a2 2 0 01-2 2H8l-4 3v-3H4a2 2 0 01-2-2V6a2 2 0 012-2z"/>'
        };
        return '<span class="ui-icon ' + (cls || '') + '"><svg viewBox="0 0 24 24" aria-hidden="true">' + (icons[name] || '') + '</svg></span>';
    }
    function getInitials(n) { return n ? n.substring(0, 2).toUpperCase() : '??'; }
    function renderAvatarContent(name, avatarUrl) {
        if (avatarUrl) return '<img class="avatar-image" src="' + escapeHtml(avatarUrl) + '" alt="avatar">';
        return escapeHtml(getInitials(name));
    }
    function formatTime(d) {
        var dt = new Date(d), now = new Date();
        var t = dt.toLocaleTimeString('ru-RU', {hour:'2-digit',minute:'2-digit'});
        return dt.toDateString() === now.toDateString() ? 'Сегодня ' + t : dt.toLocaleDateString('ru-RU') + ' ' + t;
    }

    function updateDebugPanelVisibility() {
        var panel = document.getElementById('debugPanel');
        var btn = document.getElementById('debugToggleBtn');
        var shouldShow = debugMode && isDebugPanelVisible;
        if (panel) panel.classList.toggle('show', shouldShow);
        if (btn) btn.textContent = shouldShow ? 'Свернуть логи' : 'Показать логи';
    }

    function clearPendingAttachment() {
        pendingAttachment = null;
        pendingAttachmentName = '';
        renderAttachmentPreview();
    }

    function renderAttachmentPreview() {
        var preview = document.getElementById('attachmentPreview');
        if (!preview) return;
        if (!pendingAttachment) {
            preview.innerHTML = '';
            preview.style.display = 'none';
            return;
        }
        preview.style.display = 'flex';
        preview.innerHTML = '<img src="' + escapeHtml(pendingAttachment) + '" alt="attachment preview">' +
            '<div class="meta">' + escapeHtml(pendingAttachmentName || 'Изображение готово к отправке') + '</div>' +
            '<button id="clearAttachmentBtn" type="button" title="Убрать">' + icon('close') + '</button>';
        var clearBtn = document.getElementById('clearAttachmentBtn');
        if (clearBtn) clearBtn.onclick = clearPendingAttachment;
    }

    function api(endpoint, opts) {
        opts = opts || {};
        var h = { 'Content-Type': 'application/json' };
        if (token) h['Authorization'] = 'Bearer ' + token;
        return fetch(API_URL + endpoint, Object.assign({}, opts, { headers: h })).then(function(r) {
            return r.json().then(function(d) {
                if (!r.ok) throw new Error(d.error || 'Ошибка');
                return d;
            });
        });
    }

    // ============================================
    // ICE SERVERS - ЗАГРУЗКА С СЕРВЕРА + FALLBACK
    // ============================================

    // ИСПРАВЛЕНИЕ 1: Загрузка ICE-конфига с сервера с fallback на встроенный список.
    // Это гарантирует актуальность credentials и позволяет менять TURN без деплоя.
    function getIceServers() {
        if (iceServersConfig) return iceServersConfig;
        return getBuiltinIceServers();
    }

    function getBuiltinIceServers() {
        return [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' },
            {
                urls: 'turn:195.133.53.53:3478',
                username: 'discordclone',
                credential: 'ТвойСильныйПароль123!'
            },
            {
                urls: 'turn:195.133.53.53:3478?transport=tcp',
                username: 'discordclone',
                credential: 'ТвойСильныйПароль123!'
            }
        ];
    }

    function loadIceConfig() {
        return api('/api/ice-config').then(function(data) {
            if (data && data.iceServers && data.iceServers.length) {
                iceServersConfig = data.iceServers;
                debug('ICE config loaded from server: ' + data.iceServers.length + ' servers', 'success');
            }
        }).catch(function(e) {
            debug('ICE config load failed, using builtin: ' + e.message, 'warn');
        });
    }

    function shouldInitiate(myId, peerId) {
        return myId < peerId;
    }

    // ============================================
    // WEBSOCKET
    // ============================================

    function connectWebSocket() {
        if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
        debug('Connecting WS...', 'warn');
        ws = new WebSocket(WS_URL);

        ws.onopen = function() {
            debug('WS connected', 'success');
            reconnectAttempts = 0;
            if (token) ws.send(JSON.stringify({ type: 'AUTH', token: token }));
        };

        ws.onmessage = function(e) {
            try { handleWsMessage(JSON.parse(e.data)); } catch(err) { debug('WS parse error: ' + err, 'error'); }
        };

        ws.onclose = function() {
            debug('WS disconnected', 'error');

            // ИСПРАВЛЕНИЕ 2: При потере WS сохраняем канал для переподключения,
            // но не уничтожаем localStream — он понадобится при восстановлении.
            if (currentVoiceChannel) {
                pendingVoiceRejoin = {
                    channelId: currentVoiceChannel.id,
                    channelName: currentVoiceChannel.name
                };
                // Закрываем только peer connections, но не останавливаем localStream
                peerConnections.forEach(function(pc, uid) {
                    pc.close();
                    var a = document.getElementById('audio-' + uid);
                    if (a) { a.srcObject = null; a.remove(); }
                });
                peerConnections.clear();
                screenPeerConnections.forEach(function(pc) { pc.close(); });
                screenPeerConnections.clear();
                pendingCandidates.clear();
                screenPendingCandidates.clear();
                connectionStates.clear();
                remoteStreams.clear();
                speakingUsers.clear();
                voiceParticipants.clear();
                currentVoiceChannel = null;
                render();
            }

            if (reconnectAttempts < 10 && token) {
                reconnectAttempts++;
                var delay = Math.min(1000 * reconnectAttempts, 8000);
                debug('Reconnecting in ' + delay + 'ms (attempt ' + reconnectAttempts + ')', 'warn');
                wsReconnectTimer = setTimeout(connectWebSocket, delay);
            }
        };

        ws.onerror = function(e) { debug('WS error', 'error'); };
    }

    function handleWsMessage(d) {
        if (d.type !== 'PONG') debug('WS: ' + d.type);

        switch(d.type) {
            case 'AUTH_SUCCESS':
                debug('Auth OK: ' + d.username, 'success');
                // ИСПРАВЛЕНИЕ 3: После переавторизации переподключаемся к голосовому каналу.
                if (pendingVoiceRejoin && localStream) {
                    var rejoin = pendingVoiceRejoin;
                    pendingVoiceRejoin = null;
                    debug('Rejoining voice channel after WS reconnect: ' + rejoin.channelId, 'warn');
                    ws.send(JSON.stringify({ type: 'VOICE_JOIN', channelId: rejoin.channelId }));
                }
                break;
            case 'NEW_CHANNEL_MESSAGE':
                if (currentChannel && d.message.channel_id === currentChannel.id) {
                    messages.push(d.message); renderMessages(); scrollToBottom();
                }
                break;
            case 'NEW_DIRECT_MESSAGE':
                if (currentDM && (d.message.sender_id === currentDM.id || d.message.recipient_id === currentDM.id)) {
                    messages.push(d.message); renderMessages(); scrollToBottom();
                }
                break;
            case 'USER_TYPING': handleTyping(d); break;
            case 'USER_STATUS_CHANGE': updateUserStatus(d.visitorId, d.status); break;
            case 'CHANNEL_CREATED':
                if (currentServer && d.channel.server_id === currentServer.id) {
                    currentServer.channels.push(d.channel); renderChannels();
                }
                break;
            case 'CHANNEL_DELETED':
                if (currentServer && d.serverId === currentServer.id) {
                    currentServer.channels = currentServer.channels.filter(function(c) { return c.id !== d.channelId; });
                    if (currentChannel && currentChannel.id === d.channelId) {
                        currentChannel = currentServer.channels.find(function(c) { return c.type === 'text'; });
                        if (currentChannel) loadMessages();
                    }
                    renderChannels();
                }
                break;
            case 'MEMBER_JOINED':
                if (currentServer && currentServer.id === d.serverId) {
                    if (!currentServer.members) currentServer.members = [];
                    currentServer.members.push(d.member);
                    renderMembers();
                }
                break;
            case 'MEMBER_LEFT':
                if (currentServer && currentServer.id === d.serverId && currentServer.members) {
                    currentServer.members = currentServer.members.filter(function(m) { return m.id !== d.visitorId; });
                    renderMembers();
                }
                break;
            case 'SERVER_DELETED':
                servers = servers.filter(function(s) { return s.id !== d.serverId; });
                if (currentServer && currentServer.id === d.serverId) { currentServer = null; currentChannel = null; }
                render();
                break;
            case 'VOICE_JOINED': handleVoiceJoined(d); break;
            case 'VOICE_LEFT': handleVoiceLeft(d); break;
            case 'VOICE_USER_JOINED': handleVoiceUserJoined(d); break;
            case 'VOICE_USER_LEFT': handleVoiceUserLeft(d); break;
            case 'VOICE_SIGNAL': handleVoiceSignal(d); break;
            case 'VOICE_USER_MUTE': case 'VOICE_USER_DEAFEN': handleVoiceMuteDeafen(d); break;
            case 'VOICE_STATE_UPDATE': handleVoiceStateUpdate(d); break;
            case 'VOICE_SPEAKING': handleVoiceSpeaking(d); break;
            case 'VOICE_STREAM_START': handleStreamStart(d); break;
            case 'VOICE_STREAM_STOP': handleStreamStop(d); break;
            case 'VOICE_ERROR':
                alert('Ошибка голоса: ' + d.error);
                cleanupVoice(); currentVoiceChannel = null; render();
                break;
            case 'VOICE_KICKED':
                alert('Вы были отключены: ' + (d.reason || 'Канал удален'));
                cleanupVoice(); currentVoiceChannel = null; render();
                break;
        }
    }

    function handleTyping(d) {
        var k = d.channelId || d.visitorId;
        typingUsers[k] = { username: d.username, time: Date.now() };
        renderTypingIndicator();
        setTimeout(function() {
            if (typingUsers[k] && Date.now() - typingUsers[k].time > 3000) {
                delete typingUsers[k]; renderTypingIndicator();
            }
        }, 3500);
    }

    function renderTypingIndicator() {
        var el = $('.typing-indicator'); if (!el) return;
        var k = currentChannel ? currentChannel.id : (currentDM ? currentDM.id : null);
        var t = typingUsers[k];
        if (t && t.username !== currentUser.username) {
            el.innerHTML = '<span>' + escapeHtml(t.username) + ' печатает</span><span class="dots"><span class="dot"></span><span class="dot"></span><span class="dot"></span></span>';
            return;
        }
        el.textContent = '';
    }

    function updateUserStatus(uid, status) {
        if (currentServer && currentServer.members) {
            var m = currentServer.members.find(function(x) { return x.id === uid; });
            if (m) { m.status = status; renderMembers(); }
        }
    }

    // ============================================
    // VOICE CHAT
    // ============================================

    function joinVoiceChannel(channel) {
        debug('Joining voice: ' + channel.name, 'warn');
        if (currentVoiceChannel && currentVoiceChannel.id === channel.id) {
            debug('Already in channel'); return;
        }
        if (currentVoiceChannel) { leaveVoiceChannel(); return; }

        var audioConstraints = {
            echoCancellation: true,
            noiseSuppression: true,
            autoGainControl: true
        };
        if (selectedMicId) audioConstraints.deviceId = { exact: selectedMicId };

        navigator.mediaDevices.getUserMedia({ audio: audioConstraints, video: false })
            .then(function(stream) {
                debug('Got mic, tracks: ' + stream.getAudioTracks().length, 'success');
                localStream = stream;
                if (isMuted) stream.getAudioTracks().forEach(function(t) { t.enabled = false; });
                try {
                    audioContext = new (window.AudioContext || window.webkitAudioContext)();
                    localAnalyser = audioContext.createAnalyser();
                    localAnalyser.fftSize = 256;
                    audioContext.createMediaStreamSource(stream).connect(localAnalyser);
                    detectSpeaking();
                } catch(e) { debug('AudioContext error: ' + e.message, 'error'); }
                ws.send(JSON.stringify({ type: 'VOICE_JOIN', channelId: channel.id }));
            })
            .catch(function(e) {
                debug('Mic error: ' + e.message, 'error');
                var msg = 'Не удалось получить доступ к микрофону: ' + e.message;
                if (e.name === 'NotAllowedError') msg = 'Доступ к микрофону запрещен. Разрешите доступ в настройках браузера.';
                else if (e.name === 'NotFoundError') msg = 'Микрофон не найден. Подключите микрофон и попробуйте снова.';
                else if (e.name === 'OverconstrainedError') {
                    // ИСПРАВЛЕНИЕ 4: Если выбранный микрофон недоступен — пробуем дефолтный.
                    debug('Selected mic unavailable, retrying with default', 'warn');
                    selectedMicId = '';
                    localStorage.removeItem('selectedMicId');
                    joinVoiceChannel(channel);
                    return;
                }
                alert(msg);
            });
    }

    function detectSpeaking() {
        if (!currentVoiceChannel || !localAnalyser) return;
        var data = new Uint8Array(localAnalyser.frequencyBinCount);
        localAnalyser.getByteFrequencyData(data);
        var avg = data.reduce(function(a,b) { return a+b; }, 0) / data.length;
        var was = speakingUsers.has(currentUser.id);
        var is = avg > 25 && !isMuted;
        if (is !== was) {
            if (is) speakingUsers.add(currentUser.id); else speakingUsers.delete(currentUser.id);
            updateSpeakingUI();
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'VOICE_SPEAKING', speaking: is }));
            }
        }
        if (currentVoiceChannel) requestAnimationFrame(detectSpeaking);
    }

    function handleVoiceSpeaking(d) {
        if (d.speaking) speakingUsers.add(d.visitorId); else speakingUsers.delete(d.visitorId);
        updateSpeakingUI();
    }

    function updateSpeakingUI() {
        $$('.voice-participant').forEach(function(el) {
            el.classList.toggle('speaking', speakingUsers.has(el.getAttribute('data-user-id')));
        });
        $$('.voice-grid-item').forEach(function(el) {
            el.classList.toggle('speaking', speakingUsers.has(el.getAttribute('data-user-id')));
        });
        var av = $('.user-panel .avatar');
        if (av) av.classList.toggle('speaking', speakingUsers.has(currentUser.id) && !!currentVoiceChannel);
    }

    function handleVoiceJoined(d) {
        debug('VOICE_JOINED, participants: ' + (d.participants ? d.participants.length : 0), 'success');

        // ИСПРАВЛЕНИЕ 5: Если сервер прислал ICE-серверы в ответе — используем их.
        if (d.iceServers && d.iceServers.length) {
            iceServersConfig = d.iceServers;
            debug('ICE config updated from VOICE_JOINED', 'success');
        }

        var ch = null;
        if (currentServer && currentServer.channels) {
            ch = currentServer.channels.find(function(c) { return c.id === d.channelId; });
        }
        if (ch) {
            currentVoiceChannel = ch;
            if (!ch.voiceParticipants) ch.voiceParticipants = [];
            if (!ch.voiceParticipants.some(function(p) { return (p.visitorId || p.odego) === currentUser.id; })) {
                ch.voiceParticipants.push({
                    visitorId: currentUser.id, username: currentUser.username,
                    muted: isMuted, deafened: isDeafened, streaming: false
                });
            }
        } else {
            currentVoiceChannel = { id: d.channelId, name: 'Голосовой' };
        }

        voiceParticipants.clear();
        connectionStates.clear();
        remoteStreams.clear();
        usingRelay = false;

        if (d.participants && d.participants.length > 0) {
            d.participants.forEach(function(p) {
                var uid = p.visitorId || p.odego;
                debug('Existing participant: ' + p.username + ' (' + uid.slice(0,8) + ')');
                voiceParticipants.set(uid, p);
                connectionStates.set(uid, 'connecting');
                createPeerConnection(uid, shouldInitiate(currentUser.id, uid), false);
            });
        }
        render();
    }

    function handleVoiceLeft(d) {
        debug('VOICE_LEFT');
        if (currentServer) {
            var ch = currentServer.channels.find(function(c) { return c.id === d.channelId; });
            if (ch && ch.voiceParticipants) {
                ch.voiceParticipants = ch.voiceParticipants.filter(function(p) {
                    return (p.visitorId || p.odego) !== currentUser.id;
                });
            }
        }
        cleanupVoice();
        currentVoiceChannel = null;
        showVoiceGrid = false;
        render();
    }

    function handleVoiceUserJoined(d) {
        var uid = d.user.visitorId || d.user.odego;
        if (uid === currentUser.id) return;
        debug('User joined voice: ' + d.user.username, 'success');

        if (currentServer) {
            var ch = currentServer.channels.find(function(c) { return c.id === d.channelId; });
            if (ch) {
                if (!ch.voiceParticipants) ch.voiceParticipants = [];
                if (!ch.voiceParticipants.some(function(p) { return (p.visitorId || p.odego) === uid; })) {
                    ch.voiceParticipants.push(d.user);
                }
            }
        }

        if (currentVoiceChannel && currentVoiceChannel.id === d.channelId && localStream) {
            if (!voiceParticipants.has(uid)) voiceParticipants.set(uid, d.user);
            connectionStates.set(uid, 'connecting');
            createPeerConnection(uid, shouldInitiate(currentUser.id, uid), false);
        }
        renderChannels();
        if (showVoiceGrid) renderVoiceGrid();
    }

    function handleVoiceUserLeft(d) {
        var uid = d.visitorId;
        debug('User left voice: ' + uid.slice(0,8));
        voiceParticipants.delete(uid);
        pendingCandidates.delete(uid);
        screenPendingCandidates.delete(uid);
        speakingUsers.delete(uid);
        connectionStates.delete(uid);
        remoteStreams.delete(uid);
        var pc = peerConnections.get(uid);
        if (pc) { pc.close(); peerConnections.delete(uid); }
        var spc = screenPeerConnections.get(uid);
        if (spc) { spc.close(); screenPeerConnections.delete(uid); }
        var audio = document.getElementById('audio-' + uid);
        if (audio) { audio.srcObject = null; audio.remove(); }
        var video = document.getElementById('video-' + uid);
        if (video) { video.srcObject = null; video.remove(); }
        if (currentServer) {
            var ch = currentServer.channels.find(function(c) { return c.id === d.channelId; });
            if (ch && ch.voiceParticipants) {
                ch.voiceParticipants = ch.voiceParticipants.filter(function(p) {
                    return (p.visitorId || p.odego) !== uid;
                });
            }
        }
        renderChannels();
        if (showVoiceGrid) renderVoiceGrid();
    }

    function handleVoiceSignal(d) {
        var sig = d.signal;
        var type = sig.type || (sig.candidate ? 'candidate' : '?');
        var signalType = d.signalType || 'audio';
        debug('Signal from ' + d.fromUserId.slice(0,8) + ': ' + type + ' (' + signalType + ')');
        if (signalType === 'screen') {
            if (sig.type === 'offer') handleScreenOffer(d.fromUserId, d.fromUsername, sig);
            else if (sig.type === 'answer') handleScreenAnswer(d.fromUserId, sig);
            else if (sig.candidate) handleScreenIceCandidate(d.fromUserId, sig);
        } else {
            if (sig.type === 'offer') handleOffer(d.fromUserId, d.fromUsername, sig);
            else if (sig.type === 'answer') handleAnswer(d.fromUserId, sig);
            else if (sig.candidate) handleIceCandidate(d.fromUserId, sig);
        }
    }

    // ============================================
    // WEBRTC - PEER CONNECTIONS
    // ============================================

    // ИСПРАВЛЕНИЕ 6: Параметр relayOnly позволяет пересоздать соединение
    // через TURN при провале обычного ICE — главный механизм для внешней сети.
    function createPeerConnection(uid, initiator, relayOnly) {
        debug('Creating audio PC to ' + uid.slice(0,8) + ', init: ' + initiator + ', relay: ' + relayOnly, 'warn');

        var existing = peerConnections.get(uid);
        if (existing) { existing.close(); peerConnections.delete(uid); }

        var config = {
            iceServers: getIceServers(),
            iceCandidatePoolSize: 10,
            iceTransportPolicy: relayOnly ? 'relay' : 'all',
            bundlePolicy: 'max-bundle',
            rtcpMuxPolicy: 'require'
        };

        var pc = new RTCPeerConnection(config);
        peerConnections.set(uid, pc);
        if (!pendingCandidates.has(uid)) pendingCandidates.set(uid, []);

        if (localStream) {
            localStream.getTracks().forEach(function(t) {
                debug('Adding audio track to ' + uid.slice(0,8));
                pc.addTrack(t, localStream);
            });
        }

        pc.onicecandidate = function(e) {
            if (e.candidate) {
                var cand = e.candidate.candidate;
                if (cand.indexOf('relay') !== -1) {
                    debug('ICE candidate: RELAY (TURN)', 'warn');
                    usingRelay = true;
                    renderVoiceConnected();
                } else if (cand.indexOf('srflx') !== -1) {
                    debug('ICE candidate: STUN srflx', 'success');
                } else {
                    debug('ICE candidate: host');
                }
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({
                        type: 'VOICE_SIGNAL',
                        targetUserId: uid,
                        signal: e.candidate,
                        signalType: 'audio'
                    }));
                }
            } else {
                debug('ICE gathering complete for ' + uid.slice(0,8));
            }
        };

        pc.onicegatheringstatechange = function() {
            debug('ICE gathering ' + uid.slice(0,8) + ': ' + pc.iceGatheringState);
        };

        pc.oniceconnectionstatechange = function() {
            var state = pc.iceConnectionState;
            debug('ICE state ' + uid.slice(0,8) + ': ' + state,
                state === 'connected' || state === 'completed' ? 'success' :
                state === 'failed' || state === 'disconnected' ? 'error' : 'warn');

            connectionStates.set(uid, state);
            renderChannels();
            if (showVoiceGrid) renderVoiceGrid();

            if (state === 'failed') {
                if (!relayOnly) {
                    // ИСПРАВЛЕНИЕ 7: При провале сначала пробуем restartIce,
                    // затем пересоздаём соединение с relay-only политикой.
                    debug('ICE failed, trying restartIce first for ' + uid.slice(0,8), 'warn');
                    pc.restartIce();
                    setTimeout(function() {
                        if (peerConnections.get(uid) === pc && pc.iceConnectionState === 'failed') {
                            debug('restartIce failed, switching to relay-only for ' + uid.slice(0,8), 'error');
                            var shouldInit = shouldInitiate(currentUser.id, uid);
                            createPeerConnection(uid, shouldInit, true);
                            if (shouldInit) sendOffer(uid);
                        }
                    }, 4000);
                } else {
                    // Уже relay-only и всё равно failed — логируем
                    debug('Relay-only ICE also failed for ' + uid.slice(0,8) + '. Check TURN server.', 'error');
                }
            } else if (state === 'disconnected') {
                setTimeout(function() {
                    if (peerConnections.get(uid) === pc && pc.iceConnectionState === 'disconnected') {
                        debug('Still disconnected ' + uid.slice(0,8) + ', restarting ICE', 'warn');
                        pc.restartIce();
                    }
                }, 3000);
            }
        };

        pc.onconnectionstatechange = function() {
            debug('Connection state ' + uid.slice(0,8) + ': ' + pc.connectionState,
                pc.connectionState === 'connected' ? 'success' :
                pc.connectionState === 'failed' ? 'error' : 'warn');
        };

        pc.ontrack = function(e) {
            debug('Got audio track from ' + uid.slice(0,8), 'success');
            if (e.streams && e.streams[0]) {
                var streams = remoteStreams.get(uid) || {};
                streams.audio = e.streams[0];
                remoteStreams.set(uid, streams);

                var audio = document.getElementById('audio-' + uid);
                if (!audio) {
                    audio = document.createElement('audio');
                    audio.id = 'audio-' + uid;
                    audio.autoplay = true;
                    audio.playsInline = true;
                    document.body.appendChild(audio);
                }
                audio.srcObject = e.streams[0];
                audio.muted = isDeafened;
                if (selectedOutputId && audio.setSinkId) {
                    audio.setSinkId(selectedOutputId).catch(function(err) {
                        debug('setSinkId error: ' + err.message, 'error');
                    });
                }
                audio.play().then(function() {
                    debug('Audio playing from ' + uid.slice(0,8), 'success');
                }).catch(function(err) {
                    debug('Audio play error: ' + err.message + ' — waiting for click', 'warn');
                    document.addEventListener('click', function playOnClick() {
                        audio.play().catch(function(){});
                        document.removeEventListener('click', playOnClick);
                    }, { once: true });
                });
            }
        };

        if (initiator) sendOffer(uid);
        return pc;
    }

    function sendOffer(uid) {
        var pc = peerConnections.get(uid);
        if (!pc) return;
        debug('Creating offer for ' + uid.slice(0,8));
        pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: false })
            .then(function(offer) { return pc.setLocalDescription(offer); })
            .then(function() {
                debug('Sending offer to ' + uid.slice(0,8));
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({
                        type: 'VOICE_SIGNAL',
                        targetUserId: uid,
                        signal: pc.localDescription,
                        signalType: 'audio'
                    }));
                }
            })
            .catch(function(e) { debug('Offer error: ' + e.message, 'error'); });
    }

    function handleOffer(uid, username, offer) {
        debug('Got audio offer from ' + uid.slice(0,8));
        if (!voiceParticipants.has(uid)) {
            voiceParticipants.set(uid, { visitorId: uid, username: username, muted: false, deafened: false });
        }

        // ИСПРАВЛЕНИЕ 8: Если приходит повторный offer (например, после restartIce
        // на стороне инициатора) — обрабатываем его корректно через rollback.
        var pc = peerConnections.get(uid);
        if (!pc) {
            pc = createPeerConnection(uid, false, false);
        }

        var applyOffer = function() {
            pc.setRemoteDescription(new RTCSessionDescription(offer))
                .then(function() {
                    var cands = pendingCandidates.get(uid) || [];
                    debug('Processing ' + cands.length + ' pending audio candidates');
                    var p = Promise.resolve();
                    cands.forEach(function(c) {
                        p = p.then(function() {
                            return pc.addIceCandidate(new RTCIceCandidate(c)).catch(function(){});
                        });
                    });
                    pendingCandidates.set(uid, []);
                    return p;
                })
                .then(function() { return pc.createAnswer(); })
                .then(function(ans) { return pc.setLocalDescription(ans); })
                .then(function() {
                    debug('Sending audio answer to ' + uid.slice(0,8));
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({
                            type: 'VOICE_SIGNAL',
                            targetUserId: uid,
                            signal: pc.localDescription,
                            signalType: 'audio'
                        }));
                    }
                })
                .catch(function(e) { debug('Handle offer error: ' + e.message, 'error'); });
        };

        // Если уже есть локальное описание — делаем rollback перед новым offer
        if (pc.signalingState !== 'stable') {
            debug('Rolling back before applying new offer from ' + uid.slice(0,8), 'warn');
            pc.setLocalDescription({ type: 'rollback' })
                .then(applyOffer)
                .catch(function() { applyOffer(); }); // fallback если rollback не поддерживается
        } else {
            applyOffer();
        }
    }

    function handleAnswer(uid, answer) {
        debug('Got audio answer from ' + uid.slice(0,8));
        var pc = peerConnections.get(uid);
        if (!pc) { debug('No PC for ' + uid.slice(0,8), 'error'); return; }
        if (pc.signalingState !== 'have-local-offer') {
            debug('Wrong signaling state for answer: ' + pc.signalingState, 'warn'); return;
        }
        pc.setRemoteDescription(new RTCSessionDescription(answer))
            .then(function() {
                var cands = pendingCandidates.get(uid) || [];
                debug('Processing ' + cands.length + ' pending audio candidates after answer');
                var p = Promise.resolve();
                cands.forEach(function(c) {
                    p = p.then(function() {
                        return pc.addIceCandidate(new RTCIceCandidate(c)).catch(function(){});
                    });
                });
                pendingCandidates.set(uid, []);
                return p;
            })
            .catch(function(e) { debug('Handle answer error: ' + e.message, 'error'); });
    }

    function handleIceCandidate(uid, candidate) {
        var pc = peerConnections.get(uid);
        if (!pc || !pc.remoteDescription || !pc.remoteDescription.type) {
            if (!pendingCandidates.has(uid)) pendingCandidates.set(uid, []);
            pendingCandidates.get(uid).push(candidate);
            return;
        }
        pc.addIceCandidate(new RTCIceCandidate(candidate)).catch(function(e) {
            debug('addIceCandidate error: ' + e.message, 'warn');
        });
    }

    // ============================================
    // SCREEN SHARING
    // ============================================

    function showScreenShareModal() {
        if (!currentVoiceChannel) { alert('Сначала подключитесь к голосовому каналу'); return; }
        $('#modalContainer').innerHTML =
            '<div class="modal-overlay" id="modalOverlay"><div class="modal">' +
            '<button class="modal-close" id="modalCloseBtn">' + icon('close') + '</button>' +
            '<div class="modal-header"><h2>Демонстрация экрана</h2><p>Выберите настройки качества трансляции</p></div>' +
            '<div class="modal-body"><div class="screen-settings">' +
            '<div class="setting-group"><label>Разрешение</label><select id="screenResolution">' +
            '<option value="720" ' + (screenShareSettings.resolution === '720' ? 'selected' : '') + '>720p (HD)</option>' +
            '<option value="1080" ' + (screenShareSettings.resolution === '1080' ? 'selected' : '') + '>1080p (Full HD)</option>' +
            '<option value="source" ' + (screenShareSettings.resolution === 'source' ? 'selected' : '') + '>Исходное</option>' +
            '</select></div>' +
            '<div class="setting-group"><label>Частота кадров</label><select id="screenFps">' +
            '<option value="15" ' + (screenShareSettings.frameRate === 15 ? 'selected' : '') + '>15 FPS</option>' +
            '<option value="30" ' + (screenShareSettings.frameRate === 30 ? 'selected' : '') + '>30 FPS</option>' +
            '<option value="60" ' + (screenShareSettings.frameRate === 60 ? 'selected' : '') + '>60 FPS</option>' +
            '</select></div></div></div>' +
            '<div class="modal-footer"><button class="btn secondary" id="cancelScreenBtn">Отмена</button>' +
            '<button class="btn" id="startScreenBtn">Начать трансляцию</button></div>' +
            '</div></div>';
        $('#modalOverlay').onclick = function(e) { if (e.target.id === 'modalOverlay') closeModal(); };
        $('#cancelScreenBtn').onclick = closeModal;
        if ($('#modalCloseBtn')) $('#modalCloseBtn').onclick = closeModal;
        $('#startScreenBtn').onclick = startScreenShare;
    }

    async function startScreenShare() {
        var resolution = $('#screenResolution').value;
        var fps = parseInt($('#screenFps').value);
        screenShareSettings.resolution = resolution;
        screenShareSettings.frameRate = fps;
        closeModal();

        var constraints = { video: { cursor: 'always', frameRate: { ideal: fps, max: fps } }, audio: { echoCancellation: true, noiseSuppression: true } };
        if (resolution !== 'source') {
            var height = parseInt(resolution);
            constraints.video.height = { ideal: height };
            constraints.video.width = { ideal: Math.round(height * 16 / 9) };
        }
        try {
            debug('Requesting screen capture...', 'warn');
            screenStream = await navigator.mediaDevices.getDisplayMedia(constraints);
            debug('Screen capture started', 'success');
            isScreenSharing = true;
            screenStream.getVideoTracks()[0].onended = function() {
                debug('Screen share ended by user');
                stopScreenShare();
            };
            voiceParticipants.forEach(function(p, odego) {
                createScreenPeerConnection(odego, true);
            });
            ws.send(JSON.stringify({ type: 'VOICE_STREAM_START', streamType: 'screen' }));
            renderVoiceConnected();
            renderChannels();
            if (showVoiceGrid) renderVoiceGrid();
        } catch(e) {
            debug('Screen share error: ' + e.message, 'error');
            var msg = 'Не удалось начать демонстрацию экрана: ' + e.message;
            if (e.name === 'NotAllowedError') msg = 'Демонстрация экрана отменена или запрещена.';
            alert(msg);
        }
    }

    function stopScreenShare() {
        if (!isScreenSharing) return;
        debug('Stopping screen share');
        isScreenSharing = false;
        if (screenStream) {
            screenStream.getTracks().forEach(function(t) { t.stop(); });
            screenStream = null;
        }
        screenPeerConnections.forEach(function(pc) { pc.close(); });
        screenPeerConnections.clear();
        screenPendingCandidates.clear();
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'VOICE_STREAM_STOP' }));
        }
        renderVoiceConnected();
        renderChannels();
        if (showVoiceGrid) renderVoiceGrid();
    }

    // ИСПРАВЛЕНИЕ 9: Screen PC теперь тоже буферизует ICE-кандидатов
    // и поддерживает relay-only fallback.
    function createScreenPeerConnection(uid, initiator) {
        debug('Creating screen PC to ' + uid.slice(0,8) + ', init: ' + initiator, 'warn');
        var existing = screenPeerConnections.get(uid);
        if (existing) { existing.close(); screenPeerConnections.delete(uid); }

        var config = {
            iceServers: getIceServers(),
            iceCandidatePoolSize: 10,
            bundlePolicy: 'max-bundle',
            rtcpMuxPolicy: 'require'
        };
        var pc = new RTCPeerConnection(config);
        screenPeerConnections.set(uid, pc);
        if (!screenPendingCandidates.has(uid)) screenPendingCandidates.set(uid, []);

        if (initiator && screenStream) {
            screenStream.getTracks().forEach(function(t) {
                debug('Adding screen track (' + t.kind + ') to ' + uid.slice(0,8));
                pc.addTrack(t, screenStream);
            });
        }

        pc.onicecandidate = function(e) {
            if (e.candidate && ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'VOICE_SIGNAL',
                    targetUserId: uid,
                    signal: e.candidate,
                    signalType: 'screen'
                }));
            }
        };

        pc.oniceconnectionstatechange = function() {
            var state = pc.iceConnectionState;
            debug('Screen ICE ' + uid.slice(0,8) + ': ' + state,
                state === 'connected' ? 'success' : state === 'failed' ? 'error' : 'warn');
            if (state === 'failed') {
                debug('Screen ICE failed for ' + uid.slice(0,8) + ', retrying', 'error');
                pc.restartIce();
            }
        };

        pc.ontrack = function(e) {
            debug('Got screen track from ' + uid.slice(0,8), 'success');
            if (e.streams && e.streams[0]) {
                var streams = remoteStreams.get(uid) || {};
                streams.screen = e.streams[0];
                remoteStreams.set(uid, streams);
                if (showVoiceGrid) renderVoiceGrid();
            }
        };

        if (initiator) {
            pc.createOffer({ offerToReceiveVideo: true, offerToReceiveAudio: true })
                .then(function(offer) { return pc.setLocalDescription(offer); })
                .then(function() {
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({
                            type: 'VOICE_SIGNAL',
                            targetUserId: uid,
                            signal: pc.localDescription,
                            signalType: 'screen'
                        }));
                    }
                })
                .catch(function(e) { debug('Screen offer error: ' + e.message, 'error'); });
        }
        return pc;
    }

    function handleScreenOffer(uid, username, offer) {
        debug('Got screen offer from ' + uid.slice(0,8));
        var pc = createScreenPeerConnection(uid, false);
        pc.setRemoteDescription(new RTCSessionDescription(offer))
            .then(function() {
                // Применяем буферизованные кандидаты
                var cands = screenPendingCandidates.get(uid) || [];
                debug('Processing ' + cands.length + ' pending screen candidates');
                var p = Promise.resolve();
                cands.forEach(function(c) {
                    p = p.then(function() {
                        return pc.addIceCandidate(new RTCIceCandidate(c)).catch(function(){});
                    });
                });
                screenPendingCandidates.set(uid, []);
                return p;
            })
            .then(function() { return pc.createAnswer(); })
            .then(function(ans) { return pc.setLocalDescription(ans); })
            .then(function() {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({
                        type: 'VOICE_SIGNAL',
                        targetUserId: uid,
                        signal: pc.localDescription,
                        signalType: 'screen'
                    }));
                }
            })
            .catch(function(e) { debug('Screen answer error: ' + e.message, 'error'); });
    }

    function handleScreenAnswer(uid, answer) {
        var pc = screenPeerConnections.get(uid);
        if (!pc) return;
        pc.setRemoteDescription(new RTCSessionDescription(answer))
            .then(function() {
                var cands = screenPendingCandidates.get(uid) || [];
                var p = Promise.resolve();
                cands.forEach(function(c) {
                    p = p.then(function() {
                        return pc.addIceCandidate(new RTCIceCandidate(c)).catch(function(){});
                    });
                });
                screenPendingCandidates.set(uid, []);
                return p;
            })
            .catch(function(e) { debug('Screen answer error: ' + e.message, 'error'); });
    }

    function handleScreenIceCandidate(uid, candidate) {
        var pc = screenPeerConnections.get(uid);
        // ИСПРАВЛЕНИЕ 10: Буферизуем кандидаты для screen PC так же, как для audio PC.
        if (!pc || !pc.remoteDescription || !pc.remoteDescription.type) {
            if (!screenPendingCandidates.has(uid)) screenPendingCandidates.set(uid, []);
            screenPendingCandidates.get(uid).push(candidate);
            return;
        }
        pc.addIceCandidate(new RTCIceCandidate(candidate)).catch(function(e) {
            debug('Screen addIceCandidate error: ' + e.message, 'warn');
        });
    }

    function handleStreamStart(d) {
        var p = voiceParticipants.get(d.visitorId);
        if (p) { p.streaming = true; p.streamType = d.streamType; }
        if (currentServer) {
            currentServer.channels.forEach(function(ch) {
                if (ch.voiceParticipants) {
                    var vp = ch.voiceParticipants.find(function(x) { return (x.visitorId || x.odego) === d.visitorId; });
                    if (vp) { vp.streaming = true; vp.streamType = d.streamType; }
                }
            });
        }
        if (d.visitorId !== currentUser.id && currentVoiceChannel) {
            createScreenPeerConnection(d.visitorId, false);
        }
        renderChannels();
        if (showVoiceGrid) renderVoiceGrid();
    }

    function handleStreamStop(d) {
        var p = voiceParticipants.get(d.visitorId);
        if (p) { p.streaming = false; p.streamType = null; }
        if (currentServer) {
            currentServer.channels.forEach(function(ch) {
                if (ch.voiceParticipants) {
                    var vp = ch.voiceParticipants.find(function(x) { return (x.visitorId || x.odego) === d.visitorId; });
                    if (vp) { vp.streaming = false; vp.streamType = null; }
                }
            });
        }
        var streams = remoteStreams.get(d.visitorId);
        if (streams) { streams.screen = null; remoteStreams.set(d.visitorId, streams); }
        var spc = screenPeerConnections.get(d.visitorId);
        if (spc) { spc.close(); screenPeerConnections.delete(d.visitorId); }
        screenPendingCandidates.delete(d.visitorId);
        if (focusedStream === d.visitorId) focusedStream = null;
        renderChannels();
        if (showVoiceGrid) renderVoiceGrid();
    }

    // ============================================
    // VOICE CONTROLS
    // ============================================

    function handleVoiceMuteDeafen(d) {
        var p = voiceParticipants.get(d.visitorId);
        if (p) {
            if (d.muted !== undefined) p.muted = d.muted;
            if (d.deafened !== undefined) p.deafened = d.deafened;
        }
        if (currentServer) {
            currentServer.channels.forEach(function(ch) {
                if (ch.voiceParticipants) {
                    var vp = ch.voiceParticipants.find(function(x) { return (x.visitorId || x.odego) === d.visitorId; });
                    if (vp) {
                        if (d.muted !== undefined) vp.muted = d.muted;
                        if (d.deafened !== undefined) vp.deafened = d.deafened;
                    }
                }
            });
        }
        renderChannels();
        if (showVoiceGrid) renderVoiceGrid();
    }

    function handleVoiceStateUpdate(d) {
        if (!currentServer) return;
        var ch = currentServer.channels.find(function(c) { return c.id === d.channelId; });
        if (!ch) return;
        if (!ch.voiceParticipants) ch.voiceParticipants = [];
        if (d.action === 'join') {
            if (!ch.voiceParticipants.some(function(p) { return (p.visitorId || p.odego) === d.visitorId; })) {
                ch.voiceParticipants.push({ visitorId: d.visitorId, username: d.username, muted: false, deafened: false, streaming: false });
            }
        } else if (d.action === 'leave') {
            ch.voiceParticipants = ch.voiceParticipants.filter(function(p) { return (p.visitorId || p.odego) !== d.visitorId; });
        }
        renderChannels();
    }

    function leaveVoiceChannel() {
        debug('Leaving voice channel');
        if (!currentVoiceChannel) return;
        if (isScreenSharing) stopScreenShare();
        var chId = currentVoiceChannel.id;
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'VOICE_LEAVE' }));
        }
        if (currentServer) {
            var ch = currentServer.channels.find(function(c) { return c.id === chId; });
            if (ch && ch.voiceParticipants) {
                ch.voiceParticipants = ch.voiceParticipants.filter(function(p) {
                    return (p.visitorId || p.odego) !== currentUser.id;
                });
            }
        }
        pendingVoiceRejoin = null; // Сбрасываем rejoin при намеренном выходе
        cleanupVoice();
        currentVoiceChannel = null;
        showVoiceGrid = false;
        render();
    }

    function cleanupVoice() {
        debug('Cleanup voice resources');
        peerConnections.forEach(function(pc, uid) {
            pc.close();
            var a = document.getElementById('audio-' + uid);
            if (a) { a.srcObject = null; a.remove(); }
        });
        peerConnections.clear();
        screenPeerConnections.forEach(function(pc) { pc.close(); });
        screenPeerConnections.clear();
        pendingCandidates.clear();
        screenPendingCandidates.clear();
        speakingUsers.clear();
        connectionStates.clear();
        remoteStreams.clear();
        if (localStream) {
            localStream.getTracks().forEach(function(t) { t.stop(); });
            localStream = null;
        }
        if (screenStream) {
            screenStream.getTracks().forEach(function(t) { t.stop(); });
            screenStream = null;
        }
        if (audioContext) {
            audioContext.close().catch(function(){});
            audioContext = null;
            localAnalyser = null;
        }
        voiceParticipants.clear();
        isMuted = false;
        isDeafened = false;
        isScreenSharing = false;
        usingRelay = false;
        focusedStream = null;
    }

    function toggleMute() {
        if (!localStream) return;
        isMuted = !isMuted;
        localStream.getAudioTracks().forEach(function(t) { t.enabled = !isMuted; });
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'VOICE_TOGGLE_MUTE', muted: isMuted }));
        }
        if (isMuted) speakingUsers.delete(currentUser.id);
        renderVoiceConnected();
        renderUserPanel();
        renderChannels();
    }

    function toggleDeafen() {
        isDeafened = !isDeafened;
        document.querySelectorAll('audio[id^="audio-"]').forEach(function(a) { a.muted = isDeafened; });
        if (isDeafened && !isMuted) {
            isMuted = true;
            if (localStream) localStream.getAudioTracks().forEach(function(t) { t.enabled = false; });
            speakingUsers.delete(currentUser.id);
        }
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'VOICE_TOGGLE_DEAFEN', deafened: isDeafened }));
        }
        renderVoiceConnected();
        renderUserPanel();
        renderChannels();
    }

    // ============================================
    // AUDIO SETTINGS
    // ============================================

    async function showAudioSettings() {
        var devices = [];
        try { devices = await navigator.mediaDevices.enumerateDevices(); }
        catch(e) { alert('Не удалось получить список устройств: ' + e.message); return; }

        var mics = devices.filter(function(d) { return d.kind === 'audioinput'; });
        var outputs = devices.filter(function(d) { return d.kind === 'audiooutput'; });

        var micOptions = '<option value="">По умолчанию</option>';
        mics.forEach(function(m) {
            var selected = m.deviceId === selectedMicId ? ' selected' : '';
            micOptions += '<option value="' + m.deviceId + '"' + selected + '>' + escapeHtml(m.label || 'Микрофон ' + m.deviceId.slice(0,8)) + '</option>';
        });
        var outputOptions = '<option value="">По умолчанию</option>';
        outputs.forEach(function(o) {
            var selected = o.deviceId === selectedOutputId ? ' selected' : '';
            outputOptions += '<option value="' + o.deviceId + '"' + selected + '>' + escapeHtml(o.label || 'Динамик ' + o.deviceId.slice(0,8)) + '</option>';
        });

        $('#modalContainer').innerHTML =
            '<div class="modal-overlay" id="modalOverlay"><div class="modal">' +
            '<div class="modal-header"><h2>Настройки звука</h2></div>' +
            '<div class="modal-body">' +
            '<div class="form-group"><label>Микрофон</label><select id="micSelect" class="audio-select">' + micOptions + '</select></div>' +
            '<div class="form-group"><label>Устройство вывода</label><select id="outputSelect" class="audio-select">' + outputOptions + '</select></div>' +
            '<div class="form-group"><label>Проверка микрофона</label>' +
            '<div class="mic-test"><div class="mic-level-bar"><div class="mic-level-fill" id="micLevelFill"></div></div>' +
            '<button class="btn" id="testMicBtn" style="margin-top:8px;">Проверить</button></div></div>' +
            '<div id="micTestResult" style="margin-top:8px;font-size:13px;"></div></div>' +
            '<div class="modal-footer"><button class="btn secondary" id="cancelAudioBtn">Отмена</button>' +
            '<button class="btn" id="saveAudioBtn">Сохранить</button></div></div></div>';

        $('#modalOverlay').onclick = function(e) { if (e.target.id === 'modalOverlay') { stopMicTest(); closeModal(); } };
        $('#cancelAudioBtn').onclick = function() { stopMicTest(); closeModal(); };
        $('#saveAudioBtn').onclick = saveAudioSettings;
        $('#testMicBtn').onclick = testMicrophone;
        $('#micSelect').onchange = function() { stopMicTest(); };
    }

    async function testMicrophone() {
        stopMicTest();
        var micId = $('#micSelect').value;
        var constraints = { audio: micId ? { deviceId: { exact: micId } } : true };
        $('#micTestResult').innerHTML = '<span style="color:var(--yellow);">Получение доступа...</span>';
        try {
            micTestStream = await navigator.mediaDevices.getUserMedia(constraints);
            $('#micTestResult').innerHTML = '<span style="color:var(--green);">✓ Микрофон активен</span>';
            micTestCtx = new (window.AudioContext || window.webkitAudioContext)();
            var analyser = micTestCtx.createAnalyser();
            analyser.fftSize = 256;
            micTestCtx.createMediaStreamSource(micTestStream).connect(analyser);
            var data = new Uint8Array(analyser.frequencyBinCount);
            micTestInterval = setInterval(function() {
                analyser.getByteFrequencyData(data);
                var level = 0;
                for (var i = 0; i < data.length; i++) { if (data[i] > level) level = data[i]; }
                var percent = Math.min(100, (level / 255) * 100);
                var fill = $('#micLevelFill');
                if (fill) {
                    fill.style.width = percent + '%';
                    fill.style.background = level < 10 ? 'var(--red)' : level < 50 ? 'var(--yellow)' : 'var(--green)';
                }
            }, 100);
            $('#testMicBtn').textContent = 'Остановить';
            $('#testMicBtn').onclick = function() {
                stopMicTest();
                $('#testMicBtn').textContent = 'Проверить';
                $('#testMicBtn').onclick = testMicrophone;
            };
        } catch(e) {
            $('#micTestResult').innerHTML = '<span style="color:var(--red);">✗ ' + e.message + '</span>';
        }
    }

    function stopMicTest() {
        if (micTestInterval) { clearInterval(micTestInterval); micTestInterval = null; }
        if (micTestStream) { micTestStream.getTracks().forEach(function(t) { t.stop(); }); micTestStream = null; }
        if (micTestCtx) { micTestCtx.close().catch(function(){}); micTestCtx = null; }
        var fill = $('#micLevelFill');
        if (fill) fill.style.width = '0%';
    }

    async function saveAudioSettings() {
        var newMicId = $('#micSelect').value;
        var newOutputId = $('#outputSelect').value;
        selectedMicId = newMicId;
        selectedOutputId = newOutputId;
        localStorage.setItem('selectedMicId', newMicId);
        localStorage.setItem('selectedOutputId', newOutputId);
        if (newOutputId) {
            document.querySelectorAll('audio[id^="audio-"]').forEach(function(audio) {
                if (audio.setSinkId) audio.setSinkId(newOutputId).catch(function(){});
            });
        }
        if (currentVoiceChannel && localStream) {
            debug('Applying new microphone...', 'warn');
            localStream.getTracks().forEach(function(t) { t.stop(); });
            try {
                var constraints = { audio: newMicId ? { deviceId: { exact: newMicId } } : true };
                var newStream = await navigator.mediaDevices.getUserMedia(constraints);
                localStream = newStream;
                if (isMuted) newStream.getAudioTracks().forEach(function(t) { t.enabled = false; });
                var newTrack = newStream.getAudioTracks()[0];
                peerConnections.forEach(function(pc) {
                    var senders = pc.getSenders();
                    var audioSender = senders.find(function(s) { return s.track && s.track.kind === 'audio'; });
                    if (audioSender) audioSender.replaceTrack(newTrack).catch(function(e) {
                        debug('Track replace error: ' + e.message, 'error');
                    });
                });
                if (audioContext) audioContext.close().catch(function(){});
                audioContext = new (window.AudioContext || window.webkitAudioContext)();
                localAnalyser = audioContext.createAnalyser();
                localAnalyser.fftSize = 256;
                audioContext.createMediaStreamSource(newStream).connect(localAnalyser);
                debug('Microphone changed successfully', 'success');
            } catch(e) {
                debug('Mic change error: ' + e.message, 'error');
                alert('Не удалось сменить микрофон: ' + e.message);
            }
        }
        stopMicTest();
        closeModal();
    }

    // ============================================
    // RENDERING
    // ============================================

    function render() {
        var app = $('#app');
        if (!token || !currentUser) { renderAuth(); return; }
        var html = '<div class="app-container"><div class="server-list" id="serverList"></div>';
        if (currentServer) {
            html += '<div class="channel-sidebar" id="channelSidebar"></div>';
            html += '<div class="chat-area" id="chatArea"></div>';
            html += '<div class="members-sidebar" id="membersSidebar"></div>';
        } else {
            html += '<div class="dm-sidebar" id="dmSidebar"></div>';
            html += '<div class="chat-area" id="chatArea"></div>';
        }
        html += '</div><div id="modalContainer"></div>';
        if (showVoiceGrid && currentVoiceChannel) {
            html += '<div class="voice-grid-overlay" id="voiceGridOverlay"></div>';
        }
        app.innerHTML = html;
        updateDebugPanelVisibility();
        renderServerList();
        if (currentServer) {
            renderChannelSidebar();
            renderChatArea();
            renderMembers();
        } else {
            renderDMSidebar();
            renderDMChatArea();
        }
        if (showVoiceGrid && currentVoiceChannel) renderVoiceGrid();
    }

    function renderAuth() {
        var app = $('#app');
        var isLogin = !window.showRegister;
        app.innerHTML =
            '<div class="auth-container"><div class="auth-box">' +
            '<h1>' + (isLogin ? 'С возвращением!' : 'Создать аккаунт') + '</h1>' +
            '<p>' + (isLogin ? 'Рады видеть вас!' : 'Присоединяйтесь!') + '</p>' +
            '<div id="authError"></div><form id="authForm">' +
            (!isLogin ? '<div class="form-group"><label>Имя пользователя</label><input type="text" id="username" required minlength="3" maxlength="32"></div>' : '') +
            '<div class="form-group"><label>Email</label><input type="email" id="email" required></div>' +
            '<div class="form-group"><label>Пароль</label><input type="password" id="password" required minlength="6"></div>' +
            '<button type="submit" class="btn">' + (isLogin ? 'Войти' : 'Зарегистрироваться') + '</button></form>' +
            '<div class="auth-switch">' + (isLogin ? 'Нет аккаунта?' : 'Есть аккаунт?') +
            ' <a id="authSwitch">' + (isLogin ? 'Регистрация' : 'Войти') + '</a></div></div></div>';
        $('#authSwitch').onclick = function() { window.showRegister = isLogin; renderAuth(); };
        $('#authForm').onsubmit = function(e) {
            e.preventDefault();
            var email = $('#email').value;
            var password = $('#password').value;
            var usernameEl = $('#username');
            var body = isLogin ? { email: email, password: password } : { email: email, password: password, username: usernameEl.value };
            api(isLogin ? '/api/auth/login' : '/api/auth/register', { method: 'POST', body: JSON.stringify(body) })
                .then(function(d) {
                    token = d.token;
                    currentUser = d.user;
                    localStorage.setItem('token', token);
                    connectWebSocket();
                    return loadIceConfig().then(function() { return loadServers(); });
                })
                .then(function() { render(); })
                .catch(function(e) { $('#authError').innerHTML = '<div class="error-msg">' + e.message + '</div>'; });
        };
    }

    function renderServerList() {
        var c = $('#serverList'); if (!c) return;
        var html = '<div class="server-icon home ' + (!currentServer ? 'active' : '') + '" id="homeBtn" title="Личные сообщения">' + icon('home') + '</div>';
        html += '<div class="separator"></div>';
        servers.forEach(function(s) {
            html += '<div class="server-icon ' + (currentServer && currentServer.id === s.id ? 'active' : '') + '" data-server-id="' + s.id + '" title="' + escapeHtml(s.name) + '">' + getInitials(s.name) + '</div>';
        });
        html += '<div class="server-icon add" id="addServerBtn" title="Добавить сервер">' + icon('plus') + '</div>';
        c.innerHTML = html;
        $('#homeBtn').onclick = selectHome;
        $('#addServerBtn').onclick = showCreateServerModal;
        $$('.server-icon[data-server-id]').forEach(function(el) {
            el.onclick = function() { selectServer(el.getAttribute('data-server-id')); };
        });
    }

    function renderChannelSidebar() {
        var c = $('#channelSidebar'); if (!c || !currentServer) return;
        c.innerHTML =
            '<div class="server-header" id="serverHeader">' + escapeHtml(currentServer.name) + '<span>▾</span></div>' +
            '<div class="channel-list" id="channelList"></div>' +
            '<div id="voiceConnectedPanel"></div>' +
            '<div class="user-panel" id="userPanel"></div>';
        $('#serverHeader').onclick = showServerSettings;
        renderChannels();
        renderVoiceConnected();
        renderUserPanel();
    }

    function renderChannels() {
        var c = $('#channelList'); if (!c || !currentServer) return;
        var channels = currentServer.channels || [];
        var textCh = channels.filter(function(ch) { return ch.type === 'text'; });
        var voiceCh = channels.filter(function(ch) { return ch.type === 'voice'; });

        var html = '<div class="channel-category"><span>ТЕКСТОВЫЕ КАНАЛЫ</span>';
        if (currentServer.owner_id === currentUser.id) html += '<button id="addTextChannel" title="Создать канал">' + icon('plus') + '</button>';
        html += '</div>';
        textCh.forEach(function(ch) {
            html += '<div class="channel-item ' + (currentChannel && currentChannel.id === ch.id ? 'active' : '') + '" data-channel-id="' + ch.id + '">';
            html += '<span class="icon">' + icon('hash') + '</span><span class="name">' + escapeHtml(ch.name) + '</span>';
            if (currentServer.owner_id === currentUser.id && textCh.length > 1) {
                html += '<button class="delete-btn" data-delete-channel="' + ch.id + '" title="Удалить">' + icon('close') + '</button>';
            }
            html += '</div>';
        });

        html += '<div class="channel-category"><span>ГОЛОСОВЫЕ КАНАЛЫ</span>';
        if (currentServer.owner_id === currentUser.id) html += '<button id="addVoiceChannel" title="Создать канал">' + icon('plus') + '</button>';
        html += '</div>';
        voiceCh.forEach(function(ch) {
            var parts = ch.voiceParticipants || [];
            var hasUsers = parts.length > 0;
            var isConn = currentVoiceChannel && currentVoiceChannel.id === ch.id;
            html += '<div class="voice-channel ' + (hasUsers ? 'has-users' : '') + '">';
            html += '<div class="channel-item ' + (isConn ? 'active' : '') + '" data-voice-channel-id="' + ch.id + '">';
            html += '<span class="icon">' + icon('voice') + '</span><span class="name">' + escapeHtml(ch.name) + '</span>';
            if (currentServer.owner_id === currentUser.id && voiceCh.length > 1) {
                html += '<button class="delete-btn" data-delete-channel="' + ch.id + '" title="Удалить">' + icon('close') + '</button>';
            }
            html += '</div>';
            if (hasUsers) {
                html += '<div class="voice-participants">';
                parts.forEach(function(p) {
                    var uid = p.visitorId || p.odego;
                    var isSpeaking = speakingUsers.has(uid);
                    var connState = connectionStates.get(uid);
                    var stateClass = '';
                    if (uid !== currentUser.id && connState) {
                        if (connState === 'connected' || connState === 'completed') stateClass = 'connected';
                        else if (connState === 'failed' || connState === 'disconnected') stateClass = 'failed';
                        else stateClass = 'connecting';
                    }
                    html += '<div class="voice-participant ' + (isSpeaking ? 'speaking' : '') + '" data-user-id="' + uid + '">';
                    html += '<div class="avatar">' + renderAvatarContent(p.username, p.avatar_url) + '</div>';
                    html += '<span class="name">' + escapeHtml(p.username) + '</span>';
                    html += '<span class="status-icons">';
                    if (uid !== currentUser.id && stateClass) {
                        html += '<span class="conn-status ' + stateClass + '">' +
                            (stateClass === 'connected' ? '✓' : stateClass === 'failed' ? '✗' : '...') + '</span>';
                    }
                    if (p.streaming) html += '<span class="stream-icon" title="Стримит">' + icon('users') + '</span>';
                    if (p.muted) html += '<span class="mute-icon" title="Замьючен">' + icon('close') + '</span>';
                    if (p.deafened) html += '<span class="deafen-icon" title="Оглушён">' + icon('deafen') + '</span>';
                    html += '</span></div>';
                });
                html += '</div>';
            }
            html += '</div>';
        });
        c.innerHTML = html;

        if ($('#addTextChannel')) $('#addTextChannel').onclick = function() { showCreateChannelModal('text'); };
        if ($('#addVoiceChannel')) $('#addVoiceChannel').onclick = function() { showCreateChannelModal('voice'); };
        $$('.channel-item[data-channel-id]').forEach(function(el) {
            el.onclick = function(e) {
                if (!e.target.classList.contains('delete-btn')) selectChannel(el.getAttribute('data-channel-id'));
            };
        });
        $$('.channel-item[data-voice-channel-id]').forEach(function(el) {
            el.onclick = function(e) {
                if (!e.target.classList.contains('delete-btn')) {
                    var ch = currentServer.channels.find(function(c) { return c.id === el.getAttribute('data-voice-channel-id'); });
                    if (ch) joinVoiceChannel(ch);
                }
            };
        });
        $$('[data-delete-channel]').forEach(function(el) {
            el.onclick = function(e) { e.stopPropagation(); deleteChannel(el.getAttribute('data-delete-channel')); };
        });
    }

    function renderVoiceConnected() {
        var c = $('#voiceConnectedPanel'); if (!c) return;
        if (!currentVoiceChannel) { c.innerHTML = ''; return; }
        var relayClass = usingRelay ? ' relay' : '';
        var html = '<div class="voice-connected">';
        html += '<div class="voice-status">';
        html += '<div class="indicator' + relayClass + '"></div>';
        html += '<div class="text">';
        html += '<div class="title' + relayClass + '">' + (usingRelay ? 'Подключено через TURN' : 'Голос подключен') + '</div>';
        html += '<div class="channel">' + escapeHtml(currentVoiceChannel.name) + '</div>';
        html += '</div></div>';
        html += '<div class="voice-controls">';
        html += '<button id="vcMute" class="' + (isMuted ? 'active' : '') + '" title="' + (isMuted ? 'Включить микрофон' : 'Выключить микрофон') + '">' + icon('voice') + '</button>';
        html += '<button id="vcDeafen" class="' + (isDeafened ? 'active' : '') + '" title="' + (isDeafened ? 'Включить звук' : 'Выключить звук') + '">' + icon('deafen') + '</button>';
        html += '<button id="vcScreen" class="screen-share ' + (isScreenSharing ? 'active' : '') + '" title="Демонстрация экрана">' + icon('users') + '</button>';
        html += '<button id="vcGrid" title="Показать участников">' + icon('users') + '</button>';
        html += '<button id="vcDisconnect" class="disconnect" title="Отключиться">' + icon('close') + '</button>';
        html += '</div></div>';
        c.innerHTML = html;
        $('#vcMute').onclick = toggleMute;
        $('#vcDeafen').onclick = toggleDeafen;
        $('#vcScreen').onclick = function() { if (isScreenSharing) stopScreenShare(); else showScreenShareModal(); };
        $('#vcGrid').onclick = function() { showVoiceGrid = !showVoiceGrid; render(); };
        $('#vcDisconnect').onclick = leaveVoiceChannel;
    }

    function renderUserPanel() {
        var c = $('#userPanel'); if (!c) return;
        var isSpeaking = speakingUsers.has(currentUser.id) && !!currentVoiceChannel;
        var html = '<div class="avatar ' + (isSpeaking ? 'speaking' : '') + '" id="openProfileBtn" title="Открыть профиль">' + renderAvatarContent(currentUser.username, currentUser.avatar_url) + '</div>';
        html += '<div class="info"><div class="username">' + escapeHtml(currentUser.username) + '</div>';
        html += '<div class="status">В сети</div></div>';
        html += '<div class="actions">';
        html += '<button id="audioSettingsBtn" title="Настройки звука">' + icon('settings') + '</button>';
        if (currentVoiceChannel) {
            html += '<button id="upMute" class="' + (isMuted ? 'muted' : '') + '" title="Микрофон">' + icon('voice') + '</button>';
            html += '<button id="upDeafen" class="' + (isDeafened ? 'muted' : '') + '" title="Звук">' + icon('deafen') + '</button>';
        }
        html += '<button id="logoutBtn" title="Выйти">' + icon('logout') + '</button></div>';
        c.innerHTML = html;
        $('#openProfileBtn').onclick = showProfileSettings;
        $('#audioSettingsBtn').onclick = showAudioSettings;
        if ($('#upMute')) $('#upMute').onclick = toggleMute;
        if ($('#upDeafen')) $('#upDeafen').onclick = toggleDeafen;
        $('#logoutBtn').onclick = logout;
    }

    function fileToOptimizedDataUrl(file) {
        var MAX_DIMENSION = 512;
        var JPEG_QUALITY = 0.82;
        return new Promise(function(resolve, reject) {
            var reader = new FileReader();
            reader.onerror = function() { reject(new Error('Не удалось прочитать файл')); };
            reader.onload = function(ev) {
                var img = new Image();
                img.onerror = function() { reject(new Error('Файл не является корректным изображением')); };
                img.onload = function() {
                    var w = img.width;
                    var h = img.height;
                    if (!w || !h) return reject(new Error('Некорректный размер изображения'));
                    if (w > MAX_DIMENSION || h > MAX_DIMENSION) {
                        var ratio = Math.min(MAX_DIMENSION / w, MAX_DIMENSION / h);
                        w = Math.max(1, Math.round(w * ratio));
                        h = Math.max(1, Math.round(h * ratio));
                    }
                    var canvas = document.createElement('canvas');
                    canvas.width = w;
                    canvas.height = h;
                    var ctx = canvas.getContext('2d');
                    ctx.drawImage(img, 0, 0, w, h);
                    var mime = /image\/(png|webp)/i.test(file.type) ? file.type : 'image/jpeg';
                    var dataUrl = canvas.toDataURL(mime, JPEG_QUALITY);
                    resolve(dataUrl);
                };
                img.src = ev.target.result;
            };
            reader.readAsDataURL(file);
        });
    }

    function showProfileSettings() {
        var initialAvatar = currentUser.avatar_url || '';
        var nextAvatar = initialAvatar;
        $('#modalContainer').innerHTML =
            '<div class="modal-overlay" id="modalOverlay"><div class="modal" role="dialog" aria-modal="true">' +
            '<div class="modal-header"><h2>Профиль пользователя</h2><button class="modal-close" id="modalCloseBtn">' + icon('close') + '</button></div>' +
            '<div class="modal-body"><form id="profileForm" class="profile-editor">' +
            '<div class="profile-avatar-preview" id="profileAvatarPreview">' + renderAvatarContent(currentUser.username, initialAvatar) + '</div>' +
            '<div class="form-group"><label>Аватарка</label><input type="file" id="profileAvatarInput" accept="image/*"></div>' +
            '<div class="form-group"><label>Никнейм</label><input type="text" id="profileUsernameInput" minlength="3" maxlength="32" value="' + escapeHtml(currentUser.username) + '" required></div>' +
            '<label style="display:flex;align-items:center;gap:8px;"><input type="checkbox" id="removeAvatarCheck"> Удалить аватар</label>' +
            '<p class="profile-help">Поддерживаются png/jpg/webp/gif. Аватар хранится в базе данных.</p>' +
            '</form></div>' +
            '<div class="modal-actions"><button class="btn secondary" id="cancelBtn">Отмена</button><button class="btn" id="saveProfileBtn">Сохранить</button></div>' +
            '</div></div>';

        function refreshPreview(name) {
            var preview = $('#profileAvatarPreview');
            if (preview) preview.innerHTML = renderAvatarContent(name, nextAvatar);
        }

        $('#profileAvatarInput').onchange = function(e) {
            var file = e.target.files && e.target.files[0];
            if (!file) return;
            fileToOptimizedDataUrl(file).then(function(dataUrl) {
                nextAvatar = dataUrl;
                $('#removeAvatarCheck').checked = false;
                refreshPreview($('#profileUsernameInput').value || currentUser.username);
            }).catch(function(err) {
                alert(err.message || 'Не удалось обработать изображение');
                e.target.value = '';
            });
            if (file.size > 1024 * 1024) {
                alert('Файл слишком большой (максимум 1MB)');
                e.target.value = '';
                return;
            }
            var reader = new FileReader();
            reader.onload = function(ev) {
                nextAvatar = ev.target.result;
                $('#removeAvatarCheck').checked = false;
                refreshPreview($('#profileUsernameInput').value || currentUser.username);
            };
            reader.readAsDataURL(file);
        };

        $('#removeAvatarCheck').onchange = function(e) {
            if (e.target.checked) nextAvatar = null;
            else nextAvatar = initialAvatar;
            refreshPreview($('#profileUsernameInput').value || currentUser.username);
        };

        $('#profileUsernameInput').oninput = function(e) { refreshPreview(e.target.value || currentUser.username); };

        $('#saveProfileBtn').onclick = function() {
            var username = ($('#profileUsernameInput').value || '').trim();
            api('/api/users/me/profile', {
                method: 'PUT',
                body: JSON.stringify({ username: username, avatar_url: nextAvatar })
            }).then(function(data) {
                currentUser = data.user;
                token = data.token;
                localStorage.setItem('token', token);
                closeModal();
                render();
                if (ws && ws.readyState === ws.OPEN) {
                    ws.close();
                } else {
                    connectWebSocket();
                }
            }).catch(function(e) {
                alert(e.message);
            });
        };

        $('#modalOverlay').onclick = function(e) { if (e.target.id === 'modalOverlay') closeModal(); };
        $('#cancelBtn').onclick = closeModal;
        if ($('#modalCloseBtn')) $('#modalCloseBtn').onclick = closeModal;
    }

    function renderVoiceGrid() {
        var c = $('#voiceGridOverlay'); if (!c || !currentVoiceChannel) return;
        var html = '<div class="voice-grid-header">';
        html += '<h3>' + escapeHtml(currentVoiceChannel.name) + ' — ' + (voiceParticipants.size + 1) + ' участников</h3>';
        html += '<button class="close-btn" id="closeVoiceGrid">' + icon('close') + '</button></div>';
        html += '<div class="voice-grid-container">';
        var mySpeaking = speakingUsers.has(currentUser.id);
        html += '<div class="voice-grid-item ' + (mySpeaking ? 'speaking' : '') + (isScreenSharing ? ' streaming' : '') + '" data-user-id="' + currentUser.id + '">';
        if (isScreenSharing && screenStream) {
            html += '<video id="my-screen-video" autoplay muted playsinline></video>';
        } else {
            html += '<div class="avatar">' + renderAvatarContent(currentUser.username, currentUser.avatar_url) + '</div>';
        }
        html += '<div class="username">' + escapeHtml(currentUser.username) + ' (Вы)</div>';
        html += '<div class="status-icons">';
        if (isScreenSharing) html += '<span title="Стримит">' + icon('video') + '</span>';
        if (isMuted) html += '<span title="Замьючен">' + icon('muted') + '</span>';
        if (isDeafened) html += '<span title="Оглушён">' + icon('deafen') + '</span>';
        html += '</div></div>';
        voiceParticipants.forEach(function(p, uid) {
            var isSpeaking = speakingUsers.has(uid);
            var streams = remoteStreams.get(uid);
            var hasScreen = streams && streams.screen;
            var isFocused = focusedStream === uid;
            html += '<div class="voice-grid-item ' + (isSpeaking ? 'speaking' : '') + (p.streaming ? ' streaming' : '') + (isFocused ? ' focused' : '') + '" data-user-id="' + uid + '" data-focusable="' + (hasScreen ? 'true' : 'false') + '">';
            if (hasScreen) {
                html += '<video id="screen-video-' + uid + '" autoplay playsinline></video>';
            } else {
                html += '<div class="avatar">' + renderAvatarContent(p.username, p.avatar_url) + '</div>';
            }
            html += '<div class="username">' + escapeHtml(p.username) + '</div>';
            html += '<div class="status-icons">';
            if (p.streaming) html += '<span title="Стримит">' + icon('video') + '</span>';
            if (p.muted) html += '<span title="Замьючен">' + icon('muted') + '</span>';
            if (p.deafened) html += '<span title="Оглушён">' + icon('deafen') + '</span>';
            html += '</div></div>';
        });
        html += '</div>';
        c.innerHTML = html;
        $('#closeVoiceGrid').onclick = function() { showVoiceGrid = false; render(); };
        if (isScreenSharing && screenStream) {
            var myVideo = document.getElementById('my-screen-video');
            if (myVideo) myVideo.srcObject = screenStream;
        }
        remoteStreams.forEach(function(streams, uid) {
            if (streams.screen) {
                var video = document.getElementById('screen-video-' + uid);
                if (video) video.srcObject = streams.screen;
            }
        });
        $$('.voice-grid-item[data-focusable="true"]').forEach(function(el) {
            el.onclick = function() {
                var uid = el.getAttribute('data-user-id');
                focusedStream = focusedStream === uid ? null : uid;
                renderVoiceGrid();
            };
        });
    }

    function renderChatArea() {
        var c = $('#chatArea'); if (!c) return;
        if (!currentChannel) {
            c.innerHTML = '<div class="empty-state"><div class="icon">' + icon('message') + '</div><h3>Выберите канал</h3><p>Выберите текстовый канал для общения</p></div>';
            return;
        }
        c.innerHTML =
            '<div class="chat-header"><span class="icon">' + icon('hash') + '</span><span>' + escapeHtml(currentChannel.name) + '</span></div>' +
            '<div class="messages-container" id="messagesContainer"></div>' +
            '<div class="typing-indicator"></div>' +
            '<div class="attachment-preview" id="attachmentPreview" style="display:none;"></div>' +
            '<div class="message-input-container"><div class="message-input">' +
            '<input type="file" id="attachmentInput" accept="image/png,image/jpeg,image/jpg,image/gif,image/webp" style="display:none;">' +
            '<button id="attachBtn" class="attach-btn" type="button" title="Прикрепить фото">' + icon('attach') + '</button>' +
            '<input type="text" id="messageInput" placeholder="Написать в #' + escapeHtml(currentChannel.name) + '" maxlength="2000">' +
            '<button id="sendBtn" type="button">' + icon('send') + '</button></div></div>';
        renderMessages();
        setupMessageInput();
        renderAttachmentPreview();
    }

    function renderMessages() {
        var c = $('#messagesContainer'); if (!c) return;
        if (!messages.length) {
            c.innerHTML = '<div class="empty-state"><div class="icon">' + icon('message') + '</div><h3>Начните общение!</h3><p>Отправьте первое сообщение</p></div>';
            return;
        }
        var html = '';
        messages.forEach(function(m) {
            var un = m.username || m.sender_username;
            html += '<div class="message">';
            html += '<div class="avatar">' + renderAvatarContent(un, m.avatar_url || m.sender_avatar || m.recipient_avatar) + '</div>';
            html += '<div class="content">';
            html += '<div class="header"><span class="author">' + escapeHtml(un) + '</span>';
            html += '<span class="timestamp">' + formatTime(m.created_at) + '</span></div>';
            if (m.content) html += '<div class="text">' + escapeHtml(m.content) + '</div>';
            if (m.image_url) html += '<img class="attachment" src="' + escapeHtml(m.image_url) + '" alt="Вложение">';
            html += '</div></div>';
        });
        c.innerHTML = html;
        scrollToBottom();
    }

    function renderMembers() {
        var c = $('#membersSidebar'); if (!c || !currentServer || !currentServer.members) return;
        var online = currentServer.members.filter(function(m) { return m.status === 'online'; });
        var offline = currentServer.members.filter(function(m) { return m.status !== 'online'; });
        var html = '<div class="members-category">В СЕТИ — ' + online.length + '</div>';
        online.forEach(function(m) {
            var inVoice = getMemberVoiceChannel(m.id);
            html += '<div class="member-item" data-member-id="' + m.id + '">';
            html += '<div class="avatar">' + renderAvatarContent(m.username, m.avatar_url) + '<div class="status-dot online"></div></div>';
            html += '<span class="name">' + escapeHtml(m.username) + '</span>';
            if (inVoice) html += '<span class="voice-icon" title="В голосовом канале">' + icon('voice') + '</span>';
            html += '</div>';
        });
        html += '<div class="members-category">НЕ В СЕТИ — ' + offline.length + '</div>';
        offline.forEach(function(m) {
            html += '<div class="member-item" data-member-id="' + m.id + '">';
            html += '<div class="avatar">' + renderAvatarContent(m.username, m.avatar_url) + '<div class="status-dot offline"></div></div>';
            html += '<span class="name">' + escapeHtml(m.username) + '</span></div>';
        });
        c.innerHTML = html;
        $$('.member-item[data-member-id]').forEach(function(el) {
            el.onclick = function() { startDM(el.getAttribute('data-member-id')); };
        });
    }

    function getMemberVoiceChannel(uid) {
        if (!currentServer || !currentServer.channels) return null;
        for (var i = 0; i < currentServer.channels.length; i++) {
            var ch = currentServer.channels[i];
            if (ch.type === 'voice' && ch.voiceParticipants) {
                for (var j = 0; j < ch.voiceParticipants.length; j++) {
                    var p = ch.voiceParticipants[j];
                    if ((p.visitorId || p.odego) === uid) return ch;
                }
            }
        }
        return null;
    }

    function renderDMSidebar() {
        var c = $('#dmSidebar'); if (!c) return;
        c.innerHTML =
            '<div class="dm-header"><input type="text" class="dm-search" placeholder="Найти пользователя" id="dmSearch"></div>' +
            '<div class="dm-list" id="dmList"></div>' +
            '<div class="user-panel" id="userPanel"></div>';
        renderDMList();
        renderUserPanel();
        $('#dmSearch').oninput = function(e) {
            var q = e.target.value;
            if (q.length < 2) { renderDMList(); return; }
            api('/api/users/search?q=' + encodeURIComponent(q)).then(function(users) {
                var list = $('#dmList');
                if (!users.length) { list.innerHTML = '<div class="empty-state"><p>Никого не найдено</p></div>'; return; }
                var html = '';
                users.forEach(function(u) {
                    html += '<div class="dm-item" data-user-id="' + u.id + '">';
                    html += '<div class="avatar">' + renderAvatarContent(u.username, u.avatar_url) + '</div>';
                    html += '<span class="name">' + escapeHtml(u.username) + '</span></div>';
                });
                list.innerHTML = html;
                $$('.dm-item[data-user-id]').forEach(function(el) {
                    el.onclick = function() { startDM(el.getAttribute('data-user-id')); };
                });
            });
        };
    }

    function renderDMList() {
        api('/api/dm').then(function(convs) {
            var list = $('#dmList'); if (!list) return;
            if (!convs.length) { list.innerHTML = '<div class="empty-state"><p>Нет бесед</p></div>'; return; }
            var html = '';
            convs.forEach(function(c) {
                html += '<div class="dm-item ' + (currentDM && currentDM.id === c.id ? 'active' : '') + '" data-dm-id="' + c.id + '" data-dm-name="' + escapeHtml(c.username) + '">';
                html += '<div class="avatar">' + renderAvatarContent(c.username, c.avatar_url) + '</div>';
                html += '<span class="name">' + escapeHtml(c.username) + '</span></div>';
            });
            list.innerHTML = html;
            $$('.dm-item[data-dm-id]').forEach(function(el) {
                el.onclick = function() { selectDM(el.getAttribute('data-dm-id'), el.getAttribute('data-dm-name')); };
            });
        });
    }

    function renderDMChatArea() {
        var c = $('#chatArea'); if (!c) return;
        if (!currentDM) {
            c.innerHTML = '<div class="empty-state"><div class="icon">' + icon('message') + '</div><h3>Личные сообщения</h3><p>Выберите беседу или найдите пользователя</p></div>';
            return;
        }
        c.innerHTML =
            '<div class="chat-header"><span class="icon">' + icon('at') + '</span><span>' + escapeHtml(currentDM.username) + '</span></div>' +
            '<div class="messages-container" id="messagesContainer"></div>' +
            '<div class="typing-indicator"></div>' +
            '<div class="attachment-preview" id="attachmentPreview" style="display:none;"></div>' +
            '<div class="message-input-container"><div class="message-input">' +
            '<input type="file" id="attachmentInput" accept="image/png,image/jpeg,image/jpg,image/gif,image/webp" style="display:none;">' +
            '<button id="attachBtn" class="attach-btn" type="button" title="Прикрепить фото">' + icon('attach') + '</button>' +
            '<input type="text" id="messageInput" placeholder="Написать @' + escapeHtml(currentDM.username) + '" maxlength="2000">' +
            '<button id="sendDMBtn" type="button">' + icon('send') + '</button></div></div>';
        renderMessages();
        setupDMInput();
        renderAttachmentPreview();
    }

    // ============================================
    // MODALS & ACTIONS
    // ============================================

    function showCreateServerModal() {
        $('#modalContainer').innerHTML =
            '<div class="modal-overlay" id="modalOverlay"><div class="modal">' +
            '<button class="modal-close" id="modalCloseBtn">' + icon('close') + '</button>' +
            '<div class="modal-header"><h2>Создать или присоединиться</h2></div>' +
            '<div class="modal-tabs"><button class="active" id="createTab">Создать</button><button id="joinTab">Присоединиться</button></div>' +
            '<div class="modal-body" id="modalBody"><div class="form-group"><label>Название сервера</label><input type="text" id="serverName" maxlength="100" placeholder="Мой сервер"></div></div>' +
            '<div class="modal-footer"><button class="btn secondary" id="cancelBtn">Отмена</button><button class="btn" id="modalAction">Создать</button></div>' +
            '</div></div>';
        $('#modalOverlay').onclick = function(e) { if (e.target.id === 'modalOverlay') closeModal(); };
        $('#cancelBtn').onclick = closeModal;
        if ($('#modalCloseBtn')) $('#modalCloseBtn').onclick = closeModal;
        $('#createTab').onclick = function() {
            $$('.modal-tabs button').forEach(function(b) { b.classList.remove('active'); });
            $('#createTab').classList.add('active');
            $('#modalBody').innerHTML = '<div class="form-group"><label>Название сервера</label><input type="text" id="serverName" maxlength="100" placeholder="Мой сервер"></div>';
            $('#modalAction').textContent = 'Создать';
            $('#modalAction').onclick = createServer;
        };
        $('#joinTab').onclick = function() {
            $$('.modal-tabs button').forEach(function(b) { b.classList.remove('active'); });
            $('#joinTab').classList.add('active');
            $('#modalBody').innerHTML = '<div class="form-group"><label>Код приглашения</label><input type="text" id="inviteCode" maxlength="10" placeholder="abc12345"></div>';
            $('#modalAction').textContent = 'Присоединиться';
            $('#modalAction').onclick = joinServerAction;
        };
        $('#modalAction').onclick = createServer;
    }

    function showCreateChannelModal(type) {
        $('#modalContainer').innerHTML =
            '<div class="modal-overlay" id="modalOverlay"><div class="modal">' +
            '<button class="modal-close" id="modalCloseBtn">' + icon('close') + '</button>' +
            '<div class="modal-header"><h2>Создать ' + (type === 'voice' ? 'голосовой' : 'текстовый') + ' канал</h2></div>' +
            '<div class="modal-body"><div class="form-group"><label>Название канала</label><input type="text" id="channelName" maxlength="100" placeholder="' + (type === 'voice' ? 'Голосовой чат' : 'общий') + '"></div></div>' +
            '<div class="modal-footer"><button class="btn secondary" id="cancelBtn">Отмена</button><button class="btn" id="createChannelBtn">Создать</button></div>' +
            '</div></div>';
        $('#modalOverlay').onclick = function(e) { if (e.target.id === 'modalOverlay') closeModal(); };
        $('#cancelBtn').onclick = closeModal;
        if ($('#modalCloseBtn')) $('#modalCloseBtn').onclick = closeModal;
        $('#createChannelBtn').onclick = function() { createChannel(type); };
    }

    function showServerSettings() {
        if (!currentServer) return;
        var isOwner = currentServer.owner_id === currentUser.id;
        var footer = isOwner
            ? '<button class="btn danger" id="deleteServerBtn">Удалить сервер</button>'
            : '<button class="btn danger" id="leaveServerBtn">Покинуть сервер</button>';
        $('#modalContainer').innerHTML =
            '<div class="modal-overlay" id="modalOverlay"><div class="modal">' +
            '<button class="modal-close" id="modalCloseBtn">' + icon('close') + '</button>' +
            '<div class="modal-header"><h2>' + escapeHtml(currentServer.name) + '</h2></div>' +
            '<div class="modal-body"><div class="form-group"><label>Код приглашения</label><div class="invite-code" id="inviteCodeDisplay">Загрузка...</div><button class="btn secondary" id="copyInviteBtn" style="margin-top:8px;">Копировать код</button><p style="font-size:12px;color:var(--text-muted);margin-top:8px;">Поделитесь этим кодом с друзьями</p></div></div>' +
            '<div class="modal-footer">' + footer + '<button class="btn secondary" id="closeBtn">Закрыть</button></div>' +
            '</div></div>';
        $('#modalOverlay').onclick = function(e) { if (e.target.id === 'modalOverlay') closeModal(); };
        $('#closeBtn').onclick = closeModal;
        if ($('#modalCloseBtn')) $('#modalCloseBtn').onclick = closeModal;
        if ($('#deleteServerBtn')) $('#deleteServerBtn').onclick = deleteServer;
        if ($('#leaveServerBtn')) $('#leaveServerBtn').onclick = leaveServer;
        if ($('#copyInviteBtn')) $('#copyInviteBtn').onclick = function() {
            var code = ($('#inviteCodeDisplay') || {}).textContent;
            if (!code || code === 'Загрузка...') return;
            navigator.clipboard.writeText(code).then(function() { $('#copyInviteBtn').textContent = 'Скопировано'; setTimeout(function(){ if ($('#copyInviteBtn')) $('#copyInviteBtn').textContent = 'Копировать код'; }, 1200); });
        };
        api('/api/servers/' + currentServer.id + '/invite').then(function(d) {
            var el = $('#inviteCodeDisplay');
            if (el) el.textContent = d.invite_code;
        });
    }

    function closeModal() { $('#modalContainer').innerHTML = ''; }

    function loadServers() {
        return api('/api/servers').then(function(d) { servers = d; });
    }

    function selectServer(id) {
        api('/api/servers/' + id).then(function(d) {
            currentServer = d;
            currentChannel = d.channels ? d.channels.find(function(c) { return c.type === 'text'; }) : null;
            currentDM = null;
            clearPendingAttachment();
            render();
            if (currentChannel) loadMessages();
        });
    }

    function selectHome() { currentServer = null; currentChannel = null; clearPendingAttachment(); render(); }

    function selectChannel(id) {
        if (!currentServer) return;
        var ch = currentServer.channels.find(function(c) { return c.id === id; });
        if (!ch || ch.type !== 'text') return;
        currentChannel = ch;
        clearPendingAttachment();
        renderChatArea();
        loadMessages();
    }

    function loadMessages() {
        if (!currentChannel) return;
        api('/api/channels/' + currentChannel.id + '/messages?limit=50').then(function(d) {
            messages = d; renderMessages();
        });
    }

    function setupAttachmentInput() {
        var attachBtn = $('#attachBtn');
        var attachmentInput = $('#attachmentInput');
        if (attachBtn && attachmentInput) {
            attachBtn.onclick = function() { attachmentInput.click(); };
            attachmentInput.onchange = function(e) {
                var file = e.target.files && e.target.files[0];
                if (!file) return;
                if (!file.type || file.type.indexOf('image/') !== 0) {
                    alert('Можно прикреплять только изображения');
                    attachmentInput.value = '';
                    return;
                }
                if (file.size > 4 * 1024 * 1024) {
                    alert('Изображение слишком большое (максимум 4 МБ)');
                    attachmentInput.value = '';
                    return;
                }
                var reader = new FileReader();
                reader.onload = function(evt) {
                    pendingAttachment = evt.target.result;
                    pendingAttachmentName = file.name;
                    renderAttachmentPreview();
                };
                reader.readAsDataURL(file);
                attachmentInput.value = '';
            };
        }
    }

    function setupMessageInput() {
        var inp = $('#messageInput'); if (!inp) return;
        setupAttachmentInput();
        inp.onkeydown = function(e) {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
        };
        inp.oninput = function() {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'TYPING_START', channelId: currentChannel.id }));
            }
        };
        inp.focus();
        $('#sendBtn').onclick = sendMessage;
    }

    function sendMessage() {
        var inp = $('#messageInput');
        var content = inp && inp.value ? inp.value.trim() : '';
        if ((!content && !pendingAttachment) || !currentChannel) return;
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'CHANNEL_MESSAGE', channelId: currentChannel.id, content: content, imageUrl: pendingAttachment }));
        }
        inp.value = '';
        clearPendingAttachment();
    }

    function selectDM(id, name) {
        currentDM = { id: id, username: name };
        clearPendingAttachment();
        api('/api/dm/' + id + '?limit=50').then(function(d) {
            messages = d; renderDMChatArea();
        });
    }

    function startDM(id) {
        currentServer = null; currentChannel = null;
        clearPendingAttachment();
        api('/api/users/' + id).then(function(u) {
            currentDM = { id: id, username: u.username };
            return api('/api/dm/' + id + '?limit=50');
        }).then(function(d) { messages = d; render(); });
    }

    function setupDMInput() {
        var inp = $('#messageInput'); if (!inp) return;
        setupAttachmentInput();
        inp.onkeydown = function(e) {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendDM(); }
        };
        inp.oninput = function() {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'TYPING_START', recipientId: currentDM.id }));
            }
        };
        inp.focus();
        $('#sendDMBtn').onclick = sendDM;
    }

    function sendDM() {
        var inp = $('#messageInput');
        var content = inp && inp.value ? inp.value.trim() : '';
        if ((!content && !pendingAttachment) || !currentDM) return;
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'DIRECT_MESSAGE', recipientId: currentDM.id, content: content, imageUrl: pendingAttachment }));
        }
        inp.value = '';
        clearPendingAttachment();
    }

    function createServer() {
        var name = ($('#serverName') || {}).value;
        if (!name || !name.trim()) { alert('Введите название сервера'); return; }
        api('/api/servers', { method: 'POST', body: JSON.stringify({ name: name.trim() }) })
            .then(function(s) { servers.push(s); closeModal(); selectServer(s.id); })
            .catch(function(e) { alert(e.message); });
    }

    function joinServerAction() {
        var code = ($('#inviteCode') || {}).value;
        if (!code || !code.trim()) { alert('Введите код приглашения'); return; }
        api('/api/servers/join/' + code.trim(), { method: 'POST' })
            .then(function(s) { servers.push(s); closeModal(); selectServer(s.id); })
            .catch(function(e) { alert(e.message); });
    }

    function createChannel(type) {
        var name = ($('#channelName') || {}).value;
        if (!name || !name.trim()) { alert('Введите название канала'); return; }
        api('/api/servers/' + currentServer.id + '/channels', { method: 'POST', body: JSON.stringify({ name: name.trim(), type: type }) })
            .then(function() { closeModal(); })
            .catch(function(e) { alert(e.message); });
    }

    function deleteChannel(id) {
        if (!confirm('Удалить этот канал?')) return;
        api('/api/channels/' + id, { method: 'DELETE' }).catch(function(e) { alert(e.message); });
    }

    function deleteServer() {
        if (!confirm('Вы уверены, что хотите удалить сервер "' + currentServer.name + '"? Это действие нельзя отменить.')) return;
        api('/api/servers/' + currentServer.id, { method: 'DELETE' })
            .then(function() {
                servers = servers.filter(function(s) { return s.id !== currentServer.id; });
                currentServer = null; currentChannel = null; closeModal(); render();
            })
            .catch(function(e) { alert(e.message); });
    }

    function leaveServer() {
        if (!confirm('Покинуть сервер "' + currentServer.name + '"?')) return;
        api('/api/servers/' + currentServer.id + '/leave', { method: 'POST' })
            .then(function() {
                servers = servers.filter(function(s) { return s.id !== currentServer.id; });
                currentServer = null; currentChannel = null; closeModal(); render();
            })
            .catch(function(e) { alert(e.message); });
    }

    function scrollToBottom() {
        var c = $('#messagesContainer');
        if (c) c.scrollTop = c.scrollHeight;
    }

    function logout() {
        if (currentVoiceChannel) leaveVoiceChannel();
        if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
        token = null; currentUser = null;
        localStorage.removeItem('token');
        if (ws) ws.close();
        servers = []; currentServer = null; currentChannel = null; currentDM = null; messages = [];
        pendingVoiceRejoin = null;
        render();
    }

    // ============================================
    // KEYBOARD SHORTCUTS
    // ============================================

    document.addEventListener('keydown', function(e) {
        if (e.ctrlKey && e.key === 'd') {
            e.preventDefault();
            debugMode = !debugMode;
            updateDebugPanelVisibility();
        }
        if (e.key === 'Escape') {
            if ($('#modalOverlay')) closeModal();
            else if (showVoiceGrid) { showVoiceGrid = false; render(); }
            else if (focusedStream) { focusedStream = null; renderVoiceGrid(); }
        }
        if (e.key === 'm' && !e.ctrlKey && currentVoiceChannel && document.activeElement.tagName !== 'INPUT') {
            toggleMute();
        }
    });

    // ============================================
    // INIT
    // ============================================

    function init() {
        var debugToggleBtn = document.getElementById('debugToggleBtn');
        if (debugToggleBtn) {
            debugToggleBtn.onclick = function() {
                isDebugPanelVisible = !isDebugPanelVisible;
                updateDebugPanelVisibility();
            };
        }
        updateDebugPanelVisibility();
        token = localStorage.getItem('token');
        if (token) {
            api('/api/auth/me')
                .then(function(u) {
                    currentUser = u;
                    connectWebSocket();
                    // ИСПРАВЛЕНИЕ 11: Загружаем ICE-конфиг параллельно с серверами.
                    return Promise.all([loadIceConfig(), loadServers()]);
                })
                .then(function() { render(); })
                .catch(function() {
                    token = null;
                    localStorage.removeItem('token');
                    render();
                });
        } else {
            render();
        }
    }

    init();
})();
</script>
</body>
</html>
`;
}
