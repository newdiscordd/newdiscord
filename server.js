/**
 * Discord Clone - Full Stack Server with Voice Chat
 * ИСПРАВЛЕННАЯ ВЕРСИЯ
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

const ICE_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
];

// ============================================
// ИНИЦИАЛИЗАЦИЯ
// ============================================

const app = express();
const server = http.createServer(app);

app.use(cors());
app.use(express.json());

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
                edited_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS direct_messages (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                read_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
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
const clients = new Map();
const wsUserMap = new Map();

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
    
    if (room.has(odego)) {
        console.log(`[VOICE] User ${username} already in channel ${channelId}, skipping`);
        return;
    }
    
    const existingParticipants = Array.from(room.values());
    
    const participant = {
        odego: odego,
        visitorId: odego,
        username: username,
        muted: false,
        deafened: false
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
                            signal: msg.signal
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

                case 'CHANNEL_MESSAGE': {
                    const { channelId, content } = msg;
                    if (!content?.trim() || content.length > 2000) break;
                    
                    const ch = await pool.query('SELECT * FROM channels WHERE id = $1', [channelId]);
                    if (!ch.rows[0]) break;
                    
                    const mem = await pool.query('SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2', [ch.rows[0].server_id, odego]);
                    if (!mem.rows[0]) break;
                    
                    const msgId = uuidv4();
                    await pool.query('INSERT INTO messages (id, channel_id, author_id, content) VALUES ($1, $2, $3, $4)', [msgId, channelId, odego, content.trim()]);
                    
                    const newMsg = await pool.query('SELECT m.*, u.username, u.avatar_url FROM messages m JOIN users u ON m.author_id = u.id WHERE m.id = $1', [msgId]);
                    broadcastToServer(ch.rows[0].server_id, { type: 'NEW_CHANNEL_MESSAGE', message: newMsg.rows[0] });
                    break;
                }

                case 'DIRECT_MESSAGE': {
                    const { recipientId, content } = msg;
                    if (!content?.trim() || content.length > 2000) break;
                    
                    const recipient = await pool.query('SELECT id, username, avatar_url FROM users WHERE id = $1', [recipientId]);
                    if (!recipient.rows[0]) break;
                    
                    const msgId = uuidv4();
                    await pool.query('INSERT INTO direct_messages (id, sender_id, recipient_id, content) VALUES ($1, $2, $3, $4)', [msgId, odego, recipientId, content.trim()]);
                    
                    const sender = await pool.query('SELECT username, avatar_url FROM users WHERE id = $1', [odego]);
                    const newMsg = {
                        id: msgId, sender_id: odego, recipient_id: recipientId, content: content.trim(),
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
        const { content } = req.body;
        if (!content?.trim() || content.length > 2000) return res.status(400).json({ error: 'Некорректное сообщение' });
        
        const channel = await pool.query('SELECT * FROM channels WHERE id = $1', [req.params.channelId]);
        if (!channel.rows[0]) return res.status(404).json({ error: 'Канал не найден' });
        
        const mem = await pool.query('SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2', [channel.rows[0].server_id, req.user.id]);
        if (!mem.rows[0]) return res.status(403).json({ error: 'Нет доступа' });
        
        const msgId = uuidv4();
        await pool.query('INSERT INTO messages (id, channel_id, author_id, content) VALUES ($1, $2, $3, $4)', [msgId, req.params.channelId, req.user.id, content.trim()]);
        
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
        const { content } = req.body;
        if (!content?.trim() || content.length > 2000) return res.status(400).json({ error: 'Некорректное сообщение' });
        
        const recipient = await pool.query('SELECT id, username, avatar_url FROM users WHERE id = $1', [req.params.odego]);
        if (!recipient.rows[0]) return res.status(404).json({ error: 'Пользователь не найден' });
        
        const msgId = uuidv4();
        await pool.query('INSERT INTO direct_messages (id, sender_id, recipient_id, content) VALUES ($1, $2, $3, $4)', [msgId, req.user.id, req.params.odego, content.trim()]);
        
        const sender = await pool.query('SELECT username, avatar_url FROM users WHERE id = $1', [req.user.id]);
        const msg = {
            id: msgId, sender_id: req.user.id, recipient_id: req.params.odego, content: content.trim(), created_at: new Date().toISOString(),
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

// Главная страница - будет во втором ответе
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

function getClientHTML() {
    return `
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Discord Clone</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-primary: #36393f;
            --bg-secondary: #2f3136;
            --bg-tertiary: #202225;
            --bg-accent: #40444b;
            --text-primary: #dcddde;
            --text-secondary: #8e9297;
            --text-muted: #72767d;
            --accent: #5865f2;
            --accent-hover: #4752c4;
            --green: #57f287;
            --yellow: #fee75c;
            --red: #ed4245;
            --online: #3ba55c;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            height: 100vh;
            overflow: hidden;
        }
        
        #app {
            display: flex;
            height: 100vh;
        }
        
        /* Auth */
        .auth-container {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, var(--bg-tertiary) 0%, var(--bg-primary) 100%);
        }
        
        .auth-box {
            background: var(--bg-secondary);
            padding: 32px;
            border-radius: 8px;
            width: 400px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        
        .auth-box h1 {
            color: var(--text-primary);
            margin-bottom: 8px;
            font-size: 24px;
            text-align: center;
        }
        
        .auth-box p {
            color: var(--text-secondary);
            margin-bottom: 24px;
            text-align: center;
        }
        
        .form-group {
            margin-bottom: 16px;
        }
        
        .form-group label {
            display: block;
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 4px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            font-size: 16px;
            outline: none;
            transition: box-shadow 0.2s;
        }
        
        .form-group input:focus {
            box-shadow: 0 0 0 2px var(--accent);
        }
        
        .btn {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 4px;
            background: var(--accent);
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .btn:hover {
            background: var(--accent-hover);
        }
        
        .btn.secondary {
            background: var(--bg-accent);
        }
        
        .btn.secondary:hover {
            background: #4f545c;
        }
        
        .btn.disconnect {
            background: var(--red);
            width: auto;
            padding: 8px 16px;
            font-size: 14px;
        }
        
        /* Servers List */
        .servers-list {
            width: 72px;
            background: var(--bg-tertiary);
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 12px 0;
            gap: 8px;
            overflow-y: auto;
        }
        
        .server-icon {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            background: var(--bg-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.2s;
            color: var(--text-primary);
            font-weight: 600;
            font-size: 18px;
        }
        
        .server-icon:hover, .server-icon.active {
            border-radius: 16px;
            background: var(--accent);
        }
        
        .server-icon.home {
            background: var(--accent);
            margin-bottom: 8px;
        }
        
        .server-icon.add {
            background: transparent;
            border: 2px dashed var(--text-muted);
            color: var(--green);
            font-size: 24px;
        }
        
        .server-icon.add:hover {
            border-color: var(--green);
            background: transparent;
        }
        
        /* Channels Sidebar */
        .channels-sidebar {
            width: 240px;
            background: var(--bg-secondary);
            display: flex;
            flex-direction: column;
        }
        
        .server-header {
            height: 48px;
            padding: 0 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--bg-tertiary);
            font-weight: 600;
            cursor: pointer;
        }
        
        .server-header:hover {
            background: var(--bg-accent);
        }
        
        .server-header button {
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 16px;
        }
        
        .channels-list {
            flex: 1;
            overflow-y: auto;
            padding: 8px 0;
        }
        
        .channel-category {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 8px 4px 16px;
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .channel-category .add-channel {
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 16px;
            padding: 0 8px;
        }
        
        .channel-category .add-channel:hover {
            color: var(--text-primary);
        }
        
        .channel {
            display: flex;
            align-items: center;
            padding: 8px 16px;
            margin: 0 8px;
            border-radius: 4px;
            cursor: pointer;
            color: var(--text-secondary);
            transition: all 0.1s;
        }
        
        .channel:hover {
            background: var(--bg-accent);
            color: var(--text-primary);
        }
        
        .channel.active {
            background: var(--bg-accent);
            color: var(--text-primary);
        }
        
        .channel-icon {
            margin-right: 8px;
            font-size: 20px;
        }
        
        .channel-name {
            font-size: 14px;
        }
        
        .voice-user {
            display: flex;
            align-items: center;
            padding: 4px 16px 4px 40px;
            font-size: 13px;
            color: var(--text-secondary);
            gap: 8px;
        }
        
        .voice-user.speaking {
            color: var(--green);
        }
        
        .voice-user .muted-icon {
            font-size: 12px;
            opacity: 0.7;
        }
        
        .voice-controls {
            padding: 12px;
            background: var(--bg-tertiary);
            border-top: 1px solid var(--bg-accent);
        }
        
        .voice-status {
            font-size: 12px;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }
        
        /* User Panel */
        .user-panel {
            height: 52px;
            background: var(--bg-tertiary);
            display: flex;
            align-items: center;
            padding: 0 8px;
            gap: 8px;
        }
        
        .user-panel .avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: 600;
        }
        
        .user-panel .avatar.speaking {
            box-shadow: 0 0 0 2px var(--green);
        }
        
        .user-panel .info {
            flex: 1;
            min-width: 0;
        }
        
        .user-panel .username {
            font-size: 14px;
            font-weight: 600;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .user-panel .status {
            font-size: 12px;
            color: var(--text-secondary);
        }
        
        .user-panel .actions {
            display: flex;
            gap: 4px;
        }
        
        .user-panel .actions button {
            width: 32px;
            height: 32px;
            border: none;
            border-radius: 4px;
            background: transparent;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .user-panel .actions button:hover {
            background: var(--bg-accent);
            color: var(--text-primary);
        }
        
        .user-panel .actions button.muted {
            color: var(--red);
        }
        
        /* Main Content */
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            min-width: 0;
        }
        
        .chat-header {
            height: 48px;
            padding: 0 16px;
            display: flex;
            align-items: center;
            gap: 8px;
            border-bottom: 1px solid var(--bg-tertiary);
            background: var(--bg-primary);
        }
        
        .chat-header .channel-icon {
            color: var(--text-muted);
            font-size: 24px;
        }
        
        .chat-header .channel-name {
            font-weight: 600;
            font-size: 16px;
        }
        
        .chat-header .channel-topic {
            color: var(--text-secondary);
            font-size: 14px;
            margin-left: 16px;
            padding-left: 16px;
            border-left: 1px solid var(--bg-accent);
        }
        
        .chat-area {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        
        .messages-container {
            flex: 1;
            overflow-y: auto;
            padding: 16px;
        }
        
        .welcome-message {
            text-align: center;
            padding: 32px;
            color: var(--text-secondary);
        }
        
        .welcome-message h3 {
            color: var(--text-primary);
            margin-bottom: 8px;
        }
        
        .message {
            display: flex;
            padding: 4px 16px;
            margin-bottom: 4px;
            position: relative;
        }
        
        .message:hover {
            background: var(--bg-secondary);
        }
        
        .message:hover .message-actions {
            display: flex;
        }
        
        .message .avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 600;
            margin-right: 16px;
            flex-shrink: 0;
        }
        
        .message-content {
            flex: 1;
            min-width: 0;
        }
        
        .message-header {
            display: flex;
            align-items: baseline;
            gap: 8px;
            margin-bottom: 4px;
        }
        
        .message-header .username {
            font-weight: 600;
            color: var(--text-primary);
        }
        
        .message-header .timestamp {
            font-size: 12px;
            color: var(--text-muted);
        }
        
        .message-header .edited {
            font-size: 10px;
            color: var(--text-muted);
        }
        
        .message-text {
            color: var(--text-primary);
            line-height: 1.4;
            word-wrap: break-word;
        }
        
        .message-actions {
            display: none;
            position: absolute;
            right: 16px;
            top: 4px;
            gap: 4px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            padding: 4px;
        }
        
        .message-actions button {
            background: none;
            border: none;
            cursor: pointer;
            font-size: 14px;
            padding: 4px 8px;
            border-radius: 4px;
            opacity: 0.7;
        }
        
        .message-actions button:hover {
            background: var(--bg-accent);
            opacity: 1;
        }
        
        .typing-indicator {
            padding: 0 16px;
            height: 24px;
            font-size: 13px;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
        }
        
        .typing-dots {
            display: inline-block;
            width: 24px;
        }
        
        .typing-dots::after {
            content: '...';
            animation: typing 1s infinite;
        }
        
        @keyframes typing {
            0%, 20% { content: '.'; }
            40% { content: '..'; }
            60%, 100% { content: '...'; }
        }
        
        .message-input-container {
            padding: 0 16px 24px;
        }
        
        .editing-banner {
            background: var(--accent);
            color: white;
            padding: 8px 12px;
            border-radius: 4px 4px 0 0;
            font-size: 13px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .editing-banner button {
            background: none;
            border: none;
            color: white;
            cursor: pointer;
            font-size: 16px;
            opacity: 0.8;
        }
        
        .editing-banner button:hover {
            opacity: 1;
        }
        
        .message-input-wrapper {
            display: flex;
            background: var(--bg-accent);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .message-input-wrapper input {
            flex: 1;
            padding: 12px 16px;
            border: none;
            background: transparent;
            color: var(--text-primary);
            font-size: 16px;
            outline: none;
        }
        
        .message-input-wrapper input::placeholder {
            color: var(--text-muted);
        }
        
        .send-btn {
            padding: 12px 16px;
            border: none;
            background: transparent;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 18px;
            transition: color 0.2s;
        }
        
        .send-btn:hover {
            color: var(--accent);
        }
        
        /* Members Sidebar */
        .members-sidebar {
            width: 240px;
            background: var(--bg-secondary);
            overflow-y: auto;
        }
        
        .members-header {
            padding: 12px 16px;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
        }
        
        .member-category {
            padding: 16px 16px 4px;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
        }
        
        .member {
            display: flex;
            align-items: center;
            padding: 8px 16px;
            gap: 12px;
            cursor: pointer;
            border-radius: 4px;
            margin: 0 8px;
        }
        
        .member:hover {
            background: var(--bg-accent);
        }
        
        .member.offline {
            opacity: 0.5;
        }
        
        .member .avatar.small, .voice-user .avatar.small {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: 600;
        }
        
        .member .avatar.small.speaking, .voice-user .avatar.small.speaking {
            box-shadow: 0 0 0 2px var(--green);
        }
        
        .member-name {
            flex: 1;
            font-size: 14px;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--text-muted);
        }
        
        .status-dot.online {
            background: var(--online);
        }
        
        /* Modal */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.85);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        
        .modal {
            background: var(--bg-primary);
            border-radius: 8px;
            width: 440px;
            max-width: 90%;
            max-height: 90vh;
            overflow: hidden;
        }
        
        .modal-header {
            padding: 16px;
            text-align: center;
        }
        
        .modal-header h2 {
            font-size: 20px;
            color: var(--text-primary);
        }
        
        .modal-body {
            padding: 0 16px 16px;
        }
        
        .modal-footer {
            padding: 16px;
            background: var(--bg-secondary);
            display: flex;
            justify-content: flex-end;
            gap: 12px;
        }
        
        .modal-footer .btn {
            width: auto;
            padding: 12px 24px;
        }
        
        /* Audio Settings */
        .audio-select {
            width: 100%;
            padding: 10px;
            border: none;
            border-radius: 4px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            font-size: 14px;
            cursor: pointer;
        }
        
        .audio-select:focus {
            outline: 2px solid var(--accent);
        }
        
        .mic-test {
            margin-top: 8px;
        }
        
        .mic-level-bar {
            width: 100%;
            height: 20px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            overflow: hidden;
        }
        
        .mic-level-fill {
            height: 100%;
            width: 0%;
            background: var(--green);
            transition: width 0.1s ease, background 0.2s ease;
            border-radius: 4px;
        }
        
        #audioSettingsBtn {
            background: transparent;
            border: none;
            font-size: 16px;
            cursor: pointer;
            opacity: 0.7;
            transition: opacity 0.2s;
        }
        
        #audioSettingsBtn:hover {
            opacity: 1;
        }
        
        /* Context Menu */
        .context-menu {
            position: fixed;
            background: var(--bg-tertiary);
            border-radius: 4px;
            padding: 8px;
            min-width: 180px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.3);
            z-index: 1001;
            display: none;
        }
        
        .context-menu-item {
            padding: 8px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            color: var(--text-primary);
        }
        
        .context-menu-item:hover {
            background: var(--accent);
        }
        
        .context-menu-item.danger {
            color: var(--red);
        }
        
        .context-menu-item.danger:hover {
            background: var(--red);
            color: white;
        }
        
        /* Loading */
        .loading {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: var(--text-secondary);
        }
        
        .loading-spinner {
            width: 48px;
            height: 48px;
            border: 4px solid var(--bg-accent);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 16px;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .no-channel {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: var(--text-secondary);
        }
        
        .no-channel h2 {
            color: var(--text-primary);
            margin-bottom: 8px;
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: transparent;
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--bg-tertiary);
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--bg-accent);
        }
    </style>
</head>
<body>
    <div id="app"></div>
    
    <script>
        var $ = function(s) { return document.querySelector(s); };
        var $$ = function(s) { return document.querySelectorAll(s); };

        var ws = null;
        var currentUser = null;
        var currentServer = null;
        var currentChannel = null;
        var currentVoiceChannel = null;
        var servers = [];
        var users = {};
        var messages = [];
        var voiceUsers = {};
        var localStream = null;
        var peerConnections = new Map();
        var audioContext = null;
        var localAnalyser = null;
        var speakingUsers = new Set();
        var isMuted = false;
        var isDeafened = false;
        var pendingCandidates = new Map();
        var typingUsers = new Map();
        var typingTimeout = null;
        var editingMessageId = null;

        var selectedMicId = localStorage.getItem('selectedMicId') || '';
        var selectedOutputId = localStorage.getItem('selectedOutputId') || '';

        var ICE_SERVERS = [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' },
            { urls: 'stun:stun2.l.google.com:19302' },
            { urls: 'stun:stun3.l.google.com:19302' },
            { urls: 'stun:stun4.l.google.com:19302' }
        ];

        function debug(msg, type) {
            var colors = { info: '#5865f2', success: '#57f287', error: '#ed4245', warn: '#fee75c' };
            console.log('%c[DEBUG] ' + msg, 'color: ' + (colors[type] || colors.info));
        }

        function escapeHtml(t) {
            if (!t) return '';
            return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }

        function getInitials(name) {
            if (!name) return '?';
            return name.split(' ').map(function(w) { return w[0]; }).join('').substring(0,2).toUpperCase();
        }

        function formatTime(ts) {
            var d = new Date(ts);
            return d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
        }

        function init() {
            render();
            var savedUser = localStorage.getItem('discord_user');
            if (savedUser) {
                try {
                    currentUser = JSON.parse(savedUser);
                    connectWebSocket();
                } catch (e) {
                    showAuth();
                }
            } else {
                showAuth();
            }
        }

        function showAuth() {
            $('#app').innerHTML = '<div class="auth-container"><div class="auth-box"><h1>Добро пожаловать!</h1><p>Войдите чтобы продолжить</p><div class="form-group"><label>Имя пользователя</label><input type="text" id="authUsername" placeholder="Введите имя" maxlength="32"></div><div class="form-group"><label>Email</label><input type="email" id="authEmail" placeholder="Введите email"></div><button class="btn" id="authBtn">Войти</button></div></div>';
            $('#authBtn').onclick = doAuth;
            $('#authUsername').onkeypress = function(e) { if (e.key === 'Enter') $('#authEmail').focus(); };
            $('#authEmail').onkeypress = function(e) { if (e.key === 'Enter') doAuth(); };
        }

        function doAuth() {
            var username = $('#authUsername').value.trim();
            var email = $('#authEmail').value.trim();
            if (!username || username.length < 2) { alert('Имя минимум 2 символа'); return; }
            if (!email || !email.includes('@')) { alert('Введите корректный email'); return; }
            currentUser = {
                id: 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9),
                username: username,
                email: email,
                avatar: null,
                status: 'online'
            };
            localStorage.setItem('discord_user', JSON.stringify(currentUser));
            connectWebSocket();
        }

        function connectWebSocket() {
            render();
            renderLoading();
            var protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            var wsUrl = protocol + '//' + location.host + '/ws';
            debug('Connecting to ' + wsUrl, 'info');
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function() {
                debug('WebSocket connected', 'success');
                ws.send(JSON.stringify({ type: 'AUTH', user: currentUser }));
            };
            
            ws.onmessage = function(e) {
                try {
                    var msg = JSON.parse(e.data);
                    handleMessage(msg);
                } catch (err) {
                    debug('Parse error: ' + err.message, 'error');
                }
            };
            
            ws.onerror = function(e) {
                debug('WebSocket error', 'error');
            };
            
            ws.onclose = function() {
                debug('WebSocket closed, reconnecting...', 'warn');
                setTimeout(connectWebSocket, 3000);
            };
        }

        function handleMessage(msg) {
            debug('Received: ' + msg.type, 'info');
            
            switch (msg.type) {
                case 'AUTH_SUCCESS':
                    currentUser = msg.user;
                    localStorage.setItem('discord_user', JSON.stringify(currentUser));
                    break;
                    
                case 'INIT_DATA':
                    servers = msg.servers || [];
                    users = {};
                    (msg.users || []).forEach(function(u) { users[u.id] = u; });
                    if (servers.length > 0 && !currentServer) {
                        selectServer(servers[0]);
                    }
                    renderAll();
                    break;
                    
                case 'USER_JOIN':
                    users[msg.user.id] = msg.user;
                    renderMembersList();
                    break;
                    
                case 'USER_LEAVE':
                    delete users[msg.userId];
                    renderMembersList();
                    break;
                    
                case 'USERS_UPDATE':
                    users = {};
                    (msg.users || []).forEach(function(u) { users[u.id] = u; });
                    renderMembersList();
                    break;
                    
                case 'MESSAGE':
                    if (currentChannel && msg.message.channelId === currentChannel.id) {
                        messages.push(msg.message);
                        renderMessages();
                        var mc = $('.messages-container');
                        if (mc) mc.scrollTop = mc.scrollHeight;
                    }
                    break;
                    
                case 'MESSAGE_HISTORY':
                    if (currentChannel && msg.channelId === currentChannel.id) {
                        messages = msg.messages || [];
                        renderMessages();
                        var mc2 = $('.messages-container');
                        if (mc2) mc2.scrollTop = mc2.scrollHeight;
                    }
                    break;
                    
                case 'MESSAGE_EDITED':
                    for (var i = 0; i < messages.length; i++) {
                        if (messages[i].id === msg.message.id) {
                            messages[i] = msg.message;
                            break;
                        }
                    }
                    renderMessages();
                    break;
                    
                case 'MESSAGE_DELETED':
                    messages = messages.filter(function(m) { return m.id !== msg.messageId; });
                    renderMessages();
                    break;
                    
                case 'TYPING_START':
                    if (currentChannel && msg.channelId === currentChannel.id && msg.userId !== currentUser.id) {
                        typingUsers.set(msg.userId, { username: msg.username, time: Date.now() });
                        renderTypingIndicator();
                    }
                    break;
                    
                case 'TYPING_STOP':
                    typingUsers.delete(msg.userId);
                    renderTypingIndicator();
                    break;
                    
                case 'VOICE_USER_JOINED':
                    if (!voiceUsers[msg.channelId]) voiceUsers[msg.channelId] = [];
                    var exists = voiceUsers[msg.channelId].find(function(u) { return u.id === msg.user.id; });
                    if (!exists) voiceUsers[msg.channelId].push(msg.user);
                    renderChannelsList();
                    
                    if (currentVoiceChannel && currentVoiceChannel.id === msg.channelId && msg.user.id !== currentUser.id) {
                        debug('User joined voice: ' + msg.user.username, 'success');
                        createPeerConnection(msg.user.id, true);
                    }
                    break;
                    
                case 'VOICE_USER_LEFT':
                    if (voiceUsers[msg.channelId]) {
                        voiceUsers[msg.channelId] = voiceUsers[msg.channelId].filter(function(u) { return u.id !== msg.userId; });
                    }
                    renderChannelsList();
                    closePeerConnection(msg.userId);
                    break;
                    
                case 'VOICE_USERS':
                    voiceUsers[msg.channelId] = msg.users || [];
                    renderChannelsList();
                    
                    if (currentVoiceChannel && currentVoiceChannel.id === msg.channelId) {
                        msg.users.forEach(function(u) {
                            if (u.id !== currentUser.id && !peerConnections.has(u.id)) {
                                debug('Creating peer for existing user: ' + u.username, 'info');
                                createPeerConnection(u.id, true);
                            }
                        });
                    }
                    break;
                    
                case 'VOICE_SIGNAL':
                    handleVoiceSignal(msg);
                    break;
                    
                case 'VOICE_SPEAKING':
                    if (msg.speaking) {
                        speakingUsers.add(msg.userId);
                    } else {
                        speakingUsers.delete(msg.userId);
                    }
                    renderChannelsList();
                    renderUserPanel();
                    break;
                    
                case 'SERVER_CREATED':
                    servers.push(msg.server);
                    renderServersList();
                    break;
                    
                case 'CHANNEL_CREATED':
                    if (currentServer && msg.channel.serverId === currentServer.id) {
                        currentServer.channels.push(msg.channel);
                        renderChannelsList();
                    }
                    break;
                    
                case 'ERROR':
                    debug('Server error: ' + msg.message, 'error');
                    alert('Ошибка: ' + msg.message);
                    break;
            }
        }

        function createPeerConnection(userId, initiator) {
            if (peerConnections.has(userId)) {
                debug('Peer exists for ' + userId.slice(0,8), 'warn');
                return peerConnections.get(userId);
            }
            
            debug('Creating peer for ' + userId.slice(0,8) + ' initiator=' + initiator, 'info');
            
            var pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
            peerConnections.set(userId, pc);
            pendingCandidates.set(userId, []);
            
            if (localStream) {
                localStream.getTracks().forEach(function(track) {
                    debug('Adding track: ' + track.kind, 'info');
                    pc.addTrack(track, localStream);
                });
            }
            
            pc.onicecandidate = function(e) {
                if (e.candidate) {
                    debug('Sending ICE candidate', 'info');
                    ws.send(JSON.stringify({
                        type: 'VOICE_SIGNAL',
                        targetUserId: userId,
                        signal: { type: 'candidate', candidate: e.candidate }
                    }));
                }
            };
            
            pc.oniceconnectionstatechange = function() {
                debug('ICE state [' + userId.slice(0,8) + ']: ' + pc.iceConnectionState, 
                    pc.iceConnectionState === 'connected' ? 'success' : 
                    pc.iceConnectionState === 'failed' ? 'error' : 'info');
                
                if (pc.iceConnectionState === 'failed') {
                    debug('Restarting ICE...', 'warn');
                    pc.restartIce();
                }
            };
            
            pc.ontrack = function(e) {
                debug('Received remote track from ' + userId.slice(0,8), 'success');
                
                var existingAudio = document.getElementById('audio-' + userId);
                if (existingAudio) existingAudio.remove();
                
                var audio = document.createElement('audio');
                audio.id = 'audio-' + userId;
                audio.autoplay = true;
                audio.srcObject = e.streams[0];
                
                if (selectedOutputId && audio.setSinkId) {
                    audio.setSinkId(selectedOutputId).catch(function(err) {
                        debug('setSinkId error: ' + err.message, 'warn');
                    });
                }
                
                if (isDeafened) audio.muted = true;
                document.body.appendChild(audio);
                
                audio.play().then(function() {
                    debug('Audio playing for ' + userId.slice(0,8), 'success');
                }).catch(function(err) {
                    debug('Audio play error: ' + err.message, 'error');
                });
                
                setupRemoteAudioAnalyser(userId, e.streams[0]);
            };
            
            if (initiator) {
                debug('Creating offer...', 'info');
                pc.createOffer({
                    offerToReceiveAudio: true,
                    offerToReceiveVideo: false
                }).then(function(offer) {
                    return pc.setLocalDescription(offer);
                }).then(function() {
                    debug('Sending offer to ' + userId.slice(0,8), 'success');
                    ws.send(JSON.stringify({
                        type: 'VOICE_SIGNAL',
                        targetUserId: userId,
                        signal: { type: 'offer', sdp: pc.localDescription }
                    }));
                }).catch(function(e) {
                    debug('Offer error: ' + e.message, 'error');
                });
            }
            
            return pc;
        }

        function handleVoiceSignal(msg) {
            var signal = msg.signal;
            var fromUserId = msg.fromUserId;
            
            debug('Voice signal: ' + signal.type + ' from ' + fromUserId.slice(0,8), 'info');
            
            var pc = peerConnections.get(fromUserId);
            
            if (signal.type === 'offer') {
                if (pc) {
                    closePeerConnection(fromUserId);
                }
                pc = createPeerConnection(fromUserId, false);
                
                pc.setRemoteDescription(new RTCSessionDescription(signal.sdp))
                    .then(function() {
                        debug('Remote description set', 'success');
                        var pending = pendingCandidates.get(fromUserId) || [];
                        pending.forEach(function(c) {
                            pc.addIceCandidate(new RTCIceCandidate(c)).catch(function(e) {
                                debug('Add pending ICE error: ' + e.message, 'error');
                            });
                        });
                        pendingCandidates.set(fromUserId, []);
                        return pc.createAnswer();
                    })
                    .then(function(answer) {
                        return pc.setLocalDescription(answer);
                    })
                    .then(function() {
                        debug('Sending answer to ' + fromUserId.slice(0,8), 'success');
                        ws.send(JSON.stringify({
                            type: 'VOICE_SIGNAL',
                            targetUserId: fromUserId,
                            signal: { type: 'answer', sdp: pc.localDescription }
                        }));
                    })
                    .catch(function(e) {
                        debug('Handle offer error: ' + e.message, 'error');
                    });
                    
            } else if (signal.type === 'answer') {
                if (pc && pc.signalingState === 'have-local-offer') {
                    pc.setRemoteDescription(new RTCSessionDescription(signal.sdp))
                        .then(function() {
                            debug('Answer accepted from ' + fromUserId.slice(0,8), 'success');
                            var pending = pendingCandidates.get(fromUserId) || [];
                            pending.forEach(function(c) {
                                pc.addIceCandidate(new RTCIceCandidate(c)).catch(function(e) {
                                    debug('Add pending ICE error: ' + e.message, 'error');
                                });
                            });
                            pendingCandidates.set(fromUserId, []);
                        })
                        .catch(function(e) {
                            debug('Set answer error: ' + e.message, 'error');
                        });
                }
                
            } else if (signal.type === 'candidate' && signal.candidate) {
                if (pc && pc.remoteDescription) {
                    pc.addIceCandidate(new RTCIceCandidate(signal.candidate))
                        .catch(function(e) {
                            debug('Add ICE error: ' + e.message, 'error');
                        });
                } else {
                    debug('Queuing ICE candidate', 'warn');
                    if (!pendingCandidates.has(fromUserId)) {
                        pendingCandidates.set(fromUserId, []);
                    }
                    pendingCandidates.get(fromUserId).push(signal.candidate);
                }
            }
        }

        function closePeerConnection(userId) {
            var pc = peerConnections.get(userId);
            if (pc) {
                pc.close();
                peerConnections.delete(userId);
            }
            pendingCandidates.delete(userId);
            speakingUsers.delete(userId);
            var audio = document.getElementById('audio-' + userId);
            if (audio) audio.remove();
        }

        function setupRemoteAudioAnalyser(userId, stream) {
            try {
                if (!audioContext) {
                    audioContext = new (window.AudioContext || window.webkitAudioContext)();
                }
                var analyser = audioContext.createAnalyser();
                analyser.fftSize = 256;
                audioContext.createMediaStreamSource(stream).connect(analyser);
                var data = new Uint8Array(analyser.frequencyBinCount);
                
                var checkInterval = setInterval(function() {
                    if (!peerConnections.has(userId)) {
                        clearInterval(checkInterval);
                        return;
                    }
                    analyser.getByteFrequencyData(data);
                    var sum = 0;
                    for (var i = 0; i < data.length; i++) sum += data[i];
                    var avg = sum / data.length;
                    var speaking = avg > 20;
                    
                    if (speaking !== speakingUsers.has(userId)) {
                        if (speaking) {
                            speakingUsers.add(userId);
                        } else {
                            speakingUsers.delete(userId);
                        }
                        renderChannelsList();
                    }
                }, 100);
            } catch (e) {
                debug('Remote analyser error: ' + e.message, 'error');
            }
        }

        function detectSpeaking() {
            if (!localAnalyser || !currentVoiceChannel) return;
            
            var data = new Uint8Array(localAnalyser.frequencyBinCount);
            var wasSpeaking = false;
            
            function check() {
                if (!currentVoiceChannel || !localAnalyser) return;
                
                localAnalyser.getByteFrequencyData(data);
                var sum = 0;
                for (var i = 0; i < data.length; i++) sum += data[i];
                var avg = sum / data.length;
                var speaking = avg > 20 && !isMuted;
                
                if (speaking !== wasSpeaking) {
                    wasSpeaking = speaking;
                    ws.send(JSON.stringify({
                        type: 'VOICE_SPEAKING',
                        channelId: currentVoiceChannel.id,
                        speaking: speaking
                    }));
                    
                    if (speaking) {
                        speakingUsers.add(currentUser.id);
                    } else {
                        speakingUsers.delete(currentUser.id);
                    }
                    renderChannelsList();
                    renderUserPanel();
                }
                
                requestAnimationFrame(check);
            }
            check();
        }

        function joinVoiceChannel(channel) {
            debug('Joining voice: ' + channel.name, 'warn');
            
            if (currentVoiceChannel && currentVoiceChannel.id === channel.id) {
                debug('Already in channel');
                return;
            }
            
            if (currentVoiceChannel) {
                leaveVoiceChannel();
                return;
            }
            
            var audioConstraints = {
                echoCancellation: true,
                noiseSuppression: true,
                autoGainControl: true
            };
            
            if (selectedMicId) {
                audioConstraints.deviceId = { exact: selectedMicId };
            }
            
            navigator.mediaDevices.getUserMedia({
                audio: audioConstraints,
                video: false
            }).then(function(stream) {
                debug('Got mic, tracks: ' + stream.getAudioTracks().length, 'success');
                localStream = stream;
                
                if (isMuted) {
                    stream.getAudioTracks().forEach(function(t) { t.enabled = false; });
                }
                
                try {
                    audioContext = new (window.AudioContext || window.webkitAudioContext)();
                    localAnalyser = audioContext.createAnalyser();
                    localAnalyser.fftSize = 256;
                    audioContext.createMediaStreamSource(stream).connect(localAnalyser);
                    detectSpeaking();
                } catch(e) {
                    debug('AudioContext error: ' + e.message, 'error');
                }
                
                currentVoiceChannel = channel;
                ws.send(JSON.stringify({ type: 'VOICE_JOIN', channelId: channel.id }));
                renderChannelsList();
                renderUserPanel();
                
            }).catch(function(e) {
                debug('Mic error: ' + e.message, 'error');
                alert('Ошибка микрофона: ' + e.message);
            });
        }

        function leaveVoiceChannel() {
            if (!currentVoiceChannel) return;
            
            debug('Leaving voice channel', 'warn');
            ws.send(JSON.stringify({ type: 'VOICE_LEAVE', channelId: currentVoiceChannel.id }));
            
            peerConnections.forEach(function(pc, odego) {
                closePeerConnection(odego);
            });
            peerConnections.clear();
            
            if (localStream) {
                localStream.getTracks().forEach(function(t) { t.stop(); });
                localStream = null;
            }
            
            if (audioContext) {
                audioContext.close().catch(function(){});
                audioContext = null;
            }
            localAnalyser = null;
            
            speakingUsers.clear();
            currentVoiceChannel = null;
            renderChannelsList();
            renderUserPanel();
        }

        function toggleMute() {
            isMuted = !isMuted;
            if (localStream) {
                localStream.getAudioTracks().forEach(function(t) { t.enabled = !isMuted; });
            }
            if (isMuted) {
                speakingUsers.delete(currentUser.id);
            }
            renderUserPanel();
            renderChannelsList();
        }

        function toggleDeafen() {
            isDeafened = !isDeafened;
            document.querySelectorAll('audio[id^="audio-"]').forEach(function(a) {
                a.muted = isDeafened;
            });
            renderUserPanel();
        }

        var micTestStream = null;
        var micTestInterval = null;
        var micTestCtx = null;

        async function showAudioSettings() {
            var devices = [];
            try {
                devices = await navigator.mediaDevices.enumerateDevices();
            } catch (e) {
                alert('Не удалось получить список устройств: ' + e.message);
                return;
            }
            
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
            
            $('#modalContainer').innerHTML = '<div class="modal-overlay" id="modalOverlay"><div class="modal"><div class="modal-header"><h2>Настройки звука</h2></div><div class="modal-body">' +
                '<div class="form-group"><label>Микрофон</label><select id="micSelect" class="audio-select">' + micOptions + '</select></div>' +
                '<div class="form-group"><label>Устройство вывода</label><select id="outputSelect" class="audio-select">' + outputOptions + '</select></div>' +
                '<div class="form-group"><label>Проверка микрофона</label><div class="mic-test"><div class="mic-level-bar"><div class="mic-level-fill" id="micLevelFill"></div></div><button class="btn" id="testMicBtn" style="margin-top:8px;">Проверить микрофон</button></div></div>' +
                '<div id="micTestResult" style="margin-top:8px;font-size:13px;"></div>' +
                '</div><div class="modal-footer"><button class="btn secondary" id="cancelAudioBtn">Отмена</button><button class="btn" id="saveAudioBtn">Сохранить</button></div></div></div>';
            
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
                $('#micTestResult').innerHTML = '<span style="color:var(--green);">✓ Микрофон активен. Говорите!</span>';
                
                micTestCtx = new (window.AudioContext || window.webkitAudioContext)();
                var analyser = micTestCtx.createAnalyser();
                analyser.fftSize = 256;
                micTestCtx.createMediaStreamSource(micTestStream).connect(analyser);
                var data = new Uint8Array(analyser.frequencyBinCount);
                
                var maxLevel = 0;
                micTestInterval = setInterval(function() {
                    analyser.getByteFrequencyData(data);
                    var level = 0;
                    for (var i = 0; i < data.length; i++) {
                        if (data[i] > level) level = data[i];
                    }
                    if (level > maxLevel) maxLevel = level;
                    
                    var percent = Math.min(100, (level / 255) * 100);
                    var fill = $('#micLevelFill');
                    if (fill) {
                        fill.style.width = percent + '%';
                        fill.style.background = level < 10 ? 'var(--red)' : level < 50 ? 'var(--yellow)' : 'var(--green)';
                    }
                    
                    var result = $('#micTestResult');
                    if (result && maxLevel > 0) {
                        if (maxLevel < 10) {
                            result.innerHTML = '<span style="color:var(--red);">✗ Очень тихо или нет звука</span>';
                        } else if (maxLevel < 50) {
                            result.innerHTML = '<span style="color:var(--yellow);">⚠ Тихо, но работает</span>';
                        } else {
                            result.innerHTML = '<span style="color:var(--green);">✓ Микрофон работает отлично!</span>';
                        }
                    }
                }, 100);
                
                $('#testMicBtn').textContent = 'Остановить';
                $('#testMicBtn').onclick = function() {
                    stopMicTest();
                    $('#testMicBtn').textContent = 'Проверить микрофон';
                    $('#testMicBtn').onclick = testMicrophone;
                };
                
            } catch (e) {
                $('#micTestResult').innerHTML = '<span style="color:var(--red);">✗ Ошибка: ' + e.message + '</span>';
            }
        }

        function stopMicTest() {
            if (micTestInterval) {
                clearInterval(micTestInterval);
                micTestInterval = null;
            }
            if (micTestStream) {
                micTestStream.getTracks().forEach(function(t) { t.stop(); });
                micTestStream = null;
            }
            if (micTestCtx) {
                micTestCtx.close().catch(function(){});
                micTestCtx = null;
            }
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
                    if (audio.setSinkId) {
                        audio.setSinkId(newOutputId).catch(function(e) {
                            console.error('Не удалось сменить выход:', e);
                        });
                    }
                });
            }
            
            if (currentVoiceChannel && localStream) {
                debug('Применяю новый микрофон...', 'warn');
                
                localStream.getTracks().forEach(function(t) { t.stop(); });
                
                try {
                    var constraints = { 
                        audio: newMicId ? { 
                            deviceId: { exact: newMicId },
                            echoCancellation: true,
                            noiseSuppression: true,
                            autoGainControl: true
                        } : {
                            echoCancellation: true,
                            noiseSuppression: true,
                            autoGainControl: true
                        }
                    };
                    var newStream = await navigator.mediaDevices.getUserMedia(constraints);
                    localStream = newStream;
                    
                    if (isMuted) {
                        newStream.getAudioTracks().forEach(function(t) { t.enabled = false; });
                    }
                    
                    var newTrack = newStream.getAudioTracks()[0];
                    peerConnections.forEach(function(pc, odego) {
                        var senders = pc.getSenders();
                        var audioSender = senders.find(function(s) { return s.track && s.track.kind === 'audio'; });
                        if (audioSender) {
                            audioSender.replaceTrack(newTrack).then(function() {
                                debug('Трек заменён для ' + odego.slice(0,8), 'success');
                            }).catch(function(e) {
                                debug('Ошибка замены трека: ' + e.message, 'error');
                            });
                        }
                    });
                    
                    if (audioContext) {
                        audioContext.close().catch(function(){});
                    }
                    audioContext = new (window.AudioContext || window.webkitAudioContext)();
                    localAnalyser = audioContext.createAnalyser();
                    localAnalyser.fftSize = 256;
                    audioContext.createMediaStreamSource(newStream).connect(localAnalyser);
                    
                    debug('Микрофон успешно изменён!', 'success');
                    
                } catch (e) {
                    debug('Ошибка смены микрофона: ' + e.message, 'error');
                    alert('Не удалось сменить микрофон: ' + e.message);
                }
            }
            
            stopMicTest();
            closeModal();
        }

        function render() {
            $('#app').innerHTML = '<div class="servers-list" id="serversList"></div><div class="channels-sidebar" id="channelsSidebar"><div class="server-header" id="serverHeader"></div><div class="channels-list" id="channelsList"></div><div class="user-panel" id="userPanel"></div></div><div class="main-content"><div class="chat-header" id="chatHeader"></div><div class="chat-area" id="chatArea"></div></div><div class="members-sidebar" id="membersSidebar"></div><div id="modalContainer"></div><div id="contextMenu" class="context-menu"></div>';
        }

        function renderLoading() {
            $('#chatArea').innerHTML = '<div class="loading"><div class="loading-spinner"></div><p>Подключение...</p></div>';
        }

        function renderAll() {
            renderServersList();
            renderChannelsList();
            renderUserPanel();
            renderMembersList();
            renderChatHeader();
            renderMessages();
        }

        function renderServersList() {
            var html = '<div class="server-icon home" id="homeBtn">🏠</div>';
            servers.forEach(function(s) {
                var isActive = currentServer && currentServer.id === s.id;
                html += '<div class="server-icon' + (isActive ? ' active' : '') + '" data-server="' + s.id + '" title="' + escapeHtml(s.name) + '">' + getInitials(s.name) + '</div>';
            });
            html += '<div class="server-icon add" id="addServerBtn">+</div>';
            $('#serversList').innerHTML = html;
            
            $$('.server-icon[data-server]').forEach(function(el) {
                el.onclick = function() {
                    var server = servers.find(function(s) { return s.id === el.dataset.server; });
                    if (server) selectServer(server);
                };
            });
            
            $('#addServerBtn').onclick = showCreateServerModal;
        }

        function selectServer(server) {
            currentServer = server;
            currentChannel = null;
            messages = [];
            
            if (server.channels && server.channels.length > 0) {
                var textChannel = server.channels.find(function(c) { return c.type === 'text'; });
                if (textChannel) selectChannel(textChannel);
            }
            
            renderAll();
        }

        function renderChannelsList() {
            if (!currentServer) {
                $('#channelsSidebar').style.display = 'none';
                return;
            }
            $('#channelsSidebar').style.display = 'flex';
            
            $('#serverHeader').innerHTML = '<span>' + escapeHtml(currentServer.name) + '</span><button id="serverSettingsBtn">⚙️</button>';
            $('#serverSettingsBtn').onclick = showServerSettings;
            
            var textChannels = (currentServer.channels || []).filter(function(c) { return c.type === 'text'; });
            var voiceChannels = (currentServer.channels || []).filter(function(c) { return c.type === 'voice'; });
            
            var html = '<div class="channel-category"><span>ТЕКСТОВЫЕ КАНАЛЫ</span><button class="add-channel" data-type="text">+</button></div>';
            textChannels.forEach(function(c) {
                var isActive = currentChannel && currentChannel.id === c.id;
                html += '<div class="channel' + (isActive ? ' active' : '') + '" data-channel="' + c.id + '"><span class="channel-icon">#</span><span class="channel-name">' + escapeHtml(c.name) + '</span></div>';
            });
            
            html += '<div class="channel-category"><span>ГОЛОСОВЫЕ КАНАЛЫ</span><button class="add-channel" data-type="voice">+</button></div>';
            voiceChannels.forEach(function(c) {
                var isInChannel = currentVoiceChannel && currentVoiceChannel.id === c.id;
                html += '<div class="channel voice' + (isInChannel ? ' active' : '') + '" data-voice="' + c.id + '"><span class="channel-icon">🔊</span><span class="channel-name">' + escapeHtml(c.name) + '</span></div>';
                
                var usersInChannel = voiceUsers[c.id] || [];
                usersInChannel.forEach(function(u) {
                    var isSpeaking = speakingUsers.has(u.id);
                    var isMutedUser = u.id === currentUser.id && isMuted;
                    html += '<div class="voice-user' + (isSpeaking ? ' speaking' : '') + '"><div class="avatar small' + (isSpeaking ? ' speaking' : '') + '">' + getInitials(u.username) + '</div><span>' + escapeHtml(u.username) + '</span>' + (isMutedUser ? '<span class="muted-icon">🔇</span>' : '') + '</div>';
                });
            });
            
            if (currentVoiceChannel) {
                html += '<div class="voice-controls"><div class="voice-status">Голосовой канал: ' + escapeHtml(currentVoiceChannel.name) + '</div><button class="btn disconnect" id="disconnectVoice">Отключиться</button></div>';
            }
            
            $('#channelsList').innerHTML = html;
            
            $$('.channel[data-channel]').forEach(function(el) {
                el.onclick = function() {
                    var channel = currentServer.channels.find(function(c) { return c.id === el.dataset.channel; });
                    if (channel) selectChannel(channel);
                };
            });
            
            $$('.channel[data-voice]').forEach(function(el) {
                el.onclick = function() {
                    var channel = currentServer.channels.find(function(c) { return c.id === el.dataset.voice; });
                    if (channel) joinVoiceChannel(channel);
                };
            });
            
            $$('.add-channel').forEach(function(el) {
                el.onclick = function(e) {
                    e.stopPropagation();
                    showCreateChannelModal(el.dataset.type);
                };
            });
            
            if ($('#disconnectVoice')) {
                $('#disconnectVoice').onclick = leaveVoiceChannel;
            }
        }

        function selectChannel(channel) {
            currentChannel = channel;
            messages = [];
            ws.send(JSON.stringify({ type: 'GET_MESSAGES', channelId: channel.id }));
            renderChannelsList();
            renderChatHeader();
            renderMessages();
        }

        function renderUserPanel() {
            var c = $('#userPanel');
            if (!c) return;
            
            var isSpeaking = speakingUsers.has(currentUser.id) && currentVoiceChannel;
            var html = '<div class="avatar' + (isSpeaking ? ' speaking' : '') + '">' + getInitials(currentUser.username) + '</div>';
            html += '<div class="info"><div class="username">' + escapeHtml(currentUser.username) + '</div><div class="status">В сети</div></div>';
            html += '<div class="actions">';
            html += '<button id="audioSettingsBtn" title="Настройки звука">⚙️</button>';
            
            if (currentVoiceChannel) {
                html += '<button id="upMute" class="' + (isMuted ? 'muted' : '') + '" title="' + (isMuted ? 'Включить микрофон' : 'Выключить микрофон') + '">' + (isMuted ? '🔇' : '🎤') + '</button>';
                html += '<button id="upDeafen" class="' + (isDeafened ? 'muted' : '') + '" title="' + (isDeafened ? 'Включить звук' : 'Выключить звук') + '">' + (isDeafened ? '🔕' : '🎧') + '</button>';
            }
            
            html += '<button id="logoutBtn" title="Выйти">🚪</button></div>';
            c.innerHTML = html;
            
            $('#audioSettingsBtn').onclick = showAudioSettings;
            if ($('#upMute')) $('#upMute').onclick = toggleMute;
            if ($('#upDeafen')) $('#upDeafen').onclick = toggleDeafen;
            $('#logoutBtn').onclick = logout;
        }

        function renderChatHeader() {
            var header = $('#chatHeader');
            if (!currentChannel) {
                header.innerHTML = '<span>Выберите канал</span>';
                return;
            }
            header.innerHTML = '<span class="channel-icon">#</span><span class="channel-name">' + escapeHtml(currentChannel.name) + '</span>' + (currentChannel.topic ? '<span class="channel-topic">' + escapeHtml(currentChannel.topic) + '</span>' : '');
        }

        function renderMessages() {
            var area = $('#chatArea');
            if (!currentChannel) {
                area.innerHTML = '<div class="no-channel"><h2>Добро пожаловать!</h2><p>Выберите канал для начала общения</p></div>';
                return;
            }
            
            var html = '<div class="messages-container" id="messagesContainer">';
            
            if (messages.length === 0) {
                html += '<div class="welcome-message"><h3>Добро пожаловать в #' + escapeHtml(currentChannel.name) + '!</h3><p>Это начало канала.</p></div>';
            } else {
                messages.forEach(function(m) {
                    var isOwn = m.author && m.author.id === currentUser.id;
                    html += '<div class="message' + (isOwn ? ' own' : '') + '" data-message-id="' + m.id + '">';
                    html += '<div class="avatar">' + getInitials(m.author ? m.author.username : '?') + '</div>';
                    html += '<div class="message-content"><div class="message-header"><span class="username">' + escapeHtml(m.author ? m.author.username : 'Unknown') + '</span><span class="timestamp">' + formatTime(m.timestamp) + '</span>' + (m.edited ? '<span class="edited">(ред.)</span>' : '') + '</div>';
                    html += '<div class="message-text" id="msg-text-' + m.id + '">' + escapeHtml(m.content) + '</div></div>';
                    if (isOwn) {
                        html += '<div class="message-actions"><button class="msg-edit" data-id="' + m.id + '">✏️</button><button class="msg-delete" data-id="' + m.id + '">🗑️</button></div>';
                    }
                    html += '</div>';
                });
            }
            
            html += '</div><div class="typing-indicator" id="typingIndicator"></div>';
            html += '<div class="message-input-container">';
            
            if (editingMessageId) {
                html += '<div class="editing-banner">Редактирование сообщения <button id="cancelEdit">✕</button></div>';
            }
            
            html += '<div class="message-input-wrapper"><input type="text" id="messageInput" placeholder="Написать в #' + escapeHtml(currentChannel.name) + '" maxlength="2000"><button class="send-btn" id="sendBtn">➤</button></div></div>';
            
            area.innerHTML = html;
            
            $('#messageInput').onkeypress = function(e) {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendMessage();
                }
            };
            
            $('#messageInput').oninput = function() {
                sendTypingIndicator();
            };
            
            $('#sendBtn').onclick = sendMessage;
            
            if ($('#cancelEdit')) {
                $('#cancelEdit').onclick = cancelEdit;
            }
            
            $$('.msg-edit').forEach(function(btn) {
                btn.onclick = function() { startEditMessage(btn.dataset.id); };
            });
            
            $$('.msg-delete').forEach(function(btn) {
                btn.onclick = function() { deleteMessage(btn.dataset.id); };
            });
            
            var container = $('#messagesContainer');
            if (container) container.scrollTop = container.scrollHeight;
        }

        function sendMessage() {
            var input = $('#messageInput');
            var content = input.value.trim();
            if (!content || !currentChannel) return;
            
            if (editingMessageId) {
                ws.send(JSON.stringify({
                    type: 'EDIT_MESSAGE',
                    messageId: editingMessageId,
                    content: content
                }));
                editingMessageId = null;
            } else {
                ws.send(JSON.stringify({
                    type: 'SEND_MESSAGE',
                    channelId: currentChannel.id,
                    content: content
                }));
            }
            
            input.value = '';
        }

        function startEditMessage(messageId) {
            var msg = messages.find(function(m) { return m.id === messageId; });
            if (!msg) return;
            
            editingMessageId = messageId;
            renderMessages();
            
            var input = $('#messageInput');
            input.value = msg.content;
            input.focus();
        }

        function cancelEdit() {
            editingMessageId = null;
            renderMessages();
        }

        function deleteMessage(messageId) {
            if (confirm('Удалить сообщение?')) {
                ws.send(JSON.stringify({
                    type: 'DELETE_MESSAGE',
                    messageId: messageId
                }));
            }
        }

        function sendTypingIndicator() {
            if (!currentChannel) return;
            
            if (typingTimeout) clearTimeout(typingTimeout);
            
            ws.send(JSON.stringify({
                type: 'TYPING_START',
                channelId: currentChannel.id
            }));
            
            typingTimeout = setTimeout(function() {
                ws.send(JSON.stringify({
                    type: 'TYPING_STOP',
                    channelId: currentChannel.id
                }));
            }, 3000);
        }

        function renderTypingIndicator() {
            var indicator = $('#typingIndicator');
            if (!indicator) return;
            
            var now = Date.now();
            var activeTypers = [];
            
            typingUsers.forEach(function(data, odego) {
                if (now - data.time < 5000) {
                    activeTypers.push(data.username);
                } else {
                    typingUsers.delete(odego);
                }
            });
            
            if (activeTypers.length === 0) {
                indicator.innerHTML = '';
            } else if (activeTypers.length === 1) {
                indicator.innerHTML = '<span class="typing-dots"></span> ' + escapeHtml(activeTypers[0]) + ' печатает...';
            } else if (activeTypers.length <= 3) {
                indicator.innerHTML = '<span class="typing-dots"></span> ' + activeTypers.map(escapeHtml).join(', ') + ' печатают...';
            } else {
                indicator.innerHTML = '<span class="typing-dots"></span> Несколько человек печатают...';
            }
        }

        function renderMembersList() {
            var sidebar = $('#membersSidebar');
            var online = [];
            var offline = [];
            
            Object.values(users).forEach(function(u) {
                if (u.status === 'online') {
                    online.push(u);
                } else {
                    offline.push(u);
                }
            });
            
            var html = '<div class="members-header">Участники — ' + Object.keys(users).length + '</div>';
            
            if (online.length > 0) {
                html += '<div class="member-category">В СЕТИ — ' + online.length + '</div>';
                online.forEach(function(u) {
                    html += '<div class="member"><div class="avatar small">' + getInitials(u.username) + '</div><span class="member-name">' + escapeHtml(u.username) + '</span><span class="status-dot online"></span></div>';
                });
            }
            
            if (offline.length > 0) {
                html += '<div class="member-category">НЕ В СЕТИ — ' + offline.length + '</div>';
                offline.forEach(function(u) {
                    html += '<div class="member offline"><div class="avatar small">' + getInitials(u.username) + '</div><span class="member-name">' + escapeHtml(u.username) + '</span></div>';
                });
            }
            
            sidebar.innerHTML = html;
        }

        function showCreateServerModal() {
            $('#modalContainer').innerHTML = '<div class="modal-overlay" id="modalOverlay"><div class="modal"><div class="modal-header"><h2>Создать сервер</h2></div><div class="modal-body"><div class="form-group"><label>Название сервера</label><input type="text" id="serverNameInput" placeholder="Мой сервер" maxlength="100"></div></div><div class="modal-footer"><button class="btn secondary" id="cancelBtn">Отмена</button><button class="btn" id="createServerBtn">Создать</button></div></div></div>';
            
            $('#modalOverlay').onclick = function(e) { if (e.target.id === 'modalOverlay') closeModal(); };
            $('#cancelBtn').onclick = closeModal;
            $('#createServerBtn').onclick = createServer;
            $('#serverNameInput').focus();
            $('#serverNameInput').onkeypress = function(e) { if (e.key === 'Enter') createServer(); };
        }

        function createServer() {
            var name = $('#serverNameInput').value.trim();
            if (!name) { alert('Введите название'); return; }
            
            ws.send(JSON.stringify({ type: 'CREATE_SERVER', name: name }));
            closeModal();
        }

        function showCreateChannelModal(type) {
            $('#modalContainer').innerHTML = '<div class="modal-overlay" id="modalOverlay"><div class="modal"><div class="modal-header"><h2>Создать ' + (type === 'voice' ? 'голосовой' : 'текстовый') + ' канал</h2></div><div class="modal-body"><div class="form-group"><label>Название канала</label><input type="text" id="channelNameInput" placeholder="новый-канал" maxlength="100"></div></div><div class="modal-footer"><button class="btn secondary" id="cancelBtn">Отмена</button><button class="btn" id="createChannelBtn">Создать</button></div></div></div>';
            
            $('#modalOverlay').onclick = function(e) { if (e.target.id === 'modalOverlay') closeModal(); };
            $('#cancelBtn').onclick = closeModal;
            $('#createChannelBtn').onclick = function() { createChannel(type); };
            $('#channelNameInput').focus();
            $('#channelNameInput').onkeypress = function(e) { if (e.key === 'Enter') createChannel(type); };
        }

        function createChannel(type) {
            var name = $('#channelNameInput').value.trim().toLowerCase().replace(/\\s+/g, '-');
            if (!name) { alert('Введите название'); return; }
            
            ws.send(JSON.stringify({
                type: 'CREATE_CHANNEL',
                serverId: currentServer.id,
                name: name,
                channelType: type
            }));
            closeModal();
        }

        function showServerSettings() {
            alert('Настройки сервера (в разработке)');
        }

        function closeModal() {
            $('#modalContainer').innerHTML = '';
        }

        function logout() {
            if (currentVoiceChannel) leaveVoiceChannel();
            localStorage.removeItem('discord_user');
            if (ws) ws.close();
            location.reload();
        }

        document.addEventListener('DOMContentLoaded', init);
    </script>
</body>
</html>
    `;
}
