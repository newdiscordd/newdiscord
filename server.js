/**
 * Discord Clone - Full Stack Server with Voice Chat
 * ИСПРАВЛЕННАЯ ВЕРСИЯ - Часть 1: Сервер + WebRTC сигналинг
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
const JWT_SECRET = process.env.JWT_SECRET;
const BCRYPT_ROUNDS = 10;
const DATABASE_URL = process.env.DATABASE_URL;

const ICE_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' },
    { urls: 'stun:stun3.l.google.com:19302' },
    { urls: 'stun:stun4.l.google.com:19302' }
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

function getUserVoiceChannel(userId) {
    for (const [channelId, room] of voiceRooms.entries()) {
        if (room.has(userId)) {
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
            CREATE INDEX IF NOT EXISTS idx_channels_type ON channels(type);
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
const clients = new Map(); // userId -> Set<WebSocket>
const wsUserMap = new Map(); // WebSocket -> userId

function sendToUser(userId, data) {
    const sockets = clients.get(userId);
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
// ИСПРАВЛЕННЫЕ ГОЛОСОВЫЕ ФУНКЦИИ
// ============================================

async function handleVoiceJoin(userId, username, channelId, ws) {
    // Сначала выходим из текущего канала, если есть
    const currentChannel = getUserVoiceChannel(userId);
    if (currentChannel && currentChannel !== channelId) {
        await handleVoiceLeave(userId);
    }
    
    // Проверяем, что это голосовой канал
    const channelResult = await pool.query('SELECT * FROM channels WHERE id = $1 AND type = $2', [channelId, 'voice']);
    if (!channelResult.rows[0]) {
        sendToUser(userId, { type: 'VOICE_ERROR', error: 'Голосовой канал не найден' });
        return;
    }
    
    const channel = channelResult.rows[0];
    
    // Проверяем членство на сервере
    const memberResult = await pool.query('SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2', [channel.server_id, userId]);
    if (!memberResult.rows[0]) {
        sendToUser(userId, { type: 'VOICE_ERROR', error: 'Нет доступа к серверу' });
        return;
    }
    
    const room = getVoiceRoom(channelId);
    
    // ИСПРАВЛЕНИЕ: Проверяем, не подключен ли уже этот пользователь
    if (room.has(userId)) {
        console.log(`[VOICE] User ${username} already in channel ${channelId}, skipping`);
        return;
    }
    
    // Получаем существующих участников ДО добавления нового
    const existingParticipants = Array.from(room.values());
    
    // ИСПРАВЛЕНИЕ: Используем userId вместо odego для консистентности
    const participant = {
        odego: odego,
        username: username,
        muted: false,
        deafened: false
    };
    
    room.set(userId, participant);
    
    console.log(`[VOICE] ${username} (${userId}) joined channel ${channelId}. Participants: ${room.size}`);
    
    // Отправляем подтверждение присоединившемуся пользователю
    sendToUser(userId, {
        type: 'VOICE_JOINED',
        channelId: channelId,
        participants: existingParticipants,
        iceServers: ICE_SERVERS
    });
    
    // ИСПРАВЛЕНИЕ: Уведомляем ТОЛЬКО других участников в голосовом канале
    broadcastToVoiceChannel(channelId, {
        type: 'VOICE_USER_JOINED',
        channelId: channelId,
        user: participant
    }, odego); // исключаем самого пользователя
    
    // ИСПРАВЛЕНИЕ: Отдельно отправляем обновление состояния для UI всем на сервере
    // (но это НЕ должно добавлять участника повторно на клиенте)
    broadcastToServer(channel.server_id, {
        type: 'VOICE_STATE_UPDATE',
        channelId: channelId,
        odego: odego,
        username: username,
        action: 'join'
    });
}

async function handleVoiceLeave(userId) {
    const channelId = getUserVoiceChannel(userId);
    if (!channelId) return;
    
    const room = voiceRooms.get(channelId);
    if (!room) return;
    
    const user = room.get(userId);
    if (!user) return;
    
    room.delete(userId);
    
    console.log(`[VOICE] ${user.username} (${userId}) left channel ${channelId}. Participants: ${room.size}`);
    
    // Очищаем пустую комнату
    if (room.size === 0) {
        voiceRooms.delete(channelId);
    }
    
    // Уведомляем оставшихся участников голосового канала
    broadcastToVoiceChannel(channelId, {
        type: 'VOICE_USER_LEFT',
        channelId: channelId,
        odego: odego
    });
    
    // Отправляем обновление состояния на весь сервер для UI
    try {
        const channelResult = await pool.query('SELECT server_id FROM channels WHERE id = $1', [channelId]);
        if (channelResult.rows[0]) {
            broadcastToServer(channelResult.rows[0].server_id, {
                type: 'VOICE_STATE_UPDATE',
                channelId: channelId,
                odego: odego,
                action: 'leave'
            });
        }
    } catch (e) {
        console.error('Voice leave broadcast error:', e);
    }
    
    // Подтверждаем выход пользователю
    sendToUser(userId, { type: 'VOICE_LEFT', channelId: channelId });
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
                        odego: odego, 
                        username: username,
                        iceServers: ICE_SERVERS
                    }));
                    
                    const servers = await pool.query('SELECT server_id FROM server_members WHERE user_id = $1', [odego]);
                    servers.rows.forEach(r => {
                        broadcastToServer(r.server_id, { 
                            type: 'USER_STATUS_CHANGE', 
                            odego: odego, 
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
                        console.log(`[VOICE SIGNAL] ${odego} -> ${msg.targetUserId}:`, msg.signal.type || 'candidate');
                        sendToUser(msg.targetUserId, {
                            type: 'VOICE_SIGNAL',
                            fromUserId: odego,
                            fromUsername: username,
                            signal: msg.signal
                        });
                    }
                    break;

                case 'VOICE_TOGGLE_MUTE': {
                    const channelId = getUserVoiceChannel(odego);
                    if (channelId) {
                        const room = voiceRooms.get(channelId);
                        if (room && room.has(odego)) {
                            const participant = room.get(odego);
                            participant.muted = msg.muted;
                            broadcastToVoiceChannel(channelId, {
                                type: 'VOICE_USER_MUTE',
                                channelId: channelId,
                                odego: odego,
                                muted: msg.muted
                            });
                        }
                    }
                    break;
                }

                case 'VOICE_TOGGLE_DEAFEN': {
                    const channelId = getUserVoiceChannel(odego);
                    if (channelId) {
                        const room = voiceRooms.get(channelId);
                        if (room && room.has(odego)) {
                            const participant = room.get(odego);
                            participant.deafened = msg.deafened;
                            if (msg.deafened) participant.muted = true;
                            broadcastToVoiceChannel(channelId, {
                                type: 'VOICE_USER_DEAFEN',
                                channelId: channelId,
                                odego: odego,
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
                                odego, 
                                username: user.rows[0]?.username 
                            });
                        }
                    } else if (recipientId) {
                        sendToUser(recipientId, { 
                            type: 'USER_TYPING', 
                            odego, 
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
            // Выходим из голосового канала
            await handleVoiceLeave(odego);
            
            const sockets = clients.get(odego);
            if (sockets) {
                sockets.delete(ws);
                // Обновляем статус только если это последнее соединение
                if (sockets.size === 0) {
                    clients.delete(odego);
                    await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['offline', odego]);
                    const servers = await pool.query('SELECT server_id FROM server_members WHERE user_id = $1', [odego]);
                    servers.rows.forEach(r => {
                        broadcastToServer(r.server_id, { 
                            type: 'USER_STATUS_CHANGE', 
                            odego, 
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
        broadcastToServer(req.params.serverId, { type: 'MEMBER_LEFT', serverId: req.params.serverId, odego: req.user.id });
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

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Discord Clone</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #313338; --bg-secondary: #2b2d31; --bg-tertiary: #1e1f22;
            --text-primary: #f2f3f5; --text-secondary: #b5bac1; --text-muted: #949ba4;
            --accent: #5865f2; --accent-hover: #4752c4; --green: #23a559; --red: #f23f43;
            --yellow: #f0b232; --channel-text: #80848e;
        }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg-primary); color: var(--text-primary); height: 100vh; overflow: hidden; }

        /* Auth */
        .auth-container { display: flex; align-items: center; justify-content: center; height: 100vh; background: var(--bg-tertiary); }
        .auth-box { background: var(--bg-primary); padding: 32px; border-radius: 8px; width: 100%; max-width: 480px; }
        .auth-box h1 { text-align: center; margin-bottom: 8px; font-size: 24px; }
        .auth-box p { text-align: center; color: var(--text-secondary); margin-bottom: 20px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-secondary); }
        .form-group input { width: 100%; padding: 10px; border: none; border-radius: 4px; background: var(--bg-tertiary); color: var(--text-primary); font-size: 16px; }
        .form-group input:focus { outline: 2px solid var(--accent); }
        .btn { width: 100%; padding: 12px; border: none; border-radius: 4px; background: var(--accent); color: white; font-size: 16px; font-weight: 500; cursor: pointer; transition: background 0.2s; }
        .btn:hover { background: var(--accent-hover); }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .auth-switch { text-align: center; margin-top: 16px; color: var(--text-secondary); font-size: 14px; }
        .auth-switch a { color: var(--accent); text-decoration: none; cursor: pointer; }
        .auth-switch a:hover { text-decoration: underline; }
        .error-msg { background: rgba(242,63,67,0.1); border: 1px solid var(--red); color: var(--red); padding: 10px; border-radius: 4px; margin-bottom: 16px; font-size: 14px; }

        /* Main Layout */
        .app-container { display: flex; height: 100vh; }
        .server-list { width: 72px; background: var(--bg-tertiary); padding: 12px 0; display: flex; flex-direction: column; align-items: center; gap: 8px; overflow-y: auto; }
        .server-icon { width: 48px; height: 48px; border-radius: 50%; background: var(--bg-primary); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s; font-size: 18px; color: var(--text-primary); position: relative; }
        .server-icon:hover, .server-icon.active { border-radius: 16px; background: var(--accent); }
        .server-icon img { width: 100%; height: 100%; border-radius: inherit; object-fit: cover; }
        .server-icon.home { background: var(--bg-primary); color: var(--text-primary); }
        .server-icon.home:hover, .server-icon.home.active { background: var(--accent); }
        .server-icon.add { background: var(--bg-primary); color: var(--green); font-size: 24px; }
        .server-icon.add:hover { background: var(--green); color: white; }
        .separator { width: 32px; height: 2px; background: var(--bg-secondary); border-radius: 1px; margin: 4px 0; }

        /* Channels */
        .channel-sidebar { width: 240px; background: var(--bg-secondary); display: flex; flex-direction: column; }
        .server-header { padding: 12px 16px; font-weight: 600; font-size: 16px; border-bottom: 1px solid var(--bg-tertiary); display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
        .server-header:hover { background: var(--bg-tertiary); }
        .channel-list { flex: 1; overflow-y: auto; padding: 8px 0; }
        .channel-category { padding: 16px 8px 4px 16px; font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--channel-text); display: flex; justify-content: space-between; align-items: center; }
        .channel-category button { background: none; border: none; color: var(--channel-text); cursor: pointer; font-size: 16px; padding: 2px 6px; border-radius: 4px; }
        .channel-category button:hover { color: var(--text-primary); background: var(--bg-tertiary); }
        .channel-item { display: flex; align-items: center; padding: 6px 8px; margin: 1px 8px; border-radius: 4px; cursor: pointer; color: var(--channel-text); gap: 6px; }
        .channel-item:hover { background: var(--bg-tertiary); color: var(--text-secondary); }
        .channel-item.active { background: var(--bg-tertiary); color: var(--text-primary); }
        .channel-item .icon { font-size: 20px; width: 24px; text-align: center; }
        .channel-item .name { flex: 1; font-size: 15px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .channel-item .delete-btn { opacity: 0; background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 2px 6px; border-radius: 4px; }
        .channel-item:hover .delete-btn { opacity: 1; }
        .channel-item .delete-btn:hover { color: var(--red); background: rgba(242,63,67,0.1); }

        /* Voice Channel Styles */
        .voice-channel { margin-left: 8px; margin-right: 8px; border-radius: 4px; }
        .voice-channel .channel-item { margin: 0; border-radius: 4px 4px 0 0; }
        .voice-channel.has-users .channel-item { background: var(--bg-tertiary); }
        .voice-participants { background: var(--bg-tertiary); border-radius: 0 0 4px 4px; padding-bottom: 4px; margin-bottom: 2px; }
        .voice-participant { display: flex; align-items: center; padding: 4px 8px 4px 32px; gap: 8px; font-size: 13px; color: var(--text-secondary); }
        .voice-participant .avatar { width: 24px; height: 24px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 10px; }
        .voice-participant .name { flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .voice-participant .status-icons { display: flex; gap: 4px; font-size: 14px; }
        .voice-participant.speaking .avatar { box-shadow: 0 0 0 2px var(--green); }
        .voice-participant.muted .mute-icon { color: var(--red); }
        .voice-participant.deafened .deafen-icon { color: var(--red); }

        /* User Panel */
        .user-panel { padding: 8px; background: var(--bg-tertiary); display: flex; align-items: center; gap: 8px; }
        .user-panel .avatar { width: 32px; height: 32px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; }
        .user-panel .info { flex: 1; min-width: 0; }
        .user-panel .username { font-size: 14px; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .user-panel .status { font-size: 12px; color: var(--text-muted); }
        .user-panel .actions { display: flex; gap: 4px; }
        .user-panel .actions button { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 6px; border-radius: 4px; font-size: 18px; }
        .user-panel .actions button:hover { background: var(--bg-secondary); color: var(--text-primary); }
        .user-panel .actions button.active { color: var(--green); }
        .user-panel .actions button.muted { color: var(--red); }

        /* Voice Connected Panel */
        .voice-connected { background: var(--bg-tertiary); border-bottom: 1px solid var(--bg-primary); padding: 8px; }
        .voice-connected .voice-status { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
        .voice-connected .voice-status .indicator { width: 8px; height: 8px; border-radius: 50%; background: var(--green); animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .voice-connected .voice-status .text { flex: 1; }
        .voice-connected .voice-status .text .title { font-size: 13px; font-weight: 600; color: var(--green); }
        .voice-connected .voice-status .text .channel { font-size: 12px; color: var(--text-muted); }
        .voice-connected .voice-controls { display: flex; gap: 8px; }
        .voice-connected .voice-controls button { flex: 1; padding: 8px; border: none; border-radius: 4px; background: var(--bg-secondary); color: var(--text-primary); cursor: pointer; font-size: 16px; }
        .voice-connected .voice-controls button:hover { background: var(--bg-primary); }
        .voice-connected .voice-controls button.active { color: var(--red); background: rgba(242,63,67,0.2); }
        .voice-connected .voice-controls .disconnect { background: rgba(242,63,67,0.2); color: var(--red); }
        .voice-connected .voice-controls .disconnect:hover { background: var(--red); color: white; }

        /* Chat Area */
        .chat-area { flex: 1; display: flex; flex-direction: column; background: var(--bg-primary); }
        .chat-header { padding: 12px 16px; border-bottom: 1px solid var(--bg-tertiary); display: flex; align-items: center; gap: 8px; font-weight: 600; }
        .chat-header .icon { color: var(--channel-text); }
        .messages-container { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 16px; }
        .message { display: flex; gap: 16px; }
        .message .avatar { width: 40px; height: 40px; border-radius: 50%; background: var(--accent); flex-shrink: 0; display: flex; align-items: center; justify-content: center; font-weight: 600; }
        .message .content { flex: 1; min-width: 0; }
        .message .header { display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; }
        .message .author { font-weight: 500; color: var(--text-primary); }
        .message .timestamp { font-size: 12px; color: var(--text-muted); }
        .message .text { color: var(--text-secondary); word-wrap: break-word; line-height: 1.4; }
        .message-input-container { padding: 0 16px 24px; }
        .message-input { display: flex; align-items: center; background: var(--bg-tertiary); border-radius: 8px; padding: 0 16px; }
        .message-input input { flex: 1; background: none; border: none; padding: 12px 0; color: var(--text-primary); font-size: 16px; }
        .message-input input:focus { outline: none; }
        .message-input input::placeholder { color: var(--text-muted); }
        .message-input button { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 8px; font-size: 20px; }
        .message-input button:hover { color: var(--text-primary); }
        .typing-indicator { font-size: 12px; color: var(--text-muted); padding: 4px 0; min-height: 20px; }

        /* Members Sidebar */
        .members-sidebar { width: 240px; background: var(--bg-secondary); padding: 16px 8px; overflow-y: auto; }
        .members-category { padding: 8px; font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--channel-text); }
        .member-item { display: flex; align-items: center; padding: 6px 8px; border-radius: 4px; cursor: pointer; gap: 12px; }
        .member-item:hover { background: var(--bg-tertiary); }
        .member-item .avatar { width: 32px; height: 32px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; position: relative; }
        .member-item .avatar .status-dot { position: absolute; bottom: -2px; right: -2px; width: 12px; height: 12px; border-radius: 50%; border: 3px solid var(--bg-secondary); }
        .member-item .avatar .status-dot.online { background: var(--green); }
        .member-item .avatar .status-dot.offline { background: var(--text-muted); }
        .member-item .name { font-size: 15px; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .member-item .voice-icon { font-size: 14px; color: var(--green); }

        /* Modal */
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.85); display: flex; align-items: center; justify-content: center; z-index: 1000; }
        .modal { background: var(--bg-primary); border-radius: 8px; width: 100%; max-width: 440px; max-height: 90vh; overflow: hidden; }
        .modal-header { padding: 16px; text-align: center; }
        .modal-header h2 { font-size: 20px; margin-bottom: 8px; }
        .modal-header p { color: var(--text-secondary); font-size: 14px; }
        .modal-body { padding: 0 16px 16px; }
        .modal-footer { padding: 16px; background: var(--bg-secondary); display: flex; justify-content: flex-end; gap: 8px; }
        .modal-footer .btn { width: auto; padding: 10px 24px; }
        .modal-footer .btn.secondary { background: transparent; color: var(--text-primary); }
        .modal-footer .btn.secondary:hover { text-decoration: underline; }
        .modal-tabs { display: flex; margin-bottom: 16px; }
        .modal-tabs button { flex: 1; padding: 12px; background: var(--bg-secondary); border: none; color: var(--text-secondary); cursor: pointer; font-size: 14px; }
        .modal-tabs button:first-child { border-radius: 4px 0 0 4px; }
        .modal-tabs button:last-child { border-radius: 0 4px 4px 0; }
        .modal-tabs button.active { background: var(--accent); color: white; }
        .invite-code { background: var(--bg-tertiary); padding: 12px; border-radius: 4px; font-family: monospace; font-size: 18px; text-align: center; margin: 16px 0; user-select: all; }

        /* DM Sidebar */
        .dm-sidebar { width: 240px; background: var(--bg-secondary); display: flex; flex-direction: column; }
        .dm-header { padding: 12px 16px; border-bottom: 1px solid var(--bg-tertiary); }
        .dm-search { width: 100%; padding: 8px; border: none; border-radius: 4px; background: var(--bg-tertiary); color: var(--text-primary); font-size: 14px; }
        .dm-search:focus { outline: none; }
        .dm-list { flex: 1; overflow-y: auto; padding: 8px; }
        .dm-item { display: flex; align-items: center; padding: 8px; border-radius: 4px; cursor: pointer; gap: 12px; margin-bottom: 2px; }
        .dm-item:hover { background: var(--bg-tertiary); }
        .dm-item.active { background: var(--bg-tertiary); }
        .dm-item .avatar { width: 32px; height: 32px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; position: relative; }
        .dm-item .name { flex: 1; font-size: 15px; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

        /* Empty State */
        .empty-state { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: var(--text-muted); text-align: center; padding: 32px; }
        .empty-state .icon { font-size: 64px; margin-bottom: 16px; opacity: 0.5; }
        .empty-state h3 { margin-bottom: 8px; color: var(--text-primary); }

        /* Scrollbar */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--bg-tertiary); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--bg-primary); }

        /* Responsive */
        @media (max-width: 768px) {
            .members-sidebar { display: none; }
            .channel-sidebar { width: 200px; }
        }
        @media (max-width: 600px) {
            .channel-sidebar, .dm-sidebar { position: fixed; left: 72px; top: 0; bottom: 0; z-index: 100; transform: translateX(-100%); transition: transform 0.3s; }
            .channel-sidebar.open, .dm-sidebar.open { transform: translateX(0); }
        }
    </style>
</head>
<body>
<div id="app"></div>

<script>
    // ============================================
    // ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
    // ============================================

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
    var MAX_RECONNECT_ATTEMPTS = 5;

    // WEBRTC - ИСПРАВЛЕННЫЕ ПЕРЕМЕННЫЕ
    var localStream = null;
    var peerConnections = new Map(); // odego -> RTCPeerConnection
    var currentVoiceChannel = null;
    var voiceParticipants = new Map(); // odego -> participant info
    var isMuted = false;
    var isDeafened = false;
    var iceServers = [];
    var pendingCandidates = new Map(); // odego -> candidates[] для хранения кандидатов до установки remote description

    // ============================================
    // ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
    // ============================================

    function $(selector) { return document.querySelector(selector); }
    function $$(selector) { return document.querySelectorAll(selector); }

    function formatTime(date) {
        var d = new Date(date);
        var now = new Date();
        var isToday = d.toDateString() === now.toDateString();
        var time = d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
        if (isToday) return 'Сегодня в ' + time;
        return d.toLocaleDateString('ru-RU') + ' ' + time;
    }

    function getInitials(name) {
        return name ? name.substring(0, 2).toUpperCase() : '??';
    }

    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // ИСПРАВЛЕНО: Поиск канала где находится пользователь
    function getUserVoiceChannel(odego) {
        if (!currentServer || !currentServer.channels) return null;
        for (var i = 0; i < currentServer.channels.length; i++) {
            var channel = currentServer.channels[i];
            if (channel.type === 'voice' && channel.voiceParticipants) {
                for (var j = 0; j < channel.voiceParticipants.length; j++) {
                    // ИСПРАВЛЕНО: проверяем odego
                    if (channel.voiceParticipants[j].odego === odego) {
                        return channel;
                    }
                }
            }
        }
        return null;
    }

    // ============================================
    // API ЗАПРОСЫ
    // ============================================

    function api(endpoint, options) {
        options = options || {};
        var headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = 'Bearer ' + token;

        return fetch(API_URL + endpoint, Object.assign({}, options, { headers: headers }))
            .then(function(res) {
                return res.json().then(function(data) {
                    if (!res.ok) throw new Error(data.error || 'Ошибка сервера');
                    return data;
                });
            })
            .catch(function(e) {
                console.error('API Error:', e);
                throw e;
            });
    }

    // ============================================
    // WEBSOCKET
    // ============================================

    function connectWebSocket() {
        if (ws && ws.readyState === WebSocket.OPEN) return;

        ws = new WebSocket(WS_URL);

        ws.onopen = function() {
            console.log('WebSocket connected');
            reconnectAttempts = 0;
            if (token) {
                ws.send(JSON.stringify({ type: 'AUTH', token: token }));
            }
        };

        ws.onmessage = function(event) {
            try {
                var data = JSON.parse(event.data);
                handleWebSocketMessage(data);
            } catch (e) {
                console.error('WS Parse Error:', e);
            }
        };

        ws.onclose = function() {
            console.log('WebSocket disconnected');
            // Очищаем голосовое соединение при разрыве WS
            if (currentVoiceChannel) {
                cleanupVoice();
                currentVoiceChannel = null;
                renderChannels();
                renderUserPanel();
                renderVoiceConnected();
            }
            if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS && token) {
                reconnectAttempts++;
                setTimeout(connectWebSocket, Math.min(1000 * reconnectAttempts, 5000));
            }
        };

        ws.onerror = function(error) {
            console.error('WebSocket error:', error);
        };
    }

    function handleWebSocketMessage(data) {
        console.log('[WS] Received:', data.type, data);
        
        switch (data.type) {
            case 'AUTH_SUCCESS':
                console.log('WebSocket authenticated, odego:', data.odego);
                if (data.iceServers) iceServers = data.iceServers;
                break;

            case 'NEW_CHANNEL_MESSAGE':
                if (currentChannel && data.message.channel_id === currentChannel.id) {
                    messages.push(data.message);
                    renderMessages();
                    scrollToBottom();
                }
                break;

            case 'NEW_DIRECT_MESSAGE':
                if (currentDM && (data.message.sender_id === currentDM.id || data.message.recipient_id === currentDM.id)) {
                    messages.push(data.message);
                    renderMessages();
                    scrollToBottom();
                }
                break;

            case 'USER_TYPING':
                handleTypingIndicator(data);
                break;

            case 'USER_STATUS_CHANGE':
                updateUserStatus(data.odego, data.status);
                break;

            case 'CHANNEL_CREATED':
                if (currentServer && data.channel.server_id === currentServer.id) {
                    currentServer.channels.push(data.channel);
                    renderChannels();
                }
                break;

            case 'CHANNEL_DELETED':
                if (currentServer && data.serverId === currentServer.id) {
                    currentServer.channels = currentServer.channels.filter(function(c) { return c.id !== data.channelId; });
                    if (currentChannel && currentChannel.id === data.channelId) {
                        currentChannel = currentServer.channels.find(function(c) { return c.type === 'text'; });
                        loadMessages();
                    }
                    renderChannels();
                }
                break;

            case 'MEMBER_JOINED':
                if (currentServer && currentServer.id === data.serverId) {
                    if (!currentServer.members) currentServer.members = [];
                    currentServer.members.push(data.member);
                    renderMembers();
                }
                break;

            case 'MEMBER_LEFT':
                if (currentServer && currentServer.id === data.serverId) {
                    currentServer.members = currentServer.members ? currentServer.members.filter(function(m) { return m.id !== data.odego; }) : [];
                    renderMembers();
                }
                break;

            case 'SERVER_DELETED':
                servers = servers.filter(function(s) { return s.id !== data.serverId; });
                if (currentServer && currentServer.id === data.serverId) {
                    currentServer = null;
                    currentChannel = null;
                }
                render();
                break;

            // ============================================
            // ИСПРАВЛЕННЫЕ ГОЛОСОВЫЕ ОБРАБОТЧИКИ
            // ============================================

            case 'VOICE_JOINED':
                handleVoiceJoined(data);
                break;

            case 'VOICE_LEFT':
                handleVoiceLeft(data);
                break;

            case 'VOICE_USER_JOINED':
                handleVoiceUserJoined(data);
                break;

            case 'VOICE_USER_LEFT':
                handleVoiceUserLeft(data);
                break;

            case 'VOICE_SIGNAL':
                handleVoiceSignal(data);
                break;

            case 'VOICE_USER_MUTE':
                handleVoiceUserMute(data);
                break;

            case 'VOICE_USER_DEAFEN':
                handleVoiceUserDeafen(data);
                break;

            case 'VOICE_STATE_UPDATE':
                handleVoiceStateUpdate(data);
                break;

            case 'VOICE_ERROR':
                console.error('Voice error:', data.error);
                alert('Ошибка голосового чата: ' + data.error);
                cleanupVoice();
                currentVoiceChannel = null;
                renderChannels();
                renderUserPanel();
                renderVoiceConnected();
                break;

            case 'VOICE_KICKED':
                handleVoiceKicked(data);
                break;
        }
    }

    function handleTypingIndicator(data) {
        var key = data.channelId || data.odego;
        typingUsers[key] = { username: data.username, time: Date.now() };
        renderTypingIndicator();

        setTimeout(function() {
            if (typingUsers[key] && Date.now() - typingUsers[key].time > 3000) {
                delete typingUsers[key];
                renderTypingIndicator();
            }
        }, 3500);
    }

    function renderTypingIndicator() {
        var indicator = $('.typing-indicator');
        if (!indicator) return;

        var key = currentChannel ? currentChannel.id : (currentDM ? currentDM.id : null);
        var typing = typingUsers[key];

        if (typing && typing.username !== currentUser.username) {
            indicator.textContent = typing.username + ' печатает...';
        } else {
            indicator.textContent = '';
        }
    }

    function updateUserStatus(odego, status) {
        if (currentServer && currentServer.members) {
            var member = currentServer.members.find(function(m) { return m.id === odego; });
            if (member) {
                member.status = status;
                renderMembers();
            }
        }
    }

    // ============================================
    // ИСПРАВЛЕННЫЙ WEBRTC ГОЛОСОВОЙ ЧАТ
    // ============================================

    function joinVoiceChannel(channel) {
        if (currentVoiceChannel && currentVoiceChannel.id === channel.id) {
            console.log('[VOICE] Already in this channel');
            return;
        }

        console.log('[VOICE] Requesting microphone access...');

        navigator.mediaDevices.getUserMedia({
            audio: {
                echoCancellation: true,
                noiseSuppression: true,
                autoGainControl: true
            },
            video: false
        }).then(function(stream) {
            console.log('[VOICE] Got microphone access, joining channel:', channel.id);
            localStream = stream;
            
            // Применяем текущее состояние mute
            if (isMuted) {
                localStream.getAudioTracks().forEach(function(track) {
                    track.enabled = false;
                });
            }
            
            ws.send(JSON.stringify({ type: 'VOICE_JOIN', channelId: channel.id }));
        }).catch(function(error) {
            console.error('Failed to get microphone access:', error);
            alert('Не удалось получить доступ к микрофону. Проверьте разрешения браузера.');
        });
    }

    // ИСПРАВЛЕНО: Обработка успешного присоединения к голосовому каналу
    function handleVoiceJoined(data) {
        console.log('[VOICE] Joined channel:', data.channelId, 'Existing participants:', data.participants);
        
        // Находим канал в текущем сервере
        if (currentServer) {
            currentVoiceChannel = currentServer.channels.find(function(c) { return c.id === data.channelId; });
        }
        
        if (data.iceServers) iceServers = data.iceServers;

        // Очищаем старые соединения
        voiceParticipants.clear();
        pendingCandidates.clear();
        
        // Добавляем существующих участников и создаём соединения с ними
        // Мы (как присоединяющийся) инициируем соединение
        if (data.participants && data.participants.length > 0) {
            data.participants.forEach(function(p) {
                console.log('[VOICE] Creating connection to existing participant:', p.username, p.odego);
                voiceParticipants.set(p.odego, p);
                // Мы инициаторы - создаём offer
                createPeerConnection(p.odego, true);
            });
        }

        isMuted = false;
        isDeafened = false;

        // Обновляем локальный список участников канала
        if (currentVoiceChannel) {
            currentVoiceChannel.voiceParticipants = Array.from(voiceParticipants.values());
            // Добавляем себя
            currentVoiceChannel.voiceParticipants.push({
                odego: currentUser.id,
                username: currentUser.username,
                muted: false,
                deafened: false
            });
        }

        renderChannels();
        renderUserPanel();
        renderVoiceConnected();
    }

    // ИСПРАВЛЕНО: Обработка выхода из голосового канала
    function handleVoiceLeft(data) {
        console.log('[VOICE] Left channel:', data.channelId);
        cleanupVoice();
        currentVoiceChannel = null;

        renderChannels();
        renderUserPanel();
        renderVoiceConnected();
    }

    // ИСПРАВЛЕНО: Когда другой пользователь присоединяется
    function handleVoiceUserJoined(data) {
        console.log('[VOICE] User joined:', data.user.username, data.user.odego);
        
        // Проверяем, что это не мы сами
        if (data.user.odego === currentUser.id) {
            console.log('[VOICE] Ignoring own join event');
            return;
        }
        
        // Проверяем дубликаты
        if (voiceParticipants.has(data.user.odego)) {
            console.log('[VOICE] User already in participants, skipping');
            return;
        }
        
        voiceParticipants.set(data.user.odego, data.user);

        // Обновляем список участников канала
        if (currentServer && currentVoiceChannel) {
            var channel = currentServer.channels.find(function(c) { return c.id === data.channelId; });
            if (channel) {
                if (!channel.voiceParticipants) channel.voiceParticipants = [];
                // Проверяем дубликаты в channel.voiceParticipants
                var exists = channel.voiceParticipants.some(function(p) { return p.odego === data.user.odego; });
                if (!exists) {
                    channel.voiceParticipants.push(data.user);
                }
            }
        }

        // НЕ создаём соединение здесь - новый участник сам пришлёт offer
        // Мы только ждём сигнала от него

        renderChannels();
    }

    // ИСПРАВЛЕНО: Когда другой пользователь покидает канал
    function handleVoiceUserLeft(data) {
        console.log('[VOICE] User left:', data.odego);
        
        voiceParticipants.delete(data.odego);
        pendingCandidates.delete(data.odego);

        // Закрываем peer connection
        var pc = peerConnections.get(data.odego);
        if (pc) {
            pc.close();
            peerConnections.delete(data.odego);
        }

        // Удаляем аудио элемент
        var audioEl = document.getElementById('audio-' + data.odego);
        if (audioEl) {
            audioEl.srcObject = null;
            audioEl.remove();
        }

        // Обновляем список участников канала
        if (currentServer) {
            var channel = currentServer.channels.find(function(c) { return c.id === data.channelId; });
            if (channel && channel.voiceParticipants) {
                channel.voiceParticipants = channel.voiceParticipants.filter(function(p) { return p.odego !== data.odego; });
            }
        }

        renderChannels();
    }

    // ИСПРАВЛЕНО: Обработка WebRTC сигналов
    function handleVoiceSignal(data) {
        var signal = data.signal;
        console.log('[VOICE SIGNAL] From:', data.fromUserId, 'Type:', signal.type || 'candidate');

        if (signal.type === 'offer') {
            handleOffer(data.fromUserId, data.fromUsername, signal);
        } else if (signal.type === 'answer') {
            handleAnswer(data.fromUserId, signal);
        } else if (signal.candidate) {
            handleIceCandidate(data.fromUserId, signal);
        }
    }

    // ИСПРАВЛЕНО: Создание peer connection
    function createPeerConnection(odego, initiator) {
        console.log('[WEBRTC] Creating peer connection to:', odego, 'initiator:', initiator);
        
        // Закрываем старое соединение если есть
        if (peerConnections.has(odego)) {
            var oldPc = peerConnections.get(odego);
            oldPc.close();
            peerConnections.delete(odego);
        }

        var config = { 
            iceServers: iceServers.length > 0 ? iceServers : [{ urls: 'stun:stun.l.google.com:19302' }]
        };
        
        var pc = new RTCPeerConnection(config);
        peerConnections.set(odego, pc);
        pendingCandidates.set(odego, []);

        // Добавляем локальный аудио поток
        if (localStream) {
            localStream.getTracks().forEach(function(track) {
                console.log('[WEBRTC] Adding local track:', track.kind);
                pc.addTrack(track, localStream);
            });
        }

        // Обработка ICE кандидатов
        pc.onicecandidate = function(event) {
            if (event.candidate) {
                console.log('[WEBRTC] Sending ICE candidate to:', odego);
                ws.send(JSON.stringify({
                    type: 'VOICE_SIGNAL',
                    targetUserId: odego,
                    signal: event.candidate
                }));
            }
        };

        // Обработка изменения состояния ICE
        pc.oniceconnectionstatechange = function() {
            console.log('[WEBRTC] ICE state for', odego, ':', pc.iceConnectionState);
            if (pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'disconnected') {
                console.log('[WEBRTC] Connection failed/disconnected with:', odego);
            }
        };

        // ИСПРАВЛЕНО: Обработка входящего аудио потока
        pc.ontrack = function(event) {
            console.log('[WEBRTC] Received remote track from:', odego, 'kind:', event.track.kind);
            
            if (event.streams && event.streams[0]) {
                var audioEl = document.getElementById('audio-' + odego);
                if (!audioEl) {
                    audioEl = document.createElement('audio');
                    audioEl.id = 'audio-' + odego;
                    audioEl.autoplay = true;
                    audioEl.playsInline = true;
                    document.body.appendChild(audioEl);
                    console.log('[WEBRTC] Created audio element for:', odego);
                }
                
                audioEl.srcObject = event.streams[0];
                audioEl.muted = isDeafened;
                
                // Пробуем воспроизвести
                audioEl.play().then(function() {
                    console.log('[WEBRTC] Audio playing for:', odego);
                }).catch(function(e) {
                    console.error('[WEBRTC] Audio play failed:', e);
                });
            }
        };

        // Если мы инициатор, создаём offer
        if (initiator) {
            pc.createOffer().then(function(offer) {
                console.log('[WEBRTC] Created offer for:', odego);
                return pc.setLocalDescription(offer);
            }).then(function() {
                console.log('[WEBRTC] Sending offer to:', odego);
                ws.send(JSON.stringify({
                    type: 'VOICE_SIGNAL',
                    targetUserId: odego,
                    signal: pc.localDescription
                }));
            }).catch(function(e) {
                console.error('[WEBRTC] Error creating offer:', e);
            });
        }

        return pc;
    }

    // ИСПРАВЛЕНО: Обработка входящего offer
    function handleOffer(odego, username, offer) {
        console.log('[WEBRTC] Handling offer from:', odego);
        
        // Добавляем участника если ещё нет
        if (!voiceParticipants.has(odego)) {
            voiceParticipants.set(odego, {
                odego: odego,
                username: username,
                muted: false,
                deafened: false
            });
        }
        
        // Создаём peer connection (мы не инициаторы)
        var pc = createPeerConnection(odego, false);
        
        pc.setRemoteDescription(new RTCSessionDescription(offer)).then(function() {
            console.log('[WEBRTC] Set remote description (offer) from:', odego);
            
            // Применяем отложенные ICE кандидаты
            var candidates = pendingCandidates.get(odego) || [];
            candidates.forEach(function(candidate) {
                pc.addIceCandidate(new RTCIceCandidate(candidate)).catch(function(e) {
                    console.error('[WEBRTC] Error adding pending candidate:', e);
                });
            });
            pendingCandidates.set(odego, []);
            
            return pc.createAnswer();
        }).then(function(answer) {
            console.log('[WEBRTC] Created answer for:', odego);
            return pc.setLocalDescription(answer);
        }).then(function() {
            console.log('[WEBRTC] Sending answer to:', odego);
            ws.send(JSON.stringify({
                type: 'VOICE_SIGNAL',
                targetUserId: odego,
                signal: pc.localDescription
            }));
        }).catch(function(e) {
            console.error('[WEBRTC] Error handling offer:', e);
        });
    }

    // ИСПРАВЛЕНО: Обработка входящего answer
    function handleAnswer(odego, answer) {
        console.log('[WEBRTC] Handling answer from:', odego);
        
        var pc = peerConnections.get(odego);
        if (!pc) {
            console.error('[WEBRTC] No peer connection for answer from:', odego);
            return;
        }
        
        pc.setRemoteDescription(new RTCSessionDescription(answer)).then(function() {
            console.log('[WEBRTC] Set remote description (answer) from:', odego);
            
            // Применяем отложенные ICE кандидаты
            var candidates = pendingCandidates.get(odego) || [];
            candidates.forEach(function(candidate) {
                pc.addIceCandidate(new RTCIceCandidate(candidate)).catch(function(e) {
                    console.error('[WEBRTC] Error adding pending candidate:', e);
                });
            });
            pendingCandidates.set(odego, []);
        }).catch(function(e) {
            console.error('[WEBRTC] Error handling answer:', e);
        });
    }

    // ИСПРАВЛЕНО: Обработка ICE кандидатов
    function handleIceCandidate(odego, candidate) {
        var pc = peerConnections.get(odego);
        
        if (!pc) {
            console.log('[WEBRTC] Queuing ICE candidate for:', odego);
            if (!pendingCandidates.has(odego)) {
                pendingCandidates.set(odego, []);
            }
            pendingCandidates.get(odego).push(candidate);
            return;
        }
        
        if (pc.remoteDescription) {
            pc.addIceCandidate(new RTCIceCandidate(candidate)).then(function() {
                console.log('[WEBRTC] Added ICE candidate from:', odego);
            }).catch(function(e) {
                console.error('[WEBRTC] Error adding ICE candidate:', e);
            });
        } else {
            console.log('[WEBRTC] Queuing ICE candidate (no remote desc) for:', odego);
            if (!pendingCandidates.has(odego)) {
                pendingCandidates.set(odego, []);
            }
            pendingCandidates.get(odego).push(candidate);
        }
    }

    function handleVoiceUserMute(data) {
        var participant = voiceParticipants.get(data.odego);
        if (participant) {
            participant.muted = data.muted;
        }

        if (currentServer) {
            currentServer.channels.forEach(function(channel) {
                if (channel.voiceParticipants) {
                    var p = channel.voiceParticipants.find(function(p) { return p.odego === data.odego; });
                    if (p) p.muted = data.muted;
                }
            });
        }

        renderChannels();
    }

    function handleVoiceUserDeafen(data) {
        var participant = voiceParticipants.get(data.odego);
        if (participant) {
            participant.deafened = data.deafened;
            participant.muted = data.muted;
        }

        renderChannels();
    }

    // ИСПРАВЛЕНО: Обработка обновления состояния голоса (для синхронизации между устройствами)
    function handleVoiceStateUpdate(data) {
        console.log('[VOICE STATE] Update:', data.action, 'user:', data.odego, 'channel:', data.channelId);
        
        if (!currentServer) return;
        
        var channel = currentServer.channels.find(function(c) { return c.id === data.channelId; });
        if (!channel) return;
        
        if (!channel.voiceParticipants) channel.voiceParticipants = [];

        if (data.action === 'join') {
            // ИСПРАВЛЕНО: Проверяем дубликаты перед добавлением
            var exists = channel.voiceParticipants.some(function(p) { return p.odego === data.odego; });
            if (!exists) {
                channel.voiceParticipants.push({
                    odego: data.odego,
                    username: data.username,
                    muted: false,
                    deafened: false
                });
            }
        } else if (data.action === 'leave') {
            channel.voiceParticipants = channel.voiceParticipants.filter(function(p) { return p.odego !== data.odego; });
        }

        renderChannels();
    }

    function handleVoiceKicked(data) {
        alert('Вы были отключены от голосового канала: ' + data.reason);
        cleanupVoice();
        currentVoiceChannel = null;
        renderChannels();
        renderUserPanel();
        renderVoiceConnected();
    }

    function leaveVoiceChannel() {
        if (!currentVoiceChannel) return;

        console.log('[VOICE] Leaving channel');
        ws.send(JSON.stringify({ type: 'VOICE_LEAVE' }));
        cleanupVoice();
        currentVoiceChannel = null;

        renderChannels();
        renderUserPanel();
        renderVoiceConnected();
    }

    // ИСПРАВЛЕНО: Очистка всех голосовых ресурсов
    function cleanupVoice() {
        console.log('[VOICE] Cleaning up voice resources');
        
        // Закрываем все peer connections
        peerConnections.forEach(function(pc, odego) {
            console.log('[VOICE] Closing peer connection:', odego);
            pc.close();
            var audioEl = document.getElementById('audio-' + odego);
            if (audioEl) {
                audioEl.srcObject = null;
                audioEl.remove();
            }
        });
        peerConnections.clear();
        pendingCandidates.clear();

        // Останавливаем локальный поток
        if (localStream) {
            localStream.getTracks().forEach(function(track) { 
                track.stop(); 
            });
            localStream = null;
        }

        voiceParticipants.clear();
        isMuted = false;
        isDeafened = false;
    }

    function toggleMute() {
        if (!localStream) return;

        isMuted = !isMuted;
        localStream.getAudioTracks().forEach(function(track) {
            track.enabled = !isMuted;
        });

        console.log('[VOICE] Mute toggled:', isMuted);
        ws.send(JSON.stringify({ type: 'VOICE_TOGGLE_MUTE', muted: isMuted }));

        renderUserPanel();
        renderVoiceConnected();
    }

    function toggleDeafen() {
        isDeafened = !isDeafened;

        // Mute/unmute все входящие аудио
        document.querySelectorAll('audio[id^="audio-"]').forEach(function(audio) {
            audio.muted = isDeafened;
        });

        // Если заглушили звук, автоматически mute микрофон
        if (isDeafened && !isMuted) {
            isMuted = true;
            if (localStream) {
                localStream.getAudioTracks().forEach(function(track) {
                    track.enabled = false;
                });
            }
        }

        console.log('[VOICE] Deafen toggled:', isDeafened);
        ws.send(JSON.stringify({ type: 'VOICE_TOGGLE_DEAFEN', deafened: isDeafened }));

        renderUserPanel();
        renderVoiceConnected();
    }

    // ============================================
    // РЕНДЕРИНГ
    // ============================================

    function render() {
        var app = $('#app');

        if (!token || !currentUser) {
            renderAuth();
            return;
        }

        var html = '<div class="app-container">' +
            '<div class="server-list" id="serverList"></div>';
        
        if (currentServer) {
            html += '<div class="channel-sidebar" id="channelSidebar"></div>' +
                '<div class="chat-area" id="chatArea"></div>' +
                '<div class="members-sidebar" id="membersSidebar"></div>';
        } else {
            html += '<div class="dm-sidebar" id="dmSidebar"></div>' +
                '<div class="chat-area" id="chatArea"></div>';
        }
        
        html += '</div><div id="modalContainer"></div>';

        app.innerHTML = html;

        renderServerList();

        if (currentServer) {
            renderChannelSidebar();
            renderChatArea();
            renderMembers();
        } else {
            renderDMSidebar();
            renderDMChatArea();
        }
    }

    function renderAuth() {
        var app = $('#app');
        var isLogin = !window.showRegister;

        var html = '<div class="auth-container">' +
            '<div class="auth-box">' +
            '<h1>' + (isLogin ? 'С возвращением!' : 'Создать аккаунт') + '</h1>' +
            '<p>' + (isLogin ? 'Мы так рады видеть вас снова!' : 'Присоединяйтесь к нам!') + '</p>' +
            '<div id="authError"></div>' +
            '<form id="authForm">';
        
        if (!isLogin) {
            html += '<div class="form-group">' +
                '<label>Имя пользователя</label>' +
                '<input type="text" id="username" required minlength="3" maxlength="32">' +
                '</div>';
        }
        
        html += '<div class="form-group">' +
            '<label>Email</label>' +
            '<input type="email" id="email" required>' +
            '</div>' +
            '<div class="form-group">' +
            '<label>Пароль</label>' +
            '<input type="password" id="password" required minlength="6">' +
            '</div>' +
            '<button type="submit" class="btn">' + (isLogin ? 'Войти' : 'Зарегистрироваться') + '</button>' +
            '</form>' +
            '<div class="auth-switch">' +
            (isLogin ? 'Нет аккаунта?' : 'Уже есть аккаунт?') +
            ' <a onclick="window.showRegister = ' + isLogin + '; renderAuth();">' + (isLogin ? 'Зарегистрироваться' : 'Войти') + '</a>' +
            '</div>' +
            '</div>' +
            '</div>';

        app.innerHTML = html;

        $('#authForm').onsubmit = function(e) {
            e.preventDefault();
            var email = $('#email').value;
            var password = $('#password').value;
            var usernameEl = $('#username');
            var username = usernameEl ? usernameEl.value : null;

            var endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
            var body = isLogin ? { email: email, password: password } : { email: email, password: password, username: username };
            
            api(endpoint, { method: 'POST', body: JSON.stringify(body) })
                .then(function(data) {
                    token = data.token;
                    currentUser = data.user;
                    localStorage.setItem('token', token);

                    connectWebSocket();
                    return loadServers();
                })
                .then(function() {
                    render();
                })
                .catch(function(e) {
                    $('#authError').innerHTML = '<div class="error-msg">' + e.message + '</div>';
                });
        };
    }

    function renderServerList() {
        var container = $('#serverList');
        if (!container) return;

        var html = '<div class="server-icon home ' + (!currentServer ? 'active' : '') + '" onclick="selectHome()" title="Личные сообщения">🏠</div>' +
            '<div class="separator"></div>';
        
        for (var i = 0; i < servers.length; i++) {
            var s = servers[i];
            html += '<div class="server-icon ' + (currentServer && currentServer.id === s.id ? 'active' : '') + '" ' +
                'onclick="selectServer(\'' + s.id + '\')" title="' + escapeHtml(s.name) + '">';
            if (s.icon_url) {
                html += '<img src="' + s.icon_url + '">';
            } else {
                html += getInitials(s.name);
            }
            html += '</div>';
        }
        
        html += '<div class="server-icon add" onclick="showCreateServerModal()" title="Добавить сервер">+</div>';

        container.innerHTML = html;
    }

    function renderChannelSidebar() {
        var container = $('#channelSidebar');
        if (!container || !currentServer) return;

        container.innerHTML = '<div class="server-header" onclick="showServerSettings()">' +
            escapeHtml(currentServer.name) +
            '<span>⌄</span>' +
            '</div>' +
            '<div class="channel-list" id="channelList"></div>' +
            '<div id="voiceConnectedPanel"></div>' +
            '<div class="user-panel" id="userPanel"></div>';

        renderChannels();
        renderVoiceConnected();
        renderUserPanel();
    }

    function renderChannels() {
        var container = $('#channelList');
        if (!container || !currentServer) return;

        var channels = currentServer.channels || [];
        var textChannels = channels.filter(function(c) { return c.type === 'text'; });
        var voiceChannels = channels.filter(function(c) { return c.type === 'voice'; });

        var html = '<div class="channel-category">' +
            '<span>Текстовые каналы</span>' +
            (currentServer.owner_id === currentUser.id ? '<button onclick="showCreateChannelModal(\'text\')">+</button>' : '') +
            '</div>';

        for (var i = 0; i < textChannels.length; i++) {
            var c = textChannels[i];
            html += '<div class="channel-item ' + (currentChannel && currentChannel.id === c.id ? 'active' : '') + '" onclick="selectChannel(\'' + c.id + '\')">' +
                '<span class="icon">#</span>' +
                '<span class="name">' + escapeHtml(c.name) + '</span>';
            if (currentServer.owner_id === currentUser.id && textChannels.length > 1) {
                html += '<button class="delete-btn" onclick="event.stopPropagation(); deleteChannel(\'' + c.id + '\')">×</button>';
            }
            html += '</div>';
        }

        html += '<div class="channel-category">' +
            '<span>Голосовые каналы</span>' +
            (currentServer.owner_id === currentUser.id ? '<button onclick="showCreateChannelModal(\'voice\')">+</button>' : '') +
            '</div>';

        for (var j = 0; j < voiceChannels.length; j++) {
            var vc = voiceChannels[j];
            var participants = vc.voiceParticipants || [];
            var hasUsers = participants.length > 0;
            var isConnected = currentVoiceChannel && currentVoiceChannel.id === vc.id;

            html += '<div class="voice-channel ' + (hasUsers ? 'has-users' : '') + '">' +
                '<div class="channel-item ' + (isConnected ? 'active' : '') + '" onclick="handleVoiceChannelClick(\'' + vc.id + '\')">' +
                '<span class="icon">🔊</span>' +
                '<span class="name">' + escapeHtml(vc.name) + '</span>';
            if (currentServer.owner_id === currentUser.id && voiceChannels.length > 1) {
                html += '<button class="delete-btn" onclick="event.stopPropagation(); deleteChannel(\'' + vc.id + '\')">×</button>';
            }
            html += '</div>';

            if (hasUsers) {
                html += '<div class="voice-participants">';
                for (var k = 0; k < participants.length; k++) {
                    var p = participants[k];
                    html += '<div class="voice-participant ' + (p.muted ? 'muted' : '') + ' ' + (p.deafened ? 'deafened' : '') + '">' +
                        '<div class="avatar">' + getInitials(p.username) + '</div>' +
                        '<span class="name">' + escapeHtml(p.username) + '</span>' +
                        '<span class="status-icons">' +
                        (p.muted ? '<span class="mute-icon">🔇</span>' : '') +
                        (p.deafened ? '<span class="deafen-icon">🔕</span>' : '') +
                        '</span></div>';
                }
                html += '</div>';
            }
            html += '</div>';
        }

        container.innerHTML = html;
    }

    function renderVoiceConnected() {
        var container = $('#voiceConnectedPanel');
        if (!container) return;

        if (!currentVoiceChannel) {
            container.innerHTML = '';
            return;
        }

        container.innerHTML = '<div class="voice-connected">' +
            '<div class="voice-status">' +
            '<div class="indicator"></div>' +
            '<div class="text">' +
            '<div class="title">Голосовой канал</div>' +
            '<div class="channel">' + escapeHtml(currentVoiceChannel.name) + '</div>' +
            '</div></div>' +
            '<div class="voice-controls">' +
            '<button onclick="toggleMute()" class="' + (isMuted ? 'active' : '') + '" title="' + (isMuted ? 'Включить микрофон' : 'Выключить микрофон') + '">' +
            (isMuted ? '🔇' : '🎤') + '</button>' +
            '<button onclick="toggleDeafen()" class="' + (isDeafened ? 'active' : '') + '" title="' + (isDeafened ? 'Включить звук' : 'Выключить звук') + '">' +
            (isDeafened ? '🔕' : '🔔') + '</button>' +
            '<button onclick="leaveVoiceChannel()" class="disconnect" title="Отключиться">📞</button>' +
            '</div></div>';
    }

    function renderUserPanel() {
        var container = $('#userPanel');
        if (!container) return;

        var html = '<div class="avatar">' + getInitials(currentUser.username) + '</div>' +
            '<div class="info">' +
            '<div class="username">' + escapeHtml(currentUser.username) + '</div>' +
            '<div class="status">В сети</div>' +
            '</div>' +
            '<div class="actions">';
        
        if (currentVoiceChannel) {
            html += '<button onclick="toggleMute()" class="' + (isMuted ? 'muted' : '') + '" title="' + (isMuted ? 'Вкл. микрофон' : 'Выкл. микрофон') + '">' +
                (isMuted ? '🔇' : '🎤') + '</button>' +
                '<button onclick="toggleDeafen()" class="' + (isDeafened ? 'muted' : '') + '" title="' + (isDeafened ? 'Вкл. звук' : 'Выкл. звук') + '">' +
                (isDeafened ? '🔕' : '🎧') + '</button>';
        }
        
        html += '<button onclick="logout()" title="Выйти">🚪</button></div>';

        container.innerHTML = html;
    }

    function renderChatArea() {
        var container = $('#chatArea');
        if (!container) return;

        if (!currentChannel) {
            container.innerHTML = '<div class="empty-state">' +
                '<div class="icon">💬</div>' +
                '<h3>Выберите канал</h3>' +
                '<p>Выберите текстовый канал для начала общения</p>' +
                '</div>';
            return;
        }

        container.innerHTML = '<div class="chat-header">' +
            '<span class="icon">#</span>' +
            '<span>' + escapeHtml(currentChannel.name) + '</span>' +
            '</div>' +
            '<div class="messages-container" id="messagesContainer"></div>' +
            '<div class="typing-indicator"></div>' +
            '<div class="message-input-container">' +
            '<div class="message-input">' +
            '<input type="text" id="messageInput" placeholder="Написать в #' + escapeHtml(currentChannel.name) + '" maxlength="2000">' +
            '<button onclick="sendMessage()">➤</button>' +
            '</div></div>';

        renderMessages();
        setupMessageInput();
    }

    function renderMessages() {
        var container = $('#messagesContainer');
        if (!container) return;

        if (messages.length === 0) {
            var channelName = currentChannel ? currentChannel.name : 'чата';
            container.innerHTML = '<div class="empty-state">' +
                '<div class="icon">👋</div>' +
                '<h3>Начните общение!</h3>' +
                '<p>Это начало канала #' + escapeHtml(channelName) + '</p>' +
                '</div>';
            return;
        }

        var html = '';
        for (var i = 0; i < messages.length; i++) {
            var m = messages[i];
            var username = m.username || m.sender_username;
            html += '<div class="message">' +
                '<div class="avatar">' + getInitials(username) + '</div>' +
                '<div class="content">' +
                '<div class="header">' +
                '<span class="author">' + escapeHtml(username) + '</span>' +
                '<span class="timestamp">' + formatTime(m.created_at) + '</span>' +
                '</div>' +
                '<div class="text">' + escapeHtml(m.content) + '</div>' +
                '</div></div>';
        }

        container.innerHTML = html;
        scrollToBottom();
    }

    function renderMembers() {
        var container = $('#membersSidebar');
        if (!container || !currentServer || !currentServer.members) return;

        var online = currentServer.members.filter(function(m) { return m.status === 'online'; });
        var offline = currentServer.members.filter(function(m) { return m.status !== 'online'; });

        var html = '<div class="members-category">В сети — ' + online.length + '</div>';
        
        for (var i = 0; i < online.length; i++) {
            var m = online[i];
            var inVoice = getUserVoiceChannel(m.id);
            html += '<div class="member-item" onclick="startDM(\'' + m.id + '\')">' +
                '<div class="avatar">' + getInitials(m.username) +
                '<div class="status-dot online"></div></div>' +
                '<span class="name">' + escapeHtml(m.username) + '</span>' +
                (inVoice ? '<span class="voice-icon">🔊</span>' : '') +
                '</div>';
        }
        
        html += '<div class="members-category">Не в сети — ' + offline.length + '</div>';
        
        for (var j = 0; j < offline.length; j++) {
            var mo = offline[j];
            html += '<div class="member-item" onclick="startDM(\'' + mo.id + '\')">' +
                '<div class="avatar">' + getInitials(mo.username) +
                '<div class="status-dot offline"></div></div>' +
                '<span class="name">' + escapeHtml(mo.username) + '</span>' +
                '</div>';
        }

        container.innerHTML = html;
    }

    function renderDMSidebar() {
        var container = $('#dmSidebar');
        if (!container) return;

        container.innerHTML = '<div class="dm-header">' +
            '<input type="text" class="dm-search" placeholder="Найти или начать беседу" id="dmSearch">' +
            '</div>' +
            '<div class="dm-list" id="dmList"></div>' +
            '<div class="user-panel" id="userPanel"></div>';

        renderDMList();
        renderUserPanel();

        $('#dmSearch').oninput = function(e) {
            var query = e.target.value;
            if (query.length < 2) {
                renderDMList();
                return;
            }
            api('/api/users/search?q=' + encodeURIComponent(query))
                .then(function(users) {
                    var list = $('#dmList');
                    if (users.length === 0) {
                        list.innerHTML = '<div class="empty-state"><p>Никого не найдено</p></div>';
                        return;
                    }
                    var html = '';
                    for (var i = 0; i < users.length; i++) {
                        var u = users[i];
                        html += '<div class="dm-item" onclick="startDM(\'' + u.id + '\')">' +
                            '<div class="avatar">' + getInitials(u.username) + '</div>' +
                            '<span class="name">' + escapeHtml(u.username) + '</span>' +
                            '</div>';
                    }
                    list.innerHTML = html;
                })
                .catch(function() {});
        };
    }

    function renderDMList() {
        api('/api/dm')
            .then(function(conversations) {
                var list = $('#dmList');
                if (!list) return;

                if (conversations.length === 0) {
                    list.innerHTML = '<div class="empty-state"><p>Нет бесед</p></div>';
                    return;
                }

                var html = '';
                for (var i = 0; i < conversations.length; i++) {
                    var c = conversations[i];
                    html += '<div class="dm-item ' + (currentDM && currentDM.id === c.id ? 'active' : '') + '" onclick="selectDM(\'' + c.id + '\', \'' + escapeHtml(c.username) + '\')">' +
                        '<div class="avatar">' + getInitials(c.username) + '</div>' +
                        '<span class="name">' + escapeHtml(c.username) + '</span>' +
                        '</div>';
                }
                list.innerHTML = html;
            })
            .catch(function() {});
    }

    function renderDMChatArea() {
        var container = $('#chatArea');
        if (!container) return;

        if (!currentDM) {
            container.innerHTML = '<div class="empty-state">' +
                '<div class="icon">💬</div>' +
                '<h3>Личные сообщения</h3>' +
                '<p>Выберите беседу или найдите пользователя</p>' +
                '</div>';
            return;
        }

        container.innerHTML = '<div class="chat-header">' +
            '<span class="icon">@</span>' +
            '<span>' + escapeHtml(currentDM.username) + '</span>' +
            '</div>' +
            '<div class="messages-container" id="messagesContainer"></div>' +
            '<div class="typing-indicator"></div>' +
            '<div class="message-input-container">' +
            '<div class="message-input">' +
            '<input type="text" id="messageInput" placeholder="Написать @' + escapeHtml(currentDM.username) + '" maxlength="2000">' +
            '<button onclick="sendDM()">➤</button>' +
            '</div></div>';

        renderMessages();
        setupDMInput();
    }

    // ============================================
    // МОДАЛЬНЫЕ ОКНА
    // ============================================

    function showCreateServerModal() {
        var container = $('#modalContainer');
        container.innerHTML = '<div class="modal-overlay" onclick="closeModal(event)">' +
            '<div class="modal" onclick="event.stopPropagation()">' +
            '<div class="modal-header">' +
            '<h2>Создать сервер</h2>' +
            '<p>Ваш сервер — это место, где вы общаетесь с друзьями</p>' +
            '</div>' +
            '<div class="modal-tabs">' +
            '<button class="active" onclick="showCreateTab()">Создать</button>' +
            '<button onclick="showJoinTab()">Присоединиться</button>' +
            '</div>' +
            '<div class="modal-body" id="modalBody">' +
            '<div class="form-group">' +
            '<label>Название сервера</label>' +
            '<input type="text" id="serverName" placeholder="Мой крутой сервер" maxlength="100">' +
            '</div></div>' +
            '<div class="modal-footer">' +
            '<button class="btn secondary" onclick="closeModal()">Отмена</button>' +
            '<button class="btn" id="modalAction" onclick="createServer()">Создать</button>' +
            '</div></div></div>';
    }

    window.showCreateTab = function() {
        var buttons = $$('.modal-tabs button');
        for (var i = 0; i < buttons.length; i++) buttons[i].classList.remove('active');
        buttons[0].classList.add('active');
        $('#modalBody').innerHTML = '<div class="form-group">' +
            '<label>Название сервера</label>' +
            '<input type="text" id="serverName" placeholder="Мой крутой сервер" maxlength="100">' +
            '</div>';
        $('#modalAction').textContent = 'Создать';
        $('#modalAction').onclick = createServer;
    };

    window.showJoinTab = function() {
        var buttons = $$('.modal-tabs button');
        for (var i = 0; i < buttons.length; i++) buttons[i].classList.remove('active');
        buttons[1].classList.add('active');
        $('#modalBody').innerHTML = '<div class="form-group">' +
            '<label>Код приглашения</label>' +
            '<input type="text" id="inviteCode" placeholder="Например: abc123XY" maxlength="10">' +
            '</div>';
        $('#modalAction').textContent = 'Присоединиться';
        $('#modalAction').onclick = joinServer;
    };

    function showCreateChannelModal(type) {
        var container = $('#modalContainer');
        var typeName = type === 'voice' ? 'голосовой' : 'текстовый';
        var placeholder = type === 'voice' ? 'Общий голосовой' : 'general';
        
        container.innerHTML = '<div class="modal-overlay" onclick="closeModal(event)">' +
            '<div class="modal" onclick="event.stopPropagation()">' +
            '<div class="modal-header">' +
            '<h2>Создать ' + typeName + ' канал</h2>' +
            '</div>' +
            '<div class="modal-body">' +
            '<div class="form-group">' +
            '<label>Название канала</label>' +
            '<input type="text" id="channelName" placeholder="' + placeholder + '" maxlength="100">' +
            '</div></div>' +
            '<div class="modal-footer">' +
            '<button class="btn secondary" onclick="closeModal()">Отмена</button>' +
            '<button class="btn" onclick="createChannel(\'' + type + '\')">Создать</button>' +
            '</div></div></div>';
    }

    function showServerSettings() {
        if (!currentServer) return;

        var container = $('#modalContainer');
        var footerContent = '';
        
        if (currentServer.owner_id === currentUser.id) {
            footerContent = '<button class="btn" style="background: var(--red);" onclick="deleteServer()">Удалить сервер</button>';
        } else {
            footerContent = '<button class="btn" style="background: var(--red);" onclick="leaveServer()">Покинуть сервер</button>';
        }
        
        container.innerHTML = '<div class="modal-overlay" onclick="closeModal(event)">' +
            '<div class="modal" onclick="event.stopPropagation()">' +
            '<div class="modal-header">' +
            '<h2>' + escapeHtml(currentServer.name) + '</h2>' +
            '</div>' +
            '<div class="modal-body">' +
            '<div class="form-group">' +
            '<label>Код приглашения</label>' +
            '<div class="invite-code" id="inviteCodeDisplay">Загрузка...</div>' +
            '</div></div>' +
            '<div class="modal-footer">' +
            footerContent +
            '<button class="btn secondary" onclick="closeModal()">Закрыть</button>' +
            '</div></div></div>';

        loadInviteCode();
    }

    function loadInviteCode() {
        api('/api/servers/' + currentServer.id + '/invite')
            .then(function(data) {
                $('#inviteCodeDisplay').textContent = data.invite_code;
            })
            .catch(function() {
                $('#inviteCodeDisplay').textContent = 'Ошибка загрузки';
            });
    }

    function closeModal(event) {
        if (event && event.target !== event.currentTarget) return;
        $('#modalContainer').innerHTML = '';
    }

    // ============================================
    // ДЕЙСТВИЯ
    // ============================================

    function loadServers() {
        return api('/api/servers')
            .then(function(data) {
                servers = data;
            })
            .catch(function(e) {
                console.error('Failed to load servers:', e);
            });
    }

    function selectServer(serverId) {
        api('/api/servers/' + serverId)
            .then(function(data) {
                currentServer = data;
                currentChannel = currentServer.channels ? currentServer.channels.find(function(c) { return c.type === 'text'; }) : null;
                currentDM = null;
                render();
                if (currentChannel) loadMessages();
            })
            .catch(function(e) {
                console.error('Failed to select server:', e);
            });
    }

    function selectHome() {
        currentServer = null;
        currentChannel = null;
        render();
    }

    function selectChannel(channelId) {
        if (!currentServer || !currentServer.channels) return;
        var channel = currentServer.channels.find(function(c) { return c.id === channelId; });
        if (!channel || channel.type !== 'text') return;

        currentChannel = channel;
        renderChatArea();
        loadMessages();
    }

    function handleVoiceChannelClick(channelId) {
        if (!currentServer || !currentServer.channels) return;
        var channel = currentServer.channels.find(function(c) { return c.id === channelId; });
        if (!channel || channel.type !== 'voice') return;

        if (currentVoiceChannel && currentVoiceChannel.id === channelId) {
            console.log('[VOICE] Already in this channel, ignoring click');
            return;
        }

        joinVoiceChannel(channel);
    }

    function loadMessages() {
        if (!currentChannel) return;
        api('/api/channels/' + currentChannel.id + '/messages?limit=50')
            .then(function(data) {
                messages = data;
                renderMessages();
            })
            .catch(function(e) {
                console.error('Failed to load messages:', e);
            });
    }

    function setupMessageInput() {
        var input = $('#messageInput');
        if (!input) return;

        input.onkeydown = function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        };

        var typingTimeout;
        input.oninput = function() {
            clearTimeout(typingTimeout);
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'TYPING_START', channelId: currentChannel.id }));
            }
            typingTimeout = setTimeout(function() {}, 3000);
        };

        input.focus();
    }

    function sendMessage() {
        var input = $('#messageInput');
        var content = input && input.value ? input.value.trim() : '';
        if (!content || !currentChannel) return;

        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'CHANNEL_MESSAGE',
                channelId: currentChannel.id,
                content: content
            }));
        }

        input.value = '';
    }

    function selectDM(odego, username) {
        currentDM = { id: odego, username: username };
        api('/api/dm/' + odego + '?limit=50')
            .then(function(data) {
                messages = data;
                renderDMChatArea();
            })
            .catch(function(e) {
                console.error('Failed to load DMs:', e);
            });
    }

    function startDM(odego) {
        currentServer = null;
        currentChannel = null;
        api('/api/users/' + odego)
            .then(function(user) {
                currentDM = { id: odego, username: user.username };
                return api('/api/dm/' + odego + '?limit=50');
            })
            .then(function(data) {
                messages = data;
                render();
            })
            .catch(function(e) {
                console.error('Failed to start DM:', e);
            });
    }

    function setupDMInput() {
        var input = $('#messageInput');
        if (!input) return;

        input.onkeydown = function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendDM();
            }
        };

        var typingTimeout;
        input.oninput = function() {
            clearTimeout(typingTimeout);
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'TYPING_START', recipientId: currentDM.id }));
            }
            typingTimeout = setTimeout(function() {}, 3000);
        };

        input.focus();
    }

    function sendDM() {
        var input = $('#messageInput');
        var content = input && input.value ? input.value.trim() : '';
        if (!content || !currentDM) return;

        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'DIRECT_MESSAGE',
                recipientId: currentDM.id,
                content: content
            }));
        }

        input.value = '';
    }

    function createServer() {
        var nameEl = $('#serverName');
        var name = nameEl && nameEl.value ? nameEl.value.trim() : '';
        if (!name) {
            alert('Введите название');
            return;
        }

        api('/api/servers', {
            method: 'POST',
            body: JSON.stringify({ name: name })
        })
            .then(function(server) {
                servers.push(server);
                closeModal();
                selectServer(server.id);
            })
            .catch(function(e) {
                alert(e.message);
            });
    }

    function joinServer() {
        var codeEl = $('#inviteCode');
        var code = codeEl && codeEl.value ? codeEl.value.trim() : '';
        if (!code) {
            alert('Введите код');
            return;
        }

        api('/api/servers/join/' + code, { method: 'POST' })
            .then(function(server) {
                servers.push(server);
                closeModal();
                selectServer(server.id);
            })
            .catch(function(e) {
                alert(e.message);
            });
    }

    function createChannel(type) {
        var nameEl = $('#channelName');
        var name = nameEl && nameEl.value ? nameEl.value.trim() : '';
        if (!name) {
            alert('Введите название');
            return;
        }

        api('/api/servers/' + currentServer.id + '/channels', {
            method: 'POST',
            body: JSON.stringify({ name: name, type: type })
        })
            .then(function() {
                closeModal();
            })
            .catch(function(e) {
                alert(e.message);
            });
    }

    function deleteChannel(channelId) {
        if (!confirm('Удалить канал?')) return;
        api('/api/channels/' + channelId, { method: 'DELETE' })
            .catch(function(e) {
                alert(e.message);
            });
    }

    function deleteServer() {
        if (!confirm('Вы уверены? Это действие нельзя отменить!')) return;
        api('/api/servers/' + currentServer.id, { method: 'DELETE' })
            .then(function() {
                servers = servers.filter(function(s) { return s.id !== currentServer.id; });
                currentServer = null;
                currentChannel = null;
                closeModal();
                render();
            })
            .catch(function(e) {
                alert(e.message);
            });
    }

    function leaveServer() {
        if (!confirm('Покинуть сервер?')) return;
        api('/api/servers/' + currentServer.id + '/leave', { method: 'POST' })
            .then(function() {
                servers = servers.filter(function(s) { return s.id !== currentServer.id; });
                currentServer = null;
                currentChannel = null;
                closeModal();
                render();
            })
            .catch(function(e) {
                alert(e.message);
            });
    }

    function scrollToBottom() {
        var container = $('#messagesContainer');
        if (container) {
            container.scrollTop = container.scrollHeight;
        }
    }

    function logout() {
        if (currentVoiceChannel) {
            leaveVoiceChannel();
        }
        token = null;
        currentUser = null;
        localStorage.removeItem('token');
        if (ws) ws.close();
        servers = [];
        currentServer = null;
        currentChannel = null;
        currentDM = null;
        messages = [];
        render();
    }

    // Expose functions globally
    window.selectServer = selectServer;
    window.selectHome = selectHome;
    window.selectChannel = selectChannel;
    window.handleVoiceChannelClick = handleVoiceChannelClick;
    window.selectDM = selectDM;
    window.startDM = startDM;
    window.showCreateServerModal = showCreateServerModal;
    window.showCreateChannelModal = showCreateChannelModal;
    window.showServerSettings = showServerSettings;
    window.createServer = createServer;
    window.joinServer = joinServer;
    window.createChannel = createChannel;
    window.deleteChannel = deleteChannel;
    window.deleteServer = deleteServer;
    window.leaveServer = leaveServer;
    window.sendMessage = sendMessage;
    window.sendDM = sendDM;
    window.closeModal = closeModal;
    window.logout = logout;
    window.toggleMute = toggleMute;
    window.toggleDeafen = toggleDeafen;
    window.leaveVoiceChannel = leaveVoiceChannel;
    window.renderAuth = renderAuth;

    // ============================================
    // ИНИЦИАЛИЗАЦИЯ
    // ============================================

    function init() {
        token = localStorage.getItem('token');

        if (token) {
            api('/api/auth/me')
                .then(function(user) {
                    currentUser = user;
                    connectWebSocket();
                    return loadServers();
                })
                .then(function() {
                    render();
                })
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
</script>
</body>
</html>
    `);
});

// ============================================
// ЗАПУСК СЕРВЕРА
// ============================================

initializeDatabase().then(() => {
    server.listen(PORT, () => {
        console.log('🚀 Discord Clone запущен на порту ' + PORT);
        console.log('📡 WebSocket готов');
        console.log('🎤 Голосовой чат включен');
    });
}).catch(err => {
    console.error('Failed to initialize:', err);
    process.exit(1);
});
