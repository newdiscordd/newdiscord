/**
 * Discord Clone - Full Stack Server
 * Бэкенд + Фронтенд в одном файле
 */

const express = require('express');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const http = require('http');
const path = require('path');

// ============================================
// КОНФИГУРАЦИЯ
// ============================================

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const BCRYPT_ROUNDS = 10;
const DATABASE_URL = process.env.DATABASE_URL;

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
            CREATE INDEX IF NOT EXISTS idx_dm_users ON direct_messages(sender_id, recipient_id);
            CREATE INDEX IF NOT EXISTS idx_server_members ON server_members(server_id, user_id);
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

function sendToUser(userId, data) {
    const sockets = clients.get(userId);
    if (sockets) {
        const msg = JSON.stringify(data);
        sockets.forEach(ws => ws.readyState === ws.OPEN && ws.send(msg));
    }
}

async function broadcastToServer(serverId, data) {
    try {
        const result = await pool.query('SELECT user_id FROM server_members WHERE server_id = $1', [serverId]);
        const msg = JSON.stringify(data);
        result.rows.forEach(row => {
            const sockets = clients.get(row.user_id);
            if (sockets) sockets.forEach(ws => ws.readyState === ws.OPEN && ws.send(msg));
        });
    } catch (e) { console.error('Broadcast error:', e); }
}

wss.on('connection', (ws) => {
    let userId = null;
    const pingInterval = setInterval(() => ws.readyState === ws.OPEN && ws.ping(), 30000);

    ws.on('message', async (data) => {
        try {
            const msg = JSON.parse(data.toString());

            if (msg.type === 'AUTH') {
                try {
                    const decoded = jwt.verify(msg.token, JWT_SECRET);
                    userId = decoded.id;
                    if (!clients.has(userId)) clients.set(userId, new Set());
                    clients.get(userId).add(ws);
                    await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['online', userId]);
                    ws.send(JSON.stringify({ type: 'AUTH_SUCCESS', userId, username: decoded.username }));
                    
                    const servers = await pool.query('SELECT server_id FROM server_members WHERE user_id = $1', [userId]);
                    servers.rows.forEach(r => broadcastToServer(r.server_id, { type: 'USER_STATUS_CHANGE', userId, status: 'online' }));
                } catch (e) {
                    ws.send(JSON.stringify({ type: 'AUTH_ERROR', error: 'Недействительный токен' }));
                }
                return;
            }

            if (!userId) {
                ws.send(JSON.stringify({ type: 'ERROR', error: 'Требуется аутентификация' }));
                return;
            }

            switch (msg.type) {
                case 'CHANNEL_MESSAGE': {
                    const { channelId, content } = msg;
                    if (!content?.trim() || content.length > 2000) break;
                    
                    const ch = await pool.query('SELECT * FROM channels WHERE id = $1', [channelId]);
                    if (!ch.rows[0]) break;
                    
                    const mem = await pool.query('SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2', [ch.rows[0].server_id, userId]);
                    if (!mem.rows[0]) break;
                    
                    const msgId = uuidv4();
                    await pool.query('INSERT INTO messages (id, channel_id, author_id, content) VALUES ($1, $2, $3, $4)', [msgId, channelId, userId, content.trim()]);
                    
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
                    await pool.query('INSERT INTO direct_messages (id, sender_id, recipient_id, content) VALUES ($1, $2, $3, $4)', [msgId, userId, recipientId, content.trim()]);
                    
                    const sender = await pool.query('SELECT username, avatar_url FROM users WHERE id = $1', [userId]);
                    const newMsg = {
                        id: msgId, sender_id: userId, recipient_id: recipientId, content: content.trim(),
                        created_at: new Date().toISOString(),
                        sender_username: sender.rows[0].username, sender_avatar: sender.rows[0].avatar_url,
                        recipient_username: recipient.rows[0].username, recipient_avatar: recipient.rows[0].avatar_url
                    };
                    sendToUser(userId, { type: 'NEW_DIRECT_MESSAGE', message: newMsg });
                    sendToUser(recipientId, { type: 'NEW_DIRECT_MESSAGE', message: newMsg });
                    break;
                }

                case 'TYPING_START': {
                    const { channelId, recipientId } = msg;
                    const user = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
                    if (channelId) {
                        const ch = await pool.query('SELECT server_id FROM channels WHERE id = $1', [channelId]);
                        if (ch.rows[0]) broadcastToServer(ch.rows[0].server_id, { type: 'USER_TYPING', channelId, userId, username: user.rows[0]?.username });
                    } else if (recipientId) {
                        sendToUser(recipientId, { type: 'USER_TYPING', userId, username: user.rows[0]?.username });
                    }
                    break;
                }

                case 'TYPING_STOP': {
                    const { channelId, recipientId } = msg;
                    if (channelId) {
                        const ch = await pool.query('SELECT server_id FROM channels WHERE id = $1', [channelId]);
                        if (ch.rows[0]) broadcastToServer(ch.rows[0].server_id, { type: 'USER_STOP_TYPING', channelId, userId });
                    } else if (recipientId) {
                        sendToUser(recipientId, { type: 'USER_STOP_TYPING', userId });
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
        if (userId) {
            const sockets = clients.get(userId);
            if (sockets) {
                sockets.delete(ws);
                if (sockets.size === 0) {
                    clients.delete(userId);
                    await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['offline', userId]);
                    const servers = await pool.query('SELECT server_id FROM server_members WHERE user_id = $1', [userId]);
                    servers.rows.forEach(r => broadcastToServer(r.server_id, { type: 'USER_STATUS_CHANGE', userId, status: 'offline' }));
                }
            }
        }
    });
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
        
        res.json({ token, user: { id: result.rows[0].id, username: result.rows[0].username, email: result.rows[0].email, avatar_url: result.rows[0].avatar_url, status: 'online' } });
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
            `SELECT s.*, sm.role as my_role FROM servers s JOIN server_members sm ON s.id = sm.server_id WHERE sm.user_id = $1 ORDER BY s.created_at DESC`,
            [req.user.id]
        );
        const servers = await Promise.all(result.rows.map(async (s) => {
            const ch = await pool.query('SELECT * FROM channels WHERE server_id = $1 ORDER BY position', [s.id]);
            return { ...s, channels: ch.rows };
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
        const channelId = uuidv4();
        const inviteCode = generateInviteCode();
        
        await client.query('INSERT INTO servers (id, name, owner_id, invite_code) VALUES ($1, $2, $3, $4)', [serverId, name.trim(), req.user.id, inviteCode]);
        await client.query('INSERT INTO server_members (id, server_id, user_id, role) VALUES ($1, $2, $3, $4)', [uuidv4(), serverId, req.user.id, 'owner']);
        await client.query('INSERT INTO channels (id, server_id, name, type) VALUES ($1, $2, $3, $4)', [channelId, serverId, 'general', 'text']);
        
        await client.query('COMMIT');
        
        const server = await pool.query('SELECT * FROM servers WHERE id = $1', [serverId]);
        const channels = await pool.query('SELECT * FROM channels WHERE server_id = $1', [serverId]);
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
        const channels = await pool.query('SELECT * FROM channels WHERE server_id = $1 ORDER BY position', [req.params.serverId]);
        const members = await pool.query(
            `SELECT u.id, u.username, u.avatar_url, u.status, sm.role, sm.joined_at FROM server_members sm JOIN users u ON sm.user_id = u.id WHERE sm.server_id = $1`,
            [req.params.serverId]
        );
        res.json({ ...server.rows[0], channels: channels.rows, members: members.rows });
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
        
        const channels = await pool.query('SELECT * FROM channels WHERE server_id = $1', [server.rows[0].id]);
        const user = await pool.query('SELECT id, username, avatar_url, status FROM users WHERE id = $1', [req.user.id]);
        
        broadcastToServer(server.rows[0].id, { type: 'MEMBER_JOINED', serverId: server.rows[0].id, member: { ...user.rows[0], role: 'member' } });
        res.json({ ...server.rows[0], channels: channels.rows });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/servers/:serverId/leave', authenticateToken, checkServerMembership, async (req, res) => {
    try {
        const server = await pool.query('SELECT owner_id FROM servers WHERE id = $1', [req.params.serverId]);
        if (server.rows[0].owner_id === req.user.id) return res.status(400).json({ error: 'Владелец не может покинуть' });
        
        await pool.query('DELETE FROM server_members WHERE server_id = $1 AND user_id = $2', [req.params.serverId, req.user.id]);
        broadcastToServer(req.params.serverId, { type: 'MEMBER_LEFT', serverId: req.params.serverId, userId: req.user.id });
        res.json({ message: 'Вы покинули сервер' });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/servers/:serverId/members', authenticateToken, checkServerMembership, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT u.id, u.username, u.avatar_url, u.status, sm.role, sm.joined_at FROM server_members sm JOIN users u ON sm.user_id = u.id WHERE sm.server_id = $1`,
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
        const result = await pool.query('SELECT * FROM channels WHERE server_id = $1 ORDER BY position', [req.params.serverId]);
        res.json(result.rows);
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/servers/:serverId/channels', authenticateToken, checkServerOwner, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name?.trim()) return res.status(400).json({ error: 'Название обязательно' });
        
        const formatted = name.trim().toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-_а-яё]/gi, '');
        const channelId = uuidv4();
        
        const pos = await pool.query('SELECT COALESCE(MAX(position), -1) + 1 as p FROM channels WHERE server_id = $1', [req.params.serverId]);
        const result = await pool.query(
            'INSERT INTO channels (id, server_id, name, type, position) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [channelId, req.params.serverId, formatted, 'text', pos.rows[0].p]
        );
        
        broadcastToServer(req.params.serverId, { type: 'CHANNEL_CREATED', channel: result.rows[0] });
        res.status(201).json(result.rows[0]);
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
        
        const count = await pool.query('SELECT COUNT(*) as c FROM channels WHERE server_id = $1', [channel.rows[0].server_id]);
        if (parseInt(count.rows[0].c) <= 1) return res.status(400).json({ error: 'Нельзя удалить последний канал' });
        
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
            `SELECT m.*, u.username, u.avatar_url FROM messages m JOIN users u ON m.author_id = u.id WHERE m.channel_id = $1 ORDER BY m.created_at DESC LIMIT $2`,
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

app.get('/api/dm/:userId', authenticateToken, async (req, res) => {
    try {
        const { limit = 50 } = req.query;
        const result = await pool.query(`
            SELECT dm.*, s.username as sender_username, s.avatar_url as sender_avatar, r.username as recipient_username, r.avatar_url as recipient_avatar
            FROM direct_messages dm JOIN users s ON dm.sender_id = s.id JOIN users r ON dm.recipient_id = r.id
            WHERE (dm.sender_id = $1 AND dm.recipient_id = $2) OR (dm.sender_id = $2 AND dm.recipient_id = $1)
            ORDER BY dm.created_at DESC LIMIT $3
        `, [req.user.id, req.params.userId, parseInt(limit)]);
        res.json(result.rows.reverse());
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/dm/:userId', authenticateToken, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content?.trim() || content.length > 2000) return res.status(400).json({ error: 'Некорректное сообщение' });
        
        const recipient = await pool.query('SELECT id, username, avatar_url FROM users WHERE id = $1', [req.params.userId]);
        if (!recipient.rows[0]) return res.status(404).json({ error: 'Пользователь не найден' });
        
        const msgId = uuidv4();
        await pool.query('INSERT INTO direct_messages (id, sender_id, recipient_id, content) VALUES ($1, $2, $3, $4)', [msgId, req.user.id, req.params.userId, content.trim()]);
        
        const sender = await pool.query('SELECT username, avatar_url FROM users WHERE id = $1', [req.user.id]);
        const msg = {
            id: msgId, sender_id: req.user.id, recipient_id: req.params.userId, content: content.trim(), created_at: new Date().toISOString(),
            sender_username: sender.rows[0].username, sender_avatar: sender.rows[0].avatar_url,
            recipient_username: recipient.rows[0].username, recipient_avatar: recipient.rows[0].avatar_url
        };
        
        sendToUser(req.user.id, { type: 'NEW_DIRECT_MESSAGE', message: msg });
        sendToUser(req.params.userId, { type: 'NEW_DIRECT_MESSAGE', message: msg });
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
        const result = await pool.query('SELECT id, username, avatar_url, status FROM users WHERE username ILIKE $1 AND id != $2 LIMIT 20', [`%${q}%`, req.user.id]);
        res.json(result.rows);
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/users/:userId', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, avatar_url, status, created_at FROM users WHERE id = $1', [req.params.userId]);
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
        res.json({ status: 'ok', database: 'connected', connections: clients.size });
    } catch (e) {
        res.status(500).json({ status: 'error', database: 'disconnected' });
    }
});

// ============================================
// FRONTEND - ГЛАВНАЯ СТРАНИЦА
// ============================================

const HTML_PAGE = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Discord Clone</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg-primary: #313338;
            --bg-secondary: #2b2d31;
            --bg-tertiary: #1e1f22;
            --bg-modifier-hover: rgba(79, 84, 92, 0.4);
            --bg-modifier-selected: rgba(79, 84, 92, 0.6);
            --text-normal: #dbdee1;
            --text-muted: #949ba4;
            --text-link: #00a8fc;
            --brand-500: #5865f2;
            --brand-560: #4752c4;
            --green-360: #23a559;
            --red-400: #f23f43;
            --yellow-300: #faa81a;
            --input-bg: #1e1f22;
            --scrollbar-thin-thumb: #1a1b1e;
            --scrollbar-auto-thumb: #2b2d31;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-normal);
            height: 100vh;
            overflow: hidden;
        }

        /* ===== AUTH SCREENS ===== */
        .auth-container {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            background: linear-gradient(135deg, #5865f2 0%, #3b4299 100%);
        }

        .auth-box {
            background: var(--bg-primary);
            padding: 32px;
            border-radius: 8px;
            width: 100%;
            max-width: 480px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        .auth-box h1 {
            text-align: center;
            margin-bottom: 8px;
            font-size: 24px;
            font-weight: 600;
        }

        .auth-box p {
            text-align: center;
            color: var(--text-muted);
            margin-bottom: 24px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 8px;
        }

        .form-group input {
            width: 100%;
            padding: 10px 12px;
            background: var(--input-bg);
            border: none;
            border-radius: 4px;
            color: var(--text-normal);
            font-size: 16px;
            outline: none;
            transition: box-shadow 0.2s;
        }

        .form-group input:focus {
            box-shadow: 0 0 0 2px var(--brand-500);
        }

        .btn {
            width: 100%;
            padding: 12px;
            background: var(--brand-500);
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
        }

        .btn:hover {
            background: var(--brand-560);
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .auth-switch {
            text-align: center;
            margin-top: 16px;
            font-size: 14px;
            color: var(--text-muted);
        }

        .auth-switch a {
            color: var(--text-link);
            cursor: pointer;
            text-decoration: none;
        }

        .auth-switch a:hover {
            text-decoration: underline;
        }

        .error-message {
            background: var(--red-400);
            color: white;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 16px;
            font-size: 14px;
            text-align: center;
        }

        /* ===== MAIN APP LAYOUT ===== */
        .app-container {
            display: flex;
            height: 100vh;
        }

        /* Server List */
        .server-list {
            width: 72px;
            background: var(--bg-tertiary);
            padding: 12px 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 8px;
            overflow-y: auto;
        }

        .server-list::-webkit-scrollbar {
            display: none;
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
            font-weight: 600;
            font-size: 18px;
            color: var(--text-normal);
            position: relative;
        }

        .server-icon:hover {
            border-radius: 16px;
            background: var(--brand-500);
        }

        .server-icon.active {
            border-radius: 16px;
            background: var(--brand-500);
        }

        .server-icon.home {
            background: var(--brand-500);
            color: white;
        }

        .server-icon.add {
            background: var(--bg-primary);
            color: var(--green-360);
            font-size: 24px;
        }

        .server-icon.add:hover {
            background: var(--green-360);
            color: white;
        }

        .server-divider {
            width: 32px;
            height: 2px;
            background: var(--bg-modifier-hover);
            border-radius: 1px;
        }

        /* Sidebar */
        .sidebar {
            width: 240px;
            background: var(--bg-secondary);
            display: flex;
            flex-direction: column;
        }

        .sidebar-header {
            padding: 12px 16px;
            height: 48px;
            display: flex;
            align-items: center;
            font-weight: 600;
            border-bottom: 1px solid var(--bg-tertiary);
            box-shadow: 0 1px 0 rgba(0, 0, 0, 0.2);
        }

        .channel-list {
            flex: 1;
            overflow-y: auto;
            padding: 8px;
        }

        .channel-category {
            padding: 16px 8px 4px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .channel-category-add {
            cursor: pointer;
            opacity: 0;
            transition: opacity 0.2s;
        }

        .channel-category:hover .channel-category-add {
            opacity: 1;
        }

        .channel-item {
            padding: 8px;
            border-radius: 4px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--text-muted);
            transition: all 0.1s;
        }

        .channel-item:hover {
            background: var(--bg-modifier-hover);
            color: var(--text-normal);
        }

        .channel-item.active {
            background: var(--bg-modifier-selected);
            color: var(--text-normal);
        }

        .channel-hash {
            font-size: 20px;
            font-weight: 500;
            opacity: 0.6;
        }

        /* User Panel */
        .user-panel {
            padding: 8px;
            background: var(--bg-tertiary);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: var(--brand-500);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 14px;
            position: relative;
        }

        .user-avatar img {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            object-fit: cover;
        }

        .status-indicator {
            position: absolute;
            bottom: -2px;
            right: -2px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            border: 2px solid var(--bg-tertiary);
        }

        .status-indicator.online {
            background: var(--green-360);
        }

        .status-indicator.offline {
            background: var(--text-muted);
        }

        .user-info {
            flex: 1;
            min-width: 0;
        }

        .user-name {
            font-size: 14px;
            font-weight: 500;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .user-status-text {
            font-size: 12px;
            color: var(--text-muted);
        }

        .logout-btn {
            padding: 6px;
            background: transparent;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            border-radius: 4px;
            transition: all 0.2s;
        }

        .logout-btn:hover {
            background: var(--bg-modifier-hover);
            color: var(--red-400);
        }

        /* Main Content */
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            background: var(--bg-primary);
        }

        .main-header {
            height: 48px;
            padding: 0 16px;
            display: flex;
            align-items: center;
            gap: 8px;
            border-bottom: 1px solid var(--bg-tertiary);
            box-shadow: 0 1px 0 rgba(0, 0, 0, 0.2);
        }

        .main-header-hash {
            color: var(--text-muted);
            font-size: 24px;
        }

        .main-header-title {
            font-weight: 600;
        }

        /* Messages */
        .messages-container {
            flex: 1;
            overflow-y: auto;
            padding: 16px;
            display: flex;
            flex-direction: column;
        }

        .messages-container::-webkit-scrollbar {
            width: 8px;
        }

        .messages-container::-webkit-scrollbar-thumb {
            background: var(--scrollbar-auto-thumb);
            border-radius: 4px;
        }

        .message {
            display: flex;
            gap: 16px;
            padding: 4px 0;
            margin-top: 16px;
        }

        .message:first-child {
            margin-top: auto;
        }

        .message-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--brand-500);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            flex-shrink: 0;
        }

        .message-avatar img {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            object-fit: cover;
        }

        .message-content {
            flex: 1;
            min-width: 0;
        }

        .message-header {
            display: flex;
            align-items: baseline;
            gap: 8px;
        }

        .message-author {
            font-weight: 500;
            color: var(--text-normal);
        }

        .message-timestamp {
            font-size: 12px;
            color: var(--text-muted);
        }

        .message-text {
            margin-top: 4px;
            line-height: 1.4;
            word-break: break-word;
        }

        /* Message Input */
        .message-input-container {
            padding: 0 16px 24px;
        }

        .message-input-wrapper {
            background: var(--input-bg);
            border-radius: 8px;
            padding: 0 16px;
            display: flex;
            align-items: center;
        }

        .message-input {
            flex: 1;
            background: transparent;
            border: none;
            padding: 12px 0;
            color: var(--text-normal);
            font-size: 16px;
            font-family: inherit;
            outline: none;
            resize: none;
            max-height: 200px;
        }

        .message-input::placeholder {
            color: var(--text-muted);
        }

        /* Typing Indicator */
        .typing-indicator {
            padding: 4px 16px;
            font-size: 12px;
            color: var(--text-muted);
            min-height: 20px;
        }

        /* Members Sidebar */
        .members-sidebar {
            width: 240px;
            background: var(--bg-secondary);
            padding: 16px 8px;
            overflow-y: auto;
        }

        .members-category {
            padding: 8px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
        }

        .member-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 6px 8px;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.1s;
        }

        .member-item:hover {
            background: var(--bg-modifier-hover);
        }

        .member-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: var(--brand-500);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 14px;
            position: relative;
        }

        .member-avatar img {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            object-fit: cover;
        }

        .member-name {
            font-size: 14px;
            color: var(--text-muted);
        }

        .member-item:hover .member-name {
            color: var(--text-normal);
        }

        /* DM List */
        .dm-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.1s;
        }

        .dm-item:hover {
            background: var(--bg-modifier-hover);
        }

        .dm-item.active {
            background: var(--bg-modifier-selected);
        }

        /* Modal */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.85);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }

        .modal {
            background: var(--bg-primary);
            border-radius: 8px;
            width: 100%;
            max-width: 440px;
            max-height: 90vh;
            overflow-y: auto;
        }

        .modal-header {
            padding: 16px;
            text-align: center;
        }

        .modal-header h2 {
            font-size: 24px;
            font-weight: 700;
        }

        .modal-header p {
            color: var(--text-muted);
            margin-top: 8px;
        }

        .modal-body {
            padding: 0 16px 16px;
        }

        .modal-footer {
            padding: 16px;
            background: var(--bg-secondary);
            display: flex;
            justify-content: flex-end;
            gap: 8px;
        }

        .modal-footer .btn {
            width: auto;
            padding: 8px 16px;
        }

        .btn-secondary {
            background: transparent;
            color: var(--text-normal);
        }

        .btn-secondary:hover {
            text-decoration: underline;
            background: transparent;
        }

        /* Welcome Screen */
        .welcome-screen {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 32px;
            text-align: center;
        }

        .welcome-screen h2 {
            font-size: 28px;
            margin-bottom: 8px;
        }

        .welcome-screen p {
            color: var(--text-muted);
            max-width: 400px;
        }

        /* Invite Box */
        .invite-box {
            margin-top: 16px;
            padding: 16px;
            background: var(--bg-secondary);
            border-radius: 8px;
        }

        .invite-code {
            display: flex;
            gap: 8px;
            margin-top: 8px;
        }

        .invite-code input {
            flex: 1;
            padding: 8px 12px;
            background: var(--input-bg);
            border: none;
            border-radius: 4px;
            color: var(--text-normal);
            font-family: monospace;
            font-size: 14px;
        }

        .invite-code button {
            padding: 8px 16px;
            background: var(--brand-500);
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 500;
            transition: background 0.2s;
        }

        .invite-code button:hover {
            background: var(--brand-560);
        }

        /* Search Box */
        .search-box {
            padding: 12px;
        }

        .search-input {
            width: 100%;
            padding: 8px 12px;
            background: var(--input-bg);
            border: none;
            border-radius: 4px;
            color: var(--text-normal);
            font-size: 14px;
            outline: none;
        }

        .search-results {
            max-height: 200px;
            overflow-y: auto;
        }

        .search-result-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 12px;
            cursor: pointer;
            transition: background 0.1s;
        }

        .search-result-item:hover {
            background: var(--bg-modifier-hover);
        }

        /* Empty State */
        .empty-state {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            color: var(--text-muted);
            padding: 32px;
            text-align: center;
        }

        .empty-state svg {
            width: 120px;
            height: 120px;
            margin-bottom: 16px;
            opacity: 0.5;
        }

        /* Loading */
        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            font-size: 18px;
            color: var(--text-muted);
        }

        .spinner {
            width: 32px;
            height: 32px;
            border: 3px solid var(--bg-tertiary);
            border-top-color: var(--brand-500);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 12px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Responsive */
        @media (max-width: 768px) {
            .members-sidebar {
                display: none;
            }
            .sidebar {
                width: 200px;
            }
        }

        @media (max-width: 600px) {
            .sidebar {
                display: none;
            }
            .server-list {
                width: 60px;
            }
        }

        /* Hidden */
        .hidden {
            display: none !important;
        }
    </style>
</head>
<body>
    <div id="app">
        <div class="loading">
            <div class="spinner"></div>
            Загрузка...
        </div>
    </div>

    <script>
        // ============================================
        // ГЛОБАЛЬНОЕ СОСТОЯНИЕ
        // ============================================
        const state = {
            user: null,
            token: localStorage.getItem('token'),
            servers: [],
            currentServer: null,
            currentChannel: null,
            currentDM: null,
            messages: [],
            members: [],
            dmList: [],
            typingUsers: new Map(),
            ws: null,
            view: 'home' // home, server, dm
        };

        // API URL (автоопределение)
        const API_URL = window.location.origin;
        const WS_URL = (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + window.location.host;

        // ============================================
        // API ФУНКЦИИ
        // ============================================
        async function api(endpoint, options = {}) {
            const headers = { 'Content-Type': 'application/json' };
            if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
            
            const res = await fetch(API_URL + endpoint, { ...options, headers });
            const data = await res.json();
            
            if (!res.ok) throw new Error(data.error || 'Ошибка запроса');
            return data;
        }

        // ============================================
        // WEBSOCKET
        // ============================================
        function connectWebSocket() {
            if (state.ws) state.ws.close();
            
            state.ws = new WebSocket(WS_URL);
            
            state.ws.onopen = () => {
                console.log('WebSocket подключен');
                if (state.token) {
                    state.ws.send(JSON.stringify({ type: 'AUTH', token: state.token }));
                }
            };
            
            state.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                handleWebSocketMessage(data);
            };
            
            state.ws.onclose = () => {
                console.log('WebSocket отключен, переподключение...');
                setTimeout(connectWebSocket, 3000);
            };
            
            state.ws.onerror = (err) => console.error('WebSocket ошибка:', err);
        }

        function handleWebSocketMessage(data) {
            switch (data.type) {
                case 'AUTH_SUCCESS':
                    console.log('WS Аутентификация успешна');
                    break;
                    
                case 'NEW_CHANNEL_MESSAGE':
                    if (state.currentChannel && data.message.channel_id === state.currentChannel.id) {
                        state.messages.push(data.message);
                        renderMessages();
                        scrollToBottom();
                    }
                    break;
                    
                case 'NEW_DIRECT_MESSAGE':
                    if (state.currentDM && 
                        ((data.message.sender_id === state.currentDM.id && data.message.recipient_id === state.user.id) ||
                         (data.message.sender_id === state.user.id && data.message.recipient_id === state.currentDM.id))) {
                        state.messages.push(data.message);
                        renderMessages();
                        scrollToBottom();
                    }
                    loadDMList();
                    break;
                    
                case 'USER_TYPING':
                    if (data.userId !== state.user.id) {
                        state.typingUsers.set(data.userId, data.username);
                        renderTypingIndicator();
                        setTimeout(() => {
                            state.typingUsers.delete(data.userId);
                            renderTypingIndicator();
                        }, 3000);
                    }
                    break;
                    
                case 'USER_STOP_TYPING':
                    state.typingUsers.delete(data.userId);
                    renderTypingIndicator();
                    break;
                    
                case 'USER_STATUS_CHANGE':
                    const member = state.members.find(m => m.id === data.userId);
                    if (member) {
                        member.status = data.status;
                        renderMembers();
                    }
                    break;
                    
                case 'MEMBER_JOINED':
                    if (state.currentServer && data.serverId === state.currentServer.id) {
                        state.members.push(data.member);
                        renderMembers();
                    }
                    break;
                    
                case 'MEMBER_LEFT':
                    if (state.currentServer && data.serverId === state.currentServer.id) {
                        state.members = state.members.filter(m => m.id !== data.userId);
                        renderMembers();
                    }
                    break;
                    
                case 'CHANNEL_CREATED':
                    if (state.currentServer && data.channel.server_id === state.currentServer.id) {
                        state.currentServer.channels.push(data.channel);
                        renderChannels();
                    }
                    break;
                    
                case 'CHANNEL_DELETED':
                    if (state.currentServer && data.serverId === state.currentServer.id) {
                        state.currentServer.channels = state.currentServer.channels.filter(c => c.id !== data.channelId);
                        if (state.currentChannel && state.currentChannel.id === data.channelId) {
                            state.currentChannel = state.currentServer.channels[0] || null;
                            if (state.currentChannel) loadMessages();
                        }
                        renderChannels();
                    }
                    break;
                    
                case 'SERVER_DELETED':
                    state.servers = state.servers.filter(s => s.id !== data.serverId);
                    if (state.currentServer && state.currentServer.id === data.serverId) {
                        state.currentServer = null;
                        state.currentChannel = null;
                        state.view = 'home';
                    }
                    render();
                    break;
            }
        }

        function sendTyping() {
            if (!state.ws || state.ws.readyState !== WebSocket.OPEN) return;
            
            if (state.currentChannel) {
                state.ws.send(JSON.stringify({ type: 'TYPING_START', channelId: state.currentChannel.id }));
            } else if (state.currentDM) {
                state.ws.send(JSON.stringify({ type: 'TYPING_START', recipientId: state.currentDM.id }));
            }
        }

        // ============================================
        // АВТОРИЗАЦИЯ
        // ============================================
        async function login(email, password) {
            const data = await api('/api/auth/login', {
                method: 'POST',
                body: JSON.stringify({ email, password })
            });
            
            state.token = data.token;
            state.user = data.user;
            localStorage.setItem('token', data.token);
            
            connectWebSocket();
            await loadServers();
            render();
        }

        async function register(username, email, password) {
            const data = await api('/api/auth/register', {
                method: 'POST',
                body: JSON.stringify({ username, email, password })
            });
            
            state.token = data.token;
            state.user = data.user;
            localStorage.setItem('token', data.token);
            
            connectWebSocket();
            await loadServers();
            render();
        }

        function logout() {
            state.token = null;
            state.user = null;
            state.servers = [];
            state.currentServer = null;
            state.currentChannel = null;
            localStorage.removeItem('token');
            if (state.ws) state.ws.close();
            render();
        }

        async function checkAuth() {
            if (!state.token) return false;
            try {
                state.user = await api('/api/auth/me');
                return true;
            } catch (e) {
                state.token = null;
                localStorage.removeItem('token');
                return false;
            }
        }

        // ============================================
        // ДАННЫЕ
        // ============================================
        async function loadServers() {
            state.servers = await api('/api/servers');
        }

        async function loadServer(serverId) {
            const server = await api('/api/servers/' + serverId);
            state.currentServer = server;
            state.members = server.members || [];
            if (server.channels && server.channels.length > 0) {
                state.currentChannel = server.channels[0];
                await loadMessages();
            }
        }

        async function loadMessages() {
            if (!state.currentChannel && !state.currentDM) return;
            
            if (state.currentChannel) {
                state.messages = await api('/api/channels/' + state.currentChannel.id + '/messages');
            } else if (state.currentDM) {
                state.messages = await api('/api/dm/' + state.currentDM.id);
            }
            renderMessages();
            scrollToBottom();
        }

        async function loadDMList() {
            state.dmList = await api('/api/dm');
        }

        async function sendMessage(content) {
            if (!content.trim()) return;
            
            if (state.currentChannel) {
                await api('/api/channels/' + state.currentChannel.id + '/messages', {
                    method: 'POST',
                    body: JSON.stringify({ content })
                });
            } else if (state.currentDM) {
                await api('/api/dm/' + state.currentDM.id, {
                    method: 'POST',
                    body: JSON.stringify({ content })
                });
            }
        }

        async function createServer(name) {
            const server = await api('/api/servers', {
                method: 'POST',
                body: JSON.stringify({ name })
            });
            state.servers.push(server);
            return server;
        }

        async function joinServer(inviteCode) {
            const server = await api('/api/servers/join/' + inviteCode, { method: 'POST' });
            state.servers.push(server);
            return server;
        }

        async function leaveServer(serverId) {
            await api('/api/servers/' + serverId + '/leave', { method: 'POST' });
            state.servers = state.servers.filter(s => s.id !== serverId);
            if (state.currentServer && state.currentServer.id === serverId) {
                state.currentServer = null;
                state.currentChannel = null;
                state.view = 'home';
            }
        }

        async function deleteServer(serverId) {
            await api('/api/servers/' + serverId, { method: 'DELETE' });
            state.servers = state.servers.filter(s => s.id !== serverId);
            if (state.currentServer && state.currentServer.id === serverId) {
                state.currentServer = null;
                state.currentChannel = null;
                state.view = 'home';
            }
        }

        async function createChannel(name) {
            const channel = await api('/api/servers/' + state.currentServer.id + '/channels', {
                method: 'POST',
                body: JSON.stringify({ name })
            });
            return channel;
        }

        async function searchUsers(query) {
            if (query.length < 2) return [];
            return await api('/api/users/search?q=' + encodeURIComponent(query));
        }

        async function getInviteCode() {
            const data = await api('/api/servers/' + state.currentServer.id + '/invite');
            return data.invite_code;
        }

        // ============================================
        // РЕНДЕРИНГ
        // ============================================
        function render() {
            const app = document.getElementById('app');
            
            if (!state.user) {
                app.innerHTML = renderAuth();
                setupAuthEvents();
            } else {
                app.innerHTML = renderApp();
                setupAppEvents();
                renderServerList();
                if (state.view === 'server' && state.currentServer) {
                    renderChannels();
                    renderMembers();
                    renderMessages();
                } else if (state.view === 'dm') {
                    renderDMList();
                    renderMessages();
                } else {
                    renderWelcome();
                }
            }
        }

        function renderAuth() {
            return \`
                <div class="auth-container">
                    <div class="auth-box" id="login-box">
                        <h1>С возвращением!</h1>
                        <p>Мы рады видеть вас снова!</p>
                        <div id="login-error" class="error-message hidden"></div>
                        <form id="login-form">
                            <div class="form-group">
                                <label>Email</label>
                                <input type="email" id="login-email" required>
                            </div>
                            <div class="form-group">
                                <label>Пароль</label>
                                <input type="password" id="login-password" required>
                            </div>
                            <button type="submit" class="btn">Войти</button>
                        </form>
                        <p class="auth-switch">
                            Нужен аккаунт? <a id="show-register">Зарегистрироваться</a>
                        </p>
                    </div>
                    <div class="auth-box hidden" id="register-box">
                        <h1>Создать аккаунт</h1>
                        <div id="register-error" class="error-message hidden"></div>
                        <form id="register-form">
                            <div class="form-group">
                                <label>Имя пользователя</label>
                                <input type="text" id="register-username" required minlength="3" maxlength="32">
                            </div>
                            <div class="form-group">
                                <label>Email</label>
                                <input type="email" id="register-email" required>
                            </div>
                            <div class="form-group">
                                <label>Пароль</label>
                                <input type="password" id="register-password" required minlength="6">
                            </div>
                            <button type="submit" class="btn">Продолжить</button>
                        </form>
                        <p class="auth-switch">
                            Уже есть аккаунт? <a id="show-login">Войти</a>
                        </p>
                    </div>
                </div>
            \`;
        }

        function renderApp() {
            return \`
                <div class="app-container">
                    <div class="server-list" id="server-list"></div>
                    <div class="sidebar" id="sidebar">
                        <div class="sidebar-header" id="sidebar-header"></div>
                        <div class="channel-list" id="channel-list"></div>
                        <div class="user-panel">
                            <div class="user-avatar">
                                \${state.user.avatar_url ? '<img src="' + state.user.avatar_url + '">' : state.user.username[0].toUpperCase()}
                                <div class="status-indicator online"></div>
                            </div>
                            <div class="user-info">
                                <div class="user-name">\${state.user.username}</div>
                                <div class="user-status-text">В сети</div>
                            </div>
                            <button class="logout-btn" id="logout-btn" title="Выйти">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M16 13v-2H7V8l-5 4 5 4v-3z"/>
                                    <path d="M20 3h-9c-1.103 0-2 .897-2 2v4h2V5h9v14h-9v-4H9v4c0 1.103.897 2 2 2h9c1.103 0 2-.897 2-2V5c0-1.103-.897-2-2-2z"/>
                                </svg>
                            </button>
                        </div>
                    </div>
                    <div class="main-content" id="main-content">
                        <div class="main-header" id="main-header"></div>
                        <div class="messages-container" id="messages-container"></div>
                        <div class="typing-indicator" id="typing-indicator"></div>
                        <div class="message-input-container">
                            <div class="message-input-wrapper">
                                <textarea class="message-input" id="message-input" placeholder="Написать сообщение..." rows="1"></textarea>
                            </div>
                        </div>
                    </div>
                    <div class="members-sidebar" id="members-sidebar"></div>
                </div>
                <div id="modal-container"></div>
            \`;
        }

        function renderServerList() {
            const container = document.getElementById('server-list');
            if (!container) return;
            
            let html = \`
                <div class="server-icon home \${state.view === 'home' || state.view === 'dm' ? 'active' : ''}" data-action="home" title="Личные сообщения">
                    <svg width="28" height="20" viewBox="0 0 28 20" fill="currentColor">
                        <path d="M23.0212 1.67671C21.3107 0.879656 19.5079 0.318797 17.6584 0C17.4062 0.461742 17.1749 0.934541 16.9708 1.4184C15.003 1.12145 12.9974 1.12145 11.0283 1.4184C10.819 0.934541 10.589 0.461742 10.3416 0C8.49087 0.318797 6.68679 0.879656 4.97999 1.67671C1.41265 6.77728 0.384626 11.7478 0.900237 16.6449C3.03017 18.1894 5.52889 19.0848 8.23337 19.0848C8.87732 18.2249 9.45002 17.3167 9.94545 16.3663C8.6035 15.8868 7.32172 15.277 6.11969 14.5487C6.44456 14.3266 6.76129 14.0934 7.07045 13.8529C11.0467 15.6331 15.4481 15.6331 19.3814 13.8529C19.6949 14.0934 20.0116 14.3266 20.3365 14.5487C19.1289 15.277 17.8429 15.8868 16.5015 16.3663C16.9979 17.3167 17.5703 18.2249 18.2228 19.0848C20.9261 19.0848 23.4247 18.1894 25.5559 16.6449C26.1633 10.9373 24.7101 6.0183 23.0212 1.67671ZM9.68041 13.6324C8.39503 13.6324 7.33489 12.4937 7.33489 11.0909C7.33489 9.68799 8.37249 8.54917 9.68041 8.54917C10.9883 8.54917 12.0485 9.68799 12.0259 11.0909C12.0034 12.4937 10.9883 13.6324 9.68041 13.6324ZM16.3196 13.6324C15.0342 13.6324 13.9741 12.4937 13.9741 11.0909C13.9741 9.68799 15.0117 8.54917 16.3196 8.54917C17.6275 8.54917 18.6877 9.68799 18.6651 11.0909C18.6426 12.4937 17.6275 13.6324 16.3196 13.6324Z"/>
                    </svg>
                </div>
                <div class="server-divider"></div>
            \`;
            
            state.servers.forEach(server => {
                const isActive = state.currentServer && state.currentServer.id === server.id;
                html += \`
                    <div class="server-icon \${isActive ? 'active' : ''}" data-server-id="\${server.id}" title="\${server.name}">
                        \${server.icon_url ? '<img src="' + server.icon_url + '" style="width:100%;height:100%;border-radius:inherit;object-fit:cover;">' : server.name[0].toUpperCase()}
                    </div>
                \`;
            });
            
            html += \`
                <div class="server-icon add" data-action="add-server" title="Добавить сервер">+</div>
            \`;
            
            container.innerHTML = html;
        }

        function renderChannels() {
            const header = document.getElementById('sidebar-header');
            const list = document.getElementById('channel-list');
            if (!header || !list || !state.currentServer) return;
            
            header.innerHTML = state.currentServer.name;
            
            let html = \`
                <div class="channel-category">
                    <span>Текстовые каналы</span>
                    <span class="channel-category-add" data-action="add-channel" title="Создать канал">+</span>
                </div>
            \`;
            
            (state.currentServer.channels || []).forEach(channel => {
                const isActive = state.currentChannel && state.currentChannel.id === channel.id;
                html += \`
                    <div class="channel-item \${isActive ? 'active' : ''}" data-channel-id="\${channel.id}">
                        <span class="channel-hash">#</span>
                        <span>\${channel.name}</span>
                    </div>
                \`;
            });
            
            html += \`
                <div class="invite-box">
                    <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;">Пригласить друзей</div>
                    <div class="invite-code">
                        <input type="text" id="invite-code-input" readonly>
                        <button id="copy-invite-btn">Копировать</button>
                    </div>
                </div>
            \`;
            
            list.innerHTML = html;
            
            // Load invite code
            getInviteCode().then(code => {
                const input = document.getElementById('invite-code-input');
                if (input) input.value = code;
            });
        }

        function renderDMList() {
            const header = document.getElementById('sidebar-header');
            const list = document.getElementById('channel-list');
            if (!header || !list) return;
            
            header.innerHTML = 'Личные сообщения';
            
            let html = \`
                <div class="search-box">
                    <input type="text" class="search-input" id="user-search" placeholder="Найти или начать беседу">
                </div>
                <div id="search-results" class="search-results"></div>
                <div class="channel-category">Личные сообщения</div>
            \`;
            
            state.dmList.forEach(dm => {
                const isActive = state.currentDM && state.currentDM.id === dm.id;
                html += \`
                    <div class="dm-item \${isActive ? 'active' : ''}" data-dm-id="\${dm.id}">
                        <div class="user-avatar" style="width:32px;height:32px;font-size:14px;">
                            \${dm.avatar_url ? '<img src="' + dm.avatar_url + '">' : dm.username[0].toUpperCase()}
                            <div class="status-indicator \${dm.status}"></div>
                        </div>
                        <span>\${dm.username}</span>
                    </div>
                \`;
            });
            
            if (state.dmList.length === 0) {
                html += '<div style="padding:16px;color:var(--text-muted);text-align:center;font-size:14px;">Нет активных диалогов</div>';
            }
            
            list.innerHTML = html;
        }

        function renderMembers() {
            const container = document.getElementById('members-sidebar');
            if (!container) return;
            
            if (state.view !== 'server') {
                container.innerHTML = '';
                return;
            }
            
            const online = state.members.filter(m => m.status === 'online');
            const offline = state.members.filter(m => m.status !== 'online');
            
            let html = '';
            
            if (online.length > 0) {
                html += '<div class="members-category">В сети — ' + online.length + '</div>';
                online.forEach(member => {
                    html += renderMemberItem(member);
                });
            }
            
            if (offline.length > 0) {
                html += '<div class="members-category">Не в сети — ' + offline.length + '</div>';
                offline.forEach(member => {
                    html += renderMemberItem(member);
                });
            }
            
            container.innerHTML = html;
        }

        function renderMemberItem(member) {
            return \`
                <div class="member-item" data-user-id="\${member.id}">
                    <div class="member-avatar">
                        \${member.avatar_url ? '<img src="' + member.avatar_url + '">' : member.username[0].toUpperCase()}
                        <div class="status-indicator \${member.status}"></div>
                    </div>
                    <span class="member-name">\${member.username}</span>
                </div>
            \`;
        }

        function renderMessages() {
            const container = document.getElementById('messages-container');
            const header = document.getElementById('main-header');
            if (!container || !header) return;
            
            if (state.view === 'server' && state.currentChannel) {
                header.innerHTML = \`
                    <span class="main-header-hash">#</span>
                    <span class="main-header-title">\${state.currentChannel.name}</span>
                \`;
            } else if (state.view === 'dm' && state.currentDM) {
                header.innerHTML = \`
                    <span class="main-header-title">@\${state.currentDM.username}</span>
                \`;
            } else {
                header.innerHTML = '';
            }
            
            if (state.messages.length === 0) {
                container.innerHTML = \`
                    <div class="empty-state">
                        <svg viewBox="0 0 184 132" fill="var(--text-muted)">
                            <path d="M62.5 2h2.6v127h-2.6V2zM117.5 2h2.6v127h-2.6V2zM28 42h128v2H28v-2zM28 87h128v2H28v-2z" fill-opacity=".2"/>
                            <rect x="28" y="2" width="128" height="128" rx="16" stroke="currentColor" stroke-width="4" fill="none"/>
                            <circle cx="92" cy="66" r="24" stroke="currentColor" stroke-width="4" fill="none"/>
                        </svg>
                        <h3>Начните общение!</h3>
                        <p>Отправьте первое сообщение</p>
                    </div>
                \`;
                return;
            }
            
            let html = '';
            state.messages.forEach((msg, i) => {
                const prev = state.messages[i - 1];
                const authorId = msg.author_id || msg.sender_id;
                const prevAuthorId = prev ? (prev.author_id || prev.sender_id) : null;
                const showHeader = !prev || authorId !== prevAuthorId;
                const username = msg.username || msg.sender_username;
                const avatar = msg.avatar_url || msg.sender_avatar;
                
                html += \`
                    <div class="message" \${!showHeader ? 'style="margin-top:2px;"' : ''}>
                        \${showHeader ? \`
                            <div class="message-avatar">
                                \${avatar ? '<img src="' + avatar + '">' : (username ? username[0].toUpperCase() : '?')}
                            </div>
                        \` : '<div style="width:40px;"></div>'}
                        <div class="message-content">
                            \${showHeader ? \`
                                <div class="message-header">
                                    <span class="message-author">\${username}</span>
                                    <span class="message-timestamp">\${formatTime(msg.created_at)}</span>
                                </div>
                            \` : ''}
                            <div class="message-text">\${escapeHtml(msg.content)}</div>
                        </div>
                    </div>
                \`;
            });
            
            container.innerHTML = html;
        }

        function renderTypingIndicator() {
            const container = document.getElementById('typing-indicator');
            if (!container) return;
            
            const users = Array.from(state.typingUsers.values());
            if (users.length === 0) {
                container.textContent = '';
            } else if (users.length === 1) {
                container.textContent = users[0] + ' печатает...';
            } else {
                container.textContent = users.join(', ') + ' печатают...';
            }
        }

        function renderWelcome() {
            const main = document.getElementById('main-content');
            const members = document.getElementById('members-sidebar');
            if (!main) return;
            
            if (members) members.innerHTML = '';
            
            main.innerHTML = \`
                <div class="welcome-screen">
                    <h2>Добро пожаловать!</h2>
                    <p>Выберите сервер слева или создайте новый, чтобы начать общение.</p>
                </div>
            \`;
        }

        // ============================================
        // МОДАЛЬНЫЕ ОКНА
        // ============================================
        function showModal(content) {
            const container = document.getElementById('modal-container');
            if (!container) return;
            
            container.innerHTML = \`
                <div class="modal-overlay" id="modal-overlay">
                    <div class="modal">
                        \${content}
                    </div>
                </div>
            \`;
            
            document.getElementById('modal-overlay').addEventListener('click', (e) => {
                if (e.target.id === 'modal-overlay') closeModal();
            });
        }

        function closeModal() {
            const container = document.getElementById('modal-container');
            if (container) container.innerHTML = '';
        }

        function showAddServerModal() {
            showModal(\`
                <div class="modal-header">
                    <h2>Создать сервер</h2>
                    <p>Создайте свой сервер для общения с друзьями</p>
                </div>
                <div class="modal-body">
                    <form id="create-server-form">
                        <div class="form-group">
                            <label>Название сервера</label>
                            <input type="text" id="server-name-input" required placeholder="Мой сервер">
                        </div>
                    </form>
                    <div style="margin-top:24px;padding-top:16px;border-top:1px solid var(--bg-tertiary);">
                        <p style="font-size:14px;color:var(--text-muted);margin-bottom:8px;">Или присоединитесь по приглашению</p>
                        <div class="form-group">
                            <input type="text" id="invite-code-join" placeholder="Код приглашения">
                        </div>
                        <button class="btn" id="join-server-btn" style="background:var(--green-360);">Присоединиться</button>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" id="cancel-modal-btn">Отмена</button>
                    <button class="btn" id="create-server-btn">Создать</button>
                </div>
            \`);
            
            document.getElementById('cancel-modal-btn').onclick = closeModal;
            document.getElementById('create-server-btn').onclick = async () => {
                const name = document.getElementById('server-name-input').value.trim();
                if (!name) return;
                try {
                    const server = await createServer(name);
                    closeModal();
                    selectServer(server.id);
                } catch (e) {
                    alert(e.message);
                }
            };
            document.getElementById('join-server-btn').onclick = async () => {
                const code = document.getElementById('invite-code-join').value.trim();
                if (!code) return;
                try {
                    const server = await joinServer(code);
                    closeModal();
                    selectServer(server.id);
                } catch (e) {
                    alert(e.message);
                }
            };
        }

        function showCreateChannelModal() {
            showModal(\`
                <div class="modal-header">
                    <h2>Создать канал</h2>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label>Название канала</label>
                        <input type="text" id="channel-name-input" required placeholder="новый-канал">
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" id="cancel-modal-btn">Отмена</button>
                    <button class="btn" id="create-channel-btn">Создать</button>
                </div>
            \`);
            
            document.getElementById('cancel-modal-btn').onclick = closeModal;
            document.getElementById('create-channel-btn').onclick = async () => {
                const name = document.getElementById('channel-name-input').value.trim();
                if (!name) return;
                try {
                    await createChannel(name);
                    closeModal();
                } catch (e) {
                    alert(e.message);
                }
            };
        }

        // ============================================
        // НАВИГАЦИЯ
        // ============================================
        async function selectServer(serverId) {
            state.view = 'server';
            state.currentDM = null;
            await loadServer(serverId);
            render();
        }

        async function selectChannel(channelId) {
            const channel = state.currentServer.channels.find(c => c.id === channelId);
            if (channel) {
                state.currentChannel = channel;
                state.messages = [];
                await loadMessages();
                renderChannels();
                renderMessages();
            }
        }

        async function selectDM(userId) {
            state.view = 'dm';
            state.currentServer = null;
            state.currentChannel = null;
            
            // Get user info
            const user = state.dmList.find(d => d.id === userId);
            if (user) {
                state.currentDM = user;
            } else {
                state.currentDM = await api('/api/users/' + userId);
            }
            
            state.messages = [];
            await loadMessages();
            render();
        }

        async function goHome() {
            state.view = 'home';
            state.currentServer = null;
            state.currentChannel = null;
            state.currentDM = null;
            await loadDMList();
            render();
        }

        // ============================================
        // СОБЫТИЯ
        // ============================================
        function setupAuthEvents() {
            const loginForm = document.getElementById('login-form');
            const registerForm = document.getElementById('register-form');
            const showRegister = document.getElementById('show-register');
            const showLogin = document.getElementById('show-login');
            const loginBox = document.getElementById('login-box');
            const registerBox = document.getElementById('register-box');
            
            loginForm?.addEventListener('submit', async (e) => {
                e.preventDefault();
                const email = document.getElementById('login-email').value;
                const password = document.getElementById('login-password').value;
                const errorEl = document.getElementById('login-error');
                
                try {
                    errorEl.classList.add('hidden');
                    await login(email, password);
                } catch (err) {
                    errorEl.textContent = err.message;
                    errorEl.classList.remove('hidden');
                }
            });
            
            registerForm?.addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('register-username').value;
                const email = document.getElementById('register-email').value;
                const password = document.getElementById('register-password').value;
                const errorEl = document.getElementById('register-error');
                
                try {
                    errorEl.classList.add('hidden');
                    await register(username, email, password);
                } catch (err) {
                    errorEl.textContent = err.message;
                    errorEl.classList.remove('hidden');
                }
            });
            
            showRegister?.addEventListener('click', () => {
                loginBox.classList.add('hidden');
                registerBox.classList.remove('hidden');
            });
            
            showLogin?.addEventListener('click', () => {
                registerBox.classList.add('hidden');
                loginBox.classList.remove('hidden');
            });
        }

        function setupAppEvents() {
            // Server list clicks
            document.getElementById('server-list')?.addEventListener('click', (e) => {
                const serverIcon = e.target.closest('.server-icon');
                if (!serverIcon) return;
                
                const action = serverIcon.dataset.action;
                const serverId = serverIcon.dataset.serverId;
                
                if (action === 'home') {
                    goHome();
                } else if (action === 'add-server') {
                    showAddServerModal();
                } else if (serverId) {
                    selectServer(serverId);
                }
            });
            
            // Channel list clicks
            document.getElementById('channel-list')?.addEventListener('click', (e) => {
                const channelItem = e.target.closest('.channel-item');
                const dmItem = e.target.closest('.dm-item');
                const addChannel = e.target.closest('[data-action="add-channel"]');
                
                if (channelItem) {
                    selectChannel(channelItem.dataset.channelId);
                } else if (dmItem) {
                    selectDM(dmItem.dataset.dmId);
                } else if (addChannel && state.currentServer) {
                    showCreateChannelModal();
                }
            });
            
            // Copy invite code
            document.getElementById('copy-invite-btn')?.addEventListener('click', () => {
                const input = document.getElementById('invite-code-input');
                if (input) {
                    input.select();
                    navigator.clipboard.writeText(input.value);
                }
            });
            
            // Member clicks (start DM)
            document.getElementById('members-sidebar')?.addEventListener('click', (e) => {
                const memberItem = e.target.closest('.member-item');
                if (memberItem && memberItem.dataset.userId !== state.user.id) {
                    selectDM(memberItem.dataset.userId);
                }
            });
            
            // Message input
            const messageInput = document.getElementById('message-input');
            let typingTimeout;
            
            messageInput?.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    const content = messageInput.value.trim();
                    if (content) {
                        sendMessage(content);
                        messageInput.value = '';
                    }
                }
            });
            
            messageInput?.addEventListener('input', () => {
                clearTimeout(typingTimeout);
                sendTyping();
                typingTimeout = setTimeout(() => {
                    // Stop typing after 2 seconds of inactivity
                }, 2000);
                
                // Auto-resize
                messageInput.style.height = 'auto';
                messageInput.style.height = Math.min(messageInput.scrollHeight, 200) + 'px';
            });
            
            // Logout
            document.getElementById('logout-btn')?.addEventListener('click', logout);
            
            // User search
            let searchTimeout;
            document.getElementById('user-search')?.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                const query = e.target.value.trim();
                
                if (query.length < 2) {
                    document.getElementById('search-results').innerHTML = '';
                    return;
                }
                
                searchTimeout = setTimeout(async () => {
                    const users = await searchUsers(query);
                    const container = document.getElementById('search-results');
                    
                    if (users.length === 0) {
                        container.innerHTML = '<div style="padding:8px 12px;color:var(--text-muted);">Ничего не найдено</div>';
                        return;
                    }
                    
                    container.innerHTML = users.map(user => \`
                        <div class="search-result-item" data-user-id="\${user.id}">
                            <div class="user-avatar" style="width:32px;height:32px;font-size:14px;">
                                \${user.avatar_url ? '<img src="' + user.avatar_url + '">' : user.username[0].toUpperCase()}
                            </div>
                            <span>\${user.username}</span>
                        </div>
                    \`).join('');
                    
                    container.querySelectorAll('.search-result-item').forEach(item => {
                        item.addEventListener('click', () => {
                            selectDM(item.dataset.userId);
                            e.target.value = '';
                            container.innerHTML = '';
                        });
                    });
                }, 300);
            });
        }

        // ============================================
        // УТИЛИТЫ
        // ============================================
        function formatTime(dateStr) {
            const date = new Date(dateStr);
            const now = new Date();
            const diff = now - date;
            
            if (diff < 86400000 && date.getDate() === now.getDate()) {
                return 'Сегодня в ' + date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
            } else if (diff < 172800000 && date.getDate() === now.getDate() - 1) {
                return 'Вчера в ' + date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
            } else {
                return date.toLocaleDateString('ru-RU') + ' ' + date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function scrollToBottom() {
            const container = document.getElementById('messages-container');
            if (container) {
                setTimeout(() => {
                    container.scrollTop = container.scrollHeight;
                }, 10);
            }
        }

        // ============================================
        // ИНИЦИАЛИЗАЦИЯ
        // ============================================
        async function init() {
            const isAuth = await checkAuth();
            
            if (isAuth) {
                connectWebSocket();
                await loadServers();
                await loadDMList();
            }
            
            render();
        }

        init();
    </script>
</body>
</html>`;

// Serve frontend
app.get('/', (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(HTML_PAGE);
});

// ============================================
// ЗАПУСК
// ============================================

async function start() {
    try {
        await initializeDatabase();
        server.listen(PORT, '0.0.0.0', () => {
            console.log(`
╔═══════════════════════════════════════════════════════╗
║       Discord Clone - Full Stack Application          ║
╠═══════════════════════════════════════════════════════╣
║  🌐 App:          http://localhost:\${PORT}               ║
║  🔌 WebSocket:    ws://localhost:\${PORT}                 ║
║  📊 Health:       http://localhost:\${PORT}/health        ║
║  🗄️  Database:    PostgreSQL (Neon)                    ║
╚═══════════════════════════════════════════════════════╝
            `);
        });
    } catch (e) {
        console.error('❌ Ошибка запуска:', e);
        process.exit(1);
    }
}

process.on('SIGTERM', async () => {
    console.log('\\n🛑 Завершение работы...');
    wss.clients.forEach(c => c.close(1001));
    server.close(async () => {
        await pool.end();
        process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000);
});

process.on('SIGINT', () => process.emit('SIGTERM'));

start();
