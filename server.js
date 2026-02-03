// server.js - ЕДИНСТВЕННЫЙ ФАЙЛ БЭКЕНДА
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// Проверка подключения к базе данных
prisma.$connect()
    .then(() => console.log('✅ Подключение к базе данных установлено'))
    .catch(err => {
        console.error('❌ Ошибка подключения к базе данных:', err);
        process.exit(1);
    });

// Логирование доступных моделей Prisma
console.log('📊 Доступные модели Prisma:', Object.keys(prisma).filter(key => !key.startsWith('_') && !key.startsWith('$')));

// Раздаем статические файлы (наши html)
app.use(express.static('public'));
app.use(express.json());

// --- API: АУТЕНТИФИКАЦИЯ ---

app.post('/api/auth', async (req, res) => {
    const { email, password, type } = req.body;
    
    try {
        if (type === 'register') {
            const hashed = await bcrypt.hash(password, 10);
            const username = email.split('@')[0];
            const user = await prisma.user.create({
                data: { 
                    email, 
                    password: hashed, 
                    username,
                    avatar: `https://api.dicebear.com/7.x/initials/svg?seed=${username}`
                }
            });
            // Создаем сервер для новичка сразу
            await prisma.server.create({
                data: {
                    name: "My First Server",
                    ownerId: user.id,
                    channels: { create: [{ name: "general", type: "TEXT" }, { name: "voice-room", type: "VOICE" }] },
                    members: { create: { userId: user.id } }
                }
            });
            const token = jwt.sign({ userId: user.id }, JWT_SECRET);
            return res.json({ token, user });
        } else {
            const user = await prisma.user.findUnique({ where: { email } });
            if (!user || !await bcrypt.compare(password, user.password)) {
                return res.status(401).json({ error: "Неверный логин или пароль" });
            }
            const token = jwt.sign({ userId: user.id }, JWT_SECRET);
            return res.json({ token, user });
        }
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Ошибка сервера" });
    }
});

// Middleware проверки токена
const auth = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch { res.status(401).json({ error: "Unauthorized" }); }
};

const getPagination = (req, { defaultPageSize = 20, maxPageSize = 100 } = {}) => {
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const pageSize = Math.min(
        Math.max(parseInt(req.query.pageSize, 10) || defaultPageSize, 1),
        maxPageSize
    );
    const skip = (page - 1) * pageSize;
    return { page, pageSize, skip };
};

// --- API: ДАННЫЕ ---

app.get('/api/servers', auth, async (req, res) => {
    const servers = await prisma.server.findMany({
        where: { members: { some: { userId: req.user.userId } } },
        select: {
            id: true,
            name: true,
            ownerId: true
        }
    });
    res.json(servers);
});

app.get('/api/channels/:serverId', auth, async (req, res) => {
    const { serverId } = req.params;
    const member = await prisma.member.findFirst({
        where: { serverId, userId: req.user.userId }
    });

    if (!member) {
        return res.status(403).json({ error: "Нет доступа к серверу" });
    }

    const channels = await prisma.channel.findMany({
        where: { serverId },
        orderBy: { name: 'asc' }
    });

    res.json(channels);
});

app.get('/api/members/:serverId', auth, async (req, res) => {
    const { serverId } = req.params;
    const member = await prisma.member.findFirst({
        where: { serverId, userId: req.user.userId }
    });

    if (!member) {
        return res.status(403).json({ error: "Нет доступа к серверу" });
    }

    const { page, pageSize, skip } = getPagination(req, { defaultPageSize: 25 });
    const [members, total] = await prisma.$transaction([
        prisma.member.findMany({
            where: { serverId },
            include: { user: true },
            orderBy: { user: { username: 'asc' } },
            skip,
            take: pageSize
        }),
        prisma.member.count({ where: { serverId } })
    ]);

    res.json({
        items: members,
        page,
        pageSize,
        total
    });
});

app.get('/api/friends/requests', auth, async (req, res) => {
    const { page, pageSize, skip } = getPagination(req, { defaultPageSize: 25 });
    const where = {
        OR: [
            { senderId: req.user.userId },
            { receiverId: req.user.userId }
        ]
    };
    const [requests, total] = await prisma.$transaction([
        prisma.friendRequest.findMany({
            where,
            include: {
                sender: true,
                receiver: true
            },
            orderBy: { createdAt: 'desc' },
            skip,
            take: pageSize
        }),
        prisma.friendRequest.count({ where })
    ]);

    res.json({
        items: requests,
        page,
        pageSize,
        total
    });
});

app.get('/api/messages/:channelId', auth, async (req, res) => {
    const messages = await prisma.message.findMany({
        where: { channelId: req.params.channelId },
        include: { user: true },
        orderBy: { createdAt: 'asc' },
        take: 50
    });
    res.json(messages);
});

// --- API: ПОИСК ПОЛЬЗОВАТЕЛЕЙ ---

app.get('/api/users/search', auth, async (req, res) => {
    const { query } = req.query;
    if (!query || query.length < 2) {
        return res.json([]);
    }
    
    try {
        const users = await prisma.user.findMany({
            where: {
                AND: [
                    { id: { not: req.user.userId } }, // Не показываем себя
                    {
                        OR: [
                            { username: { contains: query, mode: 'insensitive' } },
                            { email: { contains: query, mode: 'insensitive' } }
                        ]
                    }
                ]
            },
            select: {
                id: true,
                username: true,
                email: true,
                avatar: true
            },
            take: 10
        });
        res.json(users);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Ошибка поиска" });
    }
});

// --- API: ДРУЗЬЯ ---

app.post('/api/friends/request', auth, async (req, res) => {
    const { receiverId } = req.body;
    
    console.log('🔔 Получен запрос на добавление в друзья:', { senderId: req.user.userId, receiverId });
    
    try {
        // Проверяем, что это не запрос самому себе
        if (receiverId === req.user.userId) {
            console.log('❌ Попытка добавить себя в друзья');
            return res.status(400).json({ error: "Нельзя добавить себя в друзья" });
        }
        
        // Проверяем наличие модели friendRequest в Prisma
        if (!prisma.friendRequest) {
            console.error('❌ Модель friendRequest не найдена в Prisma!');
            console.error('Доступные модели:', Object.keys(prisma).filter(key => !key.startsWith('_') && !key.startsWith('$')));
            return res.status(500).json({ error: "Модель friendRequest не инициализирована. Выполните: npx prisma generate && npx prisma db push" });
        }
        
        console.log('✅ Модель friendRequest доступна');
        
        // Проверяем, существует ли получатель
        const receiver = await prisma.user.findUnique({
            where: { id: receiverId }
        });
        
        if (!receiver) {
            console.log('❌ Получатель не найден:', receiverId);
            return res.status(404).json({ error: "Пользователь не найден" });
        }
        
        console.log('✅ Получатель найден:', receiver.username);
        
        // Проверяем, не отправлена ли уже заявка
        const existing = await prisma.friendRequest.findFirst({
            where: {
                OR: [
                    { senderId: req.user.userId, receiverId, status: 'PENDING' },
                    { senderId: receiverId, receiverId: req.user.userId, status: 'PENDING' },
                    { senderId: req.user.userId, receiverId, status: 'ACCEPTED' },
                    { senderId: receiverId, receiverId: req.user.userId, status: 'ACCEPTED' }
                ]
            }
        });
        
        if (existing) {
            console.log('⚠️ Заявка уже существует:', existing.status);
            if (existing.status === 'PENDING') {
                return res.status(400).json({ error: "Заявка уже отправлена" });
            } else if (existing.status === 'ACCEPTED') {
                return res.status(400).json({ error: "Вы уже друзья" });
            }
        }
        
        console.log('✅ Создаю новую заявку...');
        
        const request = await prisma.friendRequest.create({
            data: {
                senderId: req.user.userId,
                receiverId,
                status: 'PENDING'
            },
            include: {
                sender: true,
                receiver: true
            }
        });
        
        console.log('✅ Заявка создана:', request.id);
        res.json(request);
    } catch (e) {
        console.error('❌ Ошибка создания заявки в друзья:', e);
        res.status(500).json({ error: "Ошибка создания заявки: " + e.message });
    }
});

app.post('/api/friends/respond', auth, async (req, res) => {
    const { requestId, accept } = req.body;
    
    try {
        const request = await prisma.friendRequest.findUnique({
            where: { id: requestId }
        });
        
        if (!request || request.receiverId !== req.user.userId) {
            return res.status(403).json({ error: "Нет доступа" });
        }
        
        const updated = await prisma.friendRequest.update({
            where: { id: requestId },
            data: { status: accept ? 'ACCEPTED' : 'REJECTED' },
            include: {
                sender: true,
                receiver: true
            }
        });
        
        res.json(updated);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Ошибка обработки заявки" });
    }
});

// --- API: ПРИГЛАШЕНИЯ НА СЕРВЕРЫ ---

app.post('/api/dm/messages', auth, async (req, res) => {
    const { receiverId, content } = req.body;
    
    try {
        // Проверяем, что пользователи друзья
        const friendship = await prisma.friendRequest.findFirst({
            where: {
                OR: [
                    { senderId: req.user.userId, receiverId, status: 'ACCEPTED' },
                    { senderId: receiverId, receiverId: req.user.userId, status: 'ACCEPTED' }
                ]
            }
        });
        
        if (!friendship) {
            return res.status(403).json({ error: "Вы не друзья" });
        }
        
        const message = await prisma.directMessage.create({
            data: {
                content,
                senderId: req.user.userId,
                receiverId
            }
        });
        
        res.json(message);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Ошибка отправки сообщения" });
    }
});

app.get('/api/dm/messages/:friendId', auth, async (req, res) => {
    const { friendId } = req.params;
    
    try {
        const messages = await prisma.directMessage.findMany({
            where: {
                OR: [
                    { senderId: req.user.userId, receiverId: friendId },
                    { senderId: friendId, receiverId: req.user.userId }
                ]
            },
            orderBy: { createdAt: 'asc' },
            take: 100
        });
        
        res.json(messages);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Ошибка загрузки сообщений" });
    }
});

// --- API: ПРИГЛАШЕНИЯ НА СЕРВЕРЫ ---

app.post('/api/servers/create', auth, async (req, res) => {
    const { name } = req.body;
    
    console.log('🏢 Получен запрос на создание сервера:', { userId: req.user.userId, name });
    
    if (!name || name.trim().length === 0) {
        console.log('❌ Название сервера пустое');
        return res.status(400).json({ error: "Название сервера не может быть пустым" });
    }
    
    try {
        console.log('✅ Создаю сервер...');
        
        const server = await prisma.server.create({
            data: {
                name: name.trim(),
                ownerId: req.user.userId,
                channels: { 
                    create: [
                        { name: "general", type: "TEXT" }, 
                        { name: "voice-room", type: "VOICE" }
                    ] 
                },
                members: { create: { userId: req.user.userId } }
            },
            include: {
                channels: true,
                members: { include: { user: true } }
            }
        });
        
        console.log('✅ Сервер создан:', server.id, server.name);
        res.json(server);
    } catch (e) {
        console.error('❌ Ошибка создания сервера:', e);
        res.status(500).json({ error: "Ошибка создания сервера: " + e.message });
    }
});

app.post('/api/invites/create', auth, async (req, res) => {
    const { serverId } = req.body;
    
    try {
        // Проверяем, что пользователь является членом сервера
        const member = await prisma.member.findFirst({
            where: { serverId, userId: req.user.userId }
        });
        
        if (!member) {
            return res.status(403).json({ error: "Вы не являетесь членом этого сервера" });
        }
        
        // Генерируем уникальный код
        const code = crypto.randomBytes(4).toString('hex').toUpperCase();
        
        const invite = await prisma.invite.create({
            data: {
                code,
                serverId,
                createdBy: req.user.userId,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 дней
            },
            include: {
                server: true
            }
        });
        
        res.json(invite);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Ошибка создания приглашения" });
    }
});

app.get('/api/invites/:code', auth, async (req, res) => {
    const { code } = req.params;
    
    try {
        const invite = await prisma.invite.findUnique({
            where: { code },
            include: {
                server: {
                    include: {
                        channels: true,
                        members: true
                    }
                }
            }
        });
        
        if (!invite) {
            return res.status(404).json({ error: "Приглашение не найдено" });
        }
        
        // Проверяем срок действия
        if (invite.expiresAt && new Date() > invite.expiresAt) {
            return res.status(400).json({ error: "Приглашение истекло" });
        }
        
        // Проверяем лимит использований
        if (invite.maxUses && invite.uses >= invite.maxUses) {
            return res.status(400).json({ error: "Приглашение исчерпано" });
        }
        
        res.json(invite);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Ошибка поиска приглашения" });
    }
});

app.post('/api/invites/join', auth, async (req, res) => {
    const { code } = req.body;
    
    try {
        const invite = await prisma.invite.findUnique({
            where: { code },
            include: { server: true }
        });
        
        if (!invite) {
            return res.status(404).json({ error: "Приглашение не найдено" });
        }
        
        // Проверяем срок действия
        if (invite.expiresAt && new Date() > invite.expiresAt) {
            return res.status(400).json({ error: "Приглашение истекло" });
        }
        
        // Проверяем лимит использований
        if (invite.maxUses && invite.uses >= invite.maxUses) {
            return res.status(400).json({ error: "Приглашение исчерпано" });
        }
        
        // Проверяем, не состоит ли уже в сервере
        const existingMember = await prisma.member.findFirst({
            where: {
                userId: req.user.userId,
                serverId: invite.serverId
            }
        });
        
        if (existingMember) {
            return res.status(400).json({ error: "Вы уже состоите в этом сервере" });
        }
        
        // Добавляем в сервер
        await prisma.member.create({
            data: {
                userId: req.user.userId,
                serverId: invite.serverId
            }
        });
        
        // Увеличиваем счетчик использований
        await prisma.invite.update({
            where: { id: invite.id },
            data: { uses: { increment: 1 } }
        });
        
        // Возвращаем обновленные данные
        const servers = await prisma.server.findMany({
            where: { members: { some: { userId: req.user.userId } } },
            include: { 
                channels: true,
                members: { include: { user: true } }
            }
        });
        
        res.json({ success: true, servers });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Ошибка присоединения к серверу" });
    }
});

// --- SOCKET.IO: ЧАТ И ГОЛОС ---

// Кто в какой комнате (для голоса)
const voiceRooms = {}; // { channelId: [{ socketId, userId, username, avatar }, ...] }

io.on('connection', (socket) => {
    console.log('User connected', socket.id);

    // Вход в текстовый канал (комнату сокетов)
    socket.on('join-text', (channelId) => {
        socket.join(channelId);
    });

    // Отправка сообщения
    socket.on('send-message', async ({ content, channelId, token }) => {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const msg = await prisma.message.create({
                data: { content, channelId, userId: decoded.userId },
                include: { user: true }
            });
            io.to(channelId).emit('new-message', msg);
        } catch (e) { console.error(e); }
    });

    // Отправка прямого сообщения
    socket.on('send-dm', async ({ content, receiverId, token }) => {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const msg = await prisma.directMessage.create({
                data: { content, senderId: decoded.userId, receiverId }
            });
            
            // Отправляем обоим пользователям
            const dmRoom = [decoded.userId, receiverId].sort().join('-');
            io.to(dmRoom).emit('new-dm', { ...msg, senderId: decoded.userId });
        } catch (e) { console.error(e); }
    });

    // Присоединение к DM комнате
    socket.on('join-dm', ({ userId, friendId }) => {
        const dmRoom = [userId, friendId].sort().join('-');
        socket.join(dmRoom);
    });

    // --- ГОЛОС (WebRTC Signaling) ---
    
    socket.on('join-voice', async ({ channelId, userId }) => {
        try {
            // Получаем информацию о пользователе
            const user = await prisma.user.findUnique({
                where: { id: userId },
                select: { id: true, username: true, avatar: true }
            });
            
            if (!user) return;
            
            if (!voiceRooms[channelId]) voiceRooms[channelId] = [];
            
            // Получаем список пользователей уже в комнате (без текущего)
            const usersInRoom = voiceRooms[channelId].map(u => ({
                socketId: u.socketId,
                userId: u.userId,
                username: u.username,
                avatar: u.avatar
            }));
            
            // Отправляем новому пользователю список тех, кто уже в комнате
            socket.emit('all-users', usersInRoom);
            
            // Добавляем нового пользователя в комнату
            voiceRooms[channelId].push({
                socketId: socket.id,
                userId: user.id,
                username: user.username,
                avatar: user.avatar
            });
            
            // Оповещаем всех в канале о новом пользователе
            io.emit('voice-users-updated', {
                channelId,
                users: voiceRooms[channelId].map(u => ({
                    userId: u.userId,
                    username: u.username,
                    avatar: u.avatar
                }))
            });
            
            console.log(`✅ ${user.username} присоединился к голосовому каналу ${channelId}`);
        } catch (e) {
            console.error('Error joining voice:', e);
        }
    });

    // Пересылка сигнала (Offer/Answer/Candidate) конкретному юзеру
    socket.on('sending-signal', payload => {
        io.to(payload.userToSignal).emit('user-joined', { 
            signal: payload.signal, 
            callerID: payload.callerID,
            userInfo: payload.userInfo
        });
    });

    socket.on('returning-signal', payload => {
        io.to(payload.callerID).emit('receiving-returned-signal', { 
            signal: payload.signal, 
            id: socket.id,
            userInfo: payload.userInfo
        });
    });

    // Выход из голосового канала
    socket.on('leave-voice', ({ channelId }) => {
        if (voiceRooms[channelId]) {
            const userIndex = voiceRooms[channelId].findIndex(u => u.socketId === socket.id);
            if (userIndex !== -1) {
                const user = voiceRooms[channelId][userIndex];
                voiceRooms[channelId] = voiceRooms[channelId].filter(u => u.socketId !== socket.id);
                
                // Говорим остальным убрать этого пользователя
                voiceRooms[channelId].forEach(remainingUser => {
                    io.to(remainingUser.socketId).emit('user-left', socket.id);
                });
                
                // Обновляем список активных пользователей
                io.emit('voice-users-updated', {
                    channelId,
                    users: voiceRooms[channelId].map(u => ({
                        userId: u.userId,
                        username: u.username,
                        avatar: u.avatar
                    }))
                });
                
                console.log(`❌ ${user.username} покинул голосовой канал ${channelId}`);
            }
        }
    });

    // Выход
    socket.on('disconnect', () => {
        // Удаляем из голосовых комнат
        for (const [channelId, users] of Object.entries(voiceRooms)) {
            const userIndex = users.findIndex(u => u.socketId === socket.id);
            if (userIndex !== -1) {
                const user = users[userIndex];
                voiceRooms[channelId] = users.filter(u => u.socketId !== socket.id);
                
                // Говорим остальным убрать этого пользователя
                users.forEach(remainingUser => {
                    if (remainingUser.socketId !== socket.id) {
                        io.to(remainingUser.socketId).emit('user-left', socket.id);
                    }
                });
                
                // Обновляем список активных пользователей
                io.emit('voice-users-updated', {
                    channelId,
                    users: voiceRooms[channelId].map(u => ({
                        userId: u.userId,
                        username: u.username,
                        avatar: u.avatar
                    }))
                });
                
                console.log(`❌ ${user.username} покинул голосовой канал ${channelId}`);
            }
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server ready on port ${PORT}`));
