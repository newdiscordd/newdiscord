# --- Stage 1: Build Client ---
FROM node:18-bullseye-slim AS client-builder
WORKDIR /app/client
COPY client/package*.json ./
RUN npm install
COPY client/ ./
RUN npm run build

# --- Stage 2: Build Server ---
FROM node:18-bullseye-slim AS server-builder
RUN apt-get update && apt-get install -y python3 python3-pip build-essential && rm -rf /var/lib/apt/lists/*

WORKDIR /app/server
COPY server/package*.json ./
ENV CXXFLAGS="-Wno-maybe-uninitialized -Wno-uninitialized"
RUN npm install

# Копируем исходники сервера
COPY server/ ./

# ИСПРАВЛЕНИЕ: Копируем папку prisma из корня ПРОЕКТА в корень сервера внутри контейнера
COPY prisma ./prisma

# Теперь prisma generate точно найдет схему по пути ./prisma/schema.prisma
RUN npx prisma generate

RUN npm run build

# --- Stage 3: Final Production Image ---
FROM node:18-bullseye-slim
WORKDIR /app
RUN apt-get update && apt-get install -y python3 && rm -rf /var/lib/apt/lists/*

# Копируем всё необходимое для работы
COPY --from=server-builder /app/server/node_modules ./node_modules
COPY --from=server-builder /app/server/dist ./dist
COPY --from=server-builder /app/server/prisma ./prisma
COPY --from=server-builder /app/server/package*.json ./
COPY --from=client-builder /app/client/out ./client/out

# Генерируем клиент в финальном образе
RUN npx prisma generate

EXPOSE 3001

# Запуск: синхронизация БД и старт
CMD npx prisma db push && node dist/index.js
