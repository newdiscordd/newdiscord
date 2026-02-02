# --- Stage 1: Build Client ---
FROM node:18-alpine AS client-builder
WORKDIR /app/client
COPY client/package*.json ./
RUN npm install && npm cache clean --force
COPY client/ ./
RUN npm run build

# --- Stage 2: Build Server ---
FROM node:18-alpine AS server-builder
RUN apk add --no-cache python3 make g++ py3-pip
WORKDIR /app/server
COPY server/package*.json ./
RUN npm install && npm cache clean --force
COPY server/ ./
RUN npx prisma generate
RUN npm run build

# --- Stage 3: Final Production Image ---
FROM node:18-alpine
WORKDIR /app
# Необходимые библиотеки для запуска воркера Mediasoup
RUN apk add --no-cache libstdc++ libgcc python3

COPY --from=server-builder /app/server/node_modules ./node_modules
COPY --from=server-builder /app/server/dist ./dist
COPY --from=server-builder /app/server/prisma ./prisma
COPY --from=server-builder /app/server/package*.json ./
COPY --from=client-builder /app/client/out ./client/out

RUN npx prisma generate

EXPOSE 3001

# Используем npx prisma db push для автоматического обновления схемы NeonDB
CMD npx prisma db push && node dist/index.js
