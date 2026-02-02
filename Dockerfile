# --- Этап 1: Сборка ---
FROM node:20-alpine AS builder
RUN apk add --no-cache openssl libc6-compat
WORKDIR /app

# Копируем всё содержимое
COPY . .

# Устанавливаем зависимости везде
RUN npm install --ignore-scripts
RUN cd client && npm install --ignore-scripts

# Генерируем Prisma
RUN npx prisma generate

# Собираем Next.js
WORKDIR /app/client
RUN npx next build

# --- Этап 2: Запуск ---
FROM node:20-alpine AS runner
WORKDIR /app
RUN apk add --no-cache openssl
ENV NODE_ENV=production

# Создаем пользователя
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Копируем только те файлы, которые ТОЧНО есть и нужны
# Мы убираем копирование public, если оно вызывает ошибку, 
# либо копируем его только если оно существует (через корень)
COPY --from=builder /app/client/.next ./client/.next
COPY --from=builder /app/client/node_modules ./client/node_modules
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/prisma ./prisma

# Если папка public всё же нужна и она есть в корне или в client:
# COPY --from=builder /app/client/package.json ./client/package.json

USER nextjs
EXPOSE 3000

# Запуск Next.js
# Используем npx чтобы быть уверенными в путях
CMD ["npx", "next", "start", "client"]
