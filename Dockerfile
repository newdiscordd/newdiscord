# Этап 1: Сборка (Builder)
FROM node:20-alpine AS builder

# Установка необходимых системных библиотек (важно для Prisma)
RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# Копируем файлы зависимостей
COPY package*.json ./
COPY prisma ./prisma/

# Чистая установка зависимостей
RUN npm ci

# Генерация Prisma Client
RUN npx prisma generate

# Копируем весь исходный код
COPY . .

# Запуск сборки
# Если у вас Next.js, это выполнит 'next build'.
# Если это чистый сервер на Node.js, убедитесь, что скрипт "build" в package.json выполняет "tsc"
RUN npm run build

# Этап 2: Запуск (Runner)
FROM node:20-alpine AS runner

WORKDIR /app

# Установка openssl для работы Prisma в продакшене
RUN apk add --no-cache openssl

ENV NODE_ENV=production

# Создаем пользователя для безопасности (Render рекомендует не использовать root)
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Копируем только необходимые файлы из этапа сборки
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/prisma ./prisma

# ВАЖНО: Раскомментируйте нужную строку в зависимости от типа вашего проекта

# ВАРИАНТ А: Если это Next.js приложение (стандарт для Discord клонов)
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder /app/public ./public
USER nextjs
CMD ["npm", "start"]

# ВАРИАНТ Б: Если это обычный Node.js сервер (Express/Socket.io) и папка сборки называется 'dist'
# COPY --from=builder --chown=nextjs:nodejs /app/dist ./dist
# USER nextjs
# CMD ["node", "dist/index.js"]
