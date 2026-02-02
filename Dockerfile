# --- Этап 1: Сборка ---
FROM node:20-alpine AS builder

RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# 1. Копируем всё
COPY . .

# 2. Устанавливаем зависимости в корне
RUN npm install --ignore-scripts

# 3. Переходим в папку клиента и устанавливаем зависимости там (если есть свой package.json)
# Если клиент и сервер делят один package.json в корне, Next.js всё равно нужно запускать из папки client
WORKDIR /app/client

# Генерируем Prisma (база обычно нужна серверу, но типы могут быть нужны и клиенту)
RUN cd /app && npx prisma generate

# 4. Запускаем сборку Next.js именно из папки client
# Мы указываем путь к конфигу, если он в папке client
RUN npx next build

# --- Этап 2: Запуск ---
FROM node:20-alpine AS runner
WORKDIR /app
RUN apk add --no-cache openssl
ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Копируем результаты сборки из папки client
COPY --from=builder /app/client/public ./public
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/prisma ./prisma
COPY --from=builder --chown=nextjs:nodejs /app/client/.next ./.next
COPY --from=builder /app/node_modules ./node_modules

USER nextjs

EXPOSE 3000

# Если вы запускаете Next.js сервер:
CMD ["npm", "start", "--prefix", "client"]
