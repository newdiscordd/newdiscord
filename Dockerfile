FROM node:20-alpine AS builder

RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# Копируем файлы зависимостей
COPY package*.json ./

# Устанавливаем зависимости (игнорируя скрипты для стабильности)
# Мы явно устанавливаем prisma 6-й версии
RUN npm install prisma@^6.0.0 @prisma/client@^6.0.0
RUN npm install --ignore-scripts

COPY prisma ./prisma/

# Генерируем клиент Prisma (теперь на 6-й версии это сработает)
RUN npx prisma generate

COPY . .

# Сборка
RUN npm run build

# Этап запуска
FROM node:20-alpine AS runner
WORKDIR /app
RUN apk add --no-cache openssl
ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/prisma ./prisma
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules

USER nextjs

CMD ["npm", "start"]
