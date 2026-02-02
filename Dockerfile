# Этап 1: Сборка
FROM node:20-alpine AS builder

RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# 1. Копируем файлы манифестов
COPY package*.json ./

# 2. Устанавливаем зависимости (все, включая dev)
RUN npm install --ignore-scripts

# 3. Копируем ВЕСЬ остальной код проекта
COPY . .

# --- ОТЛАДКА: Эта команда покажет в логах Render, что видит Docker ---
RUN ls -la

# 4. Генерируем клиент Prisma
RUN npx prisma generate

# 5. Запускаем сборку Next.js
# Добавляем флаг -- --no-lint чтобы билд не падал из-за мелких ошибок оформления
RUN npx next build

# Этап 2: Запуск
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

EXPOSE 3000

CMD ["npm", "start"]
