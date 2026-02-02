# --- Build Client ---
FROM node:18-alpine AS client-builder
WORKDIR /app/client
COPY client/package*.json ./
RUN npm ci
COPY client/ ./
# Use specific env for build time if needed
ENV NEXT_PUBLIC_API_URL=/ 
RUN npm run build

# --- Build Server ---
FROM node:18-alpine AS server-builder
WORKDIR /app/server
COPY server/package*.json ./
RUN npm ci
COPY server/ ./
RUN npx prisma generate
RUN npm run build

# --- Final Image ---
FROM node:18-alpine
WORKDIR /app

# System dependencies for Mediasoup (Python/Make/G++) might be needed depending on prebuilds
# Usually modern mediasoup has prebuilt binaries, but if compilation triggers:
RUN apk add --no-cache python3 make g++

COPY --from=server-builder /app/server/package*.json ./
RUN npm ci --production

COPY --from=server-builder /app/server/dist ./dist
COPY --from=server-builder /app/server/prisma ./prisma
COPY --from=client-builder /app/client/out ./client/out

# Install runtime prisma
RUN npx prisma generate

EXPOSE 3001
# Start Command: Migrate DB -> Start Server
CMD npx prisma db push && node dist/index.js
