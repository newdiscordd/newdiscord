import dotenv from 'dotenv';
dotenv.config({ path: '../.env' }); // Look in root

export const CONFIG = {
  PORT: process.env.PORT || 3001,
  JWT_SECRET: process.env.JWT_SECRET || 'super-secret-dev-key',
  DATABASE_URL: process.env.DATABASE_URL,
  // Mediasoup Settings
  MEDIASOUP: {
    // В Production на Render нужен диапазон портов или Announcement IP
    // Для демо мы используем настройки по умолчанию для Docker/Linux
    worker: {
      rtcMinPort: 10000,
      rtcMaxPort: 10100,
      logLevel: 'warn' as const,
      logTags: ['info', 'ice', 'dtls', 'rtp', 'srtp', 'rtcp'],
    },
    router: {
      mediaCodecs: [
        { kind: 'audio', mimeType: 'audio/opus', clockRate: 48000, channels: 2 }
      ] as any[]
    },
    webRtcTransport: {
      listenIps: [
        {
          ip: '0.0.0.0',
          announcedIp: process.env.ANNOUNCED_IP || '127.0.0.1' // Важно для Render!
        }
      ],
      initialAvailableOutgoingBitrate: 1000000,
    }
  }
};
