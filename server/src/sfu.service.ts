import * as mediasoup from 'mediasoup';
import { CONFIG } from './config';

// Типы для хранения состояния
interface RoomState {
  router: mediasoup.types.Router;
  peers: Map<string, PeerState>; // socketId -> Peer
}

interface PeerState {
  socketId: string;
  transports: Map<string, mediasoup.types.WebRtcTransport>;
  producers: Map<string, mediasoup.types.Producer>;
  consumers: Map<string, mediasoup.types.Consumer>;
}

class SfuService {
  private worker: mediasoup.types.Worker | null = null;
  private rooms: Map<string, RoomState> = new Map(); // channelId -> Room

  async init() {
    this.worker = await mediasoup.createWorker(CONFIG.MEDIASOUP.worker);
    
    this.worker.on('died', () => {
      console.error('Mediasoup worker died, exiting...');
      process.exit(1);
    });
    
    console.log('SFU Service Initialized');
  }

  async getOrCreateRouter(channelId: string) {
    if (this.rooms.has(channelId)) return this.rooms.get(channelId)!.router;

    if (!this.worker) throw new Error("Worker not init");
    
    const router = await this.worker.createRouter({ mediaCodecs: CONFIG.MEDIASOUP.router.mediaCodecs });
    this.rooms.set(channelId, { router, peers: new Map() });
    return router;
  }

  getRoom(channelId: string) {
    return this.rooms.get(channelId);
  }

  addPeer(channelId: string, socketId: string) {
    const room = this.rooms.get(channelId);
    if (!room) return;
    room.peers.set(socketId, {
      socketId,
      transports: new Map(),
      producers: new Map(),
      consumers: new Map()
    });
  }

  removePeer(socketId: string) {
    // Находим комнату где этот пир и удаляем
    this.rooms.forEach((room) => {
      if (room.peers.has(socketId)) {
        const peer = room.peers.get(socketId)!;
        peer.transports.forEach(t => t.close());
        room.peers.delete(socketId);
      }
    });
  }

  async createWebRtcTransport(channelId: string, socketId: string) {
    const router = await this.getOrCreateRouter(channelId);
    const transport = await router.createWebRtcTransport(CONFIG.MEDIASOUP.webRtcTransport);

    const room = this.rooms.get(channelId);
    if(room && room.peers.has(socketId)) {
       room.peers.get(socketId)!.transports.set(transport.id, transport);
    }

    return {
      id: transport.id,
      iceParameters: transport.iceParameters,
      iceCandidates: transport.iceCandidates,
      dtlsParameters: transport.dtlsParameters,
    };
  }

  async connectTransport(channelId: string, socketId: string, transportId: string, dtlsParameters: any) {
    const room = this.rooms.get(channelId);
    const peer = room?.peers.get(socketId);
    const transport = peer?.transports.get(transportId);
    
    if (transport) {
      await transport.connect({ dtlsParameters });
    }
  }

  async produce(channelId: string, socketId: string, transportId: string, kind: any, rtpParameters: any) {
    const room = this.rooms.get(channelId);
    const peer = room?.peers.get(socketId);
    const transport = peer?.transports.get(transportId);

    if (!transport) throw new Error("Transport not found");

    const producer = await transport.produce({ kind, rtpParameters });
    peer!.producers.set(producer.id, producer);

    return { id: producer.id };
  }

  async consume(channelId: string, socketId: string, transportId: string, producerId: string, rtpCapabilities: any) {
    const room = this.rooms.get(channelId);
    const router = room?.router;
    const peer = room?.peers.get(socketId);
    const transport = peer?.transports.get(transportId);

    if (!router || !router.canConsume({ producerId, rtpCapabilities })) {
      return null;
    }

    const consumer = await transport!.consume({
      producerId,
      rtpCapabilities,
      paused: true, // Start paused recommended
    });

    peer!.consumers.set(consumer.id, consumer);

    return {
      id: consumer.id,
      producerId,
      kind: consumer.kind,
      rtpParameters: consumer.rtpParameters,
    };
  }
}

export const sfuService = new SfuService();
