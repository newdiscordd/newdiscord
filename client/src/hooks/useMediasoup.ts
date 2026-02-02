import { useState, useEffect, useRef } from 'react';
import * as mediasoupClient from 'mediasoup-client';
import { Socket } from 'socket.io-client';

export const useMediasoup = (socket: Socket | null, channelId: string | null) => {
  const [device, setDevice] = useState<mediasoupClient.types.Device | null>(null);
  const [producers, setProducers] = useState<any[]>([]); // simplified
  const [peers, setPeers] = useState<any[]>([]); // simplified

  const sendTransportRef = useRef<mediasoupClient.types.Transport | null>(null);
  const recvTransportRef = useRef<mediasoupClient.types.Transport | null>(null);

  useEffect(() => {
    if (!socket || !channelId) return;

    const loadDevice = async (routerRtpCapabilities: any) => {
      const newDevice = new mediasoupClient.Device();
      await newDevice.load({ routerRtpCapabilities });
      setDevice(newDevice);
      return newDevice;
    };

    const initVoice = async () => {
      // 1. Join Room
      socket.emit('join-voice', { channelId }, async ({ rtpCapabilities }: any) => {
        const device = await loadDevice(rtpCapabilities);
        
        // 2. Create Send Transport
        socket.emit('create-transport', { channelId }, async (params: any) => {
            const transport = device.createSendTransport(params);
            sendTransportRef.current = transport;

            transport.on('connect', ({ dtlsParameters }, callback, errback) => {
                socket.emit('connect-transport', { channelId, transportId: transport.id, dtlsParameters }, callback);
            });

            transport.on('produce', ({ kind, rtpParameters }, callback, errback) => {
                socket.emit('produce', { channelId, transportId: transport.id, kind, rtpParameters }, ({ id }: any) => {
                    callback({ id });
                });
            });

            // Start Audio
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                const track = stream.getAudioTracks()[0];
                await transport.produce({ track });
            } catch(e) { console.error("Mic error", e); }
        });

        // 3. Create Recv Transport
        socket.emit('create-transport', { channelId }, async (params: any) => {
            const transport = device.createRecvTransport(params);
            recvTransportRef.current = transport;
            
            transport.on('connect', ({ dtlsParameters }, callback, errback) => {
                socket.emit('connect-transport', { channelId, transportId: transport.id, dtlsParameters }, callback);
            });
        });
      });
    };

    initVoice();

    // Listen for new producers
    socket.on('new-producer', async ({ producerId, producerSocketId }) => {
        if(!recvTransportRef.current || !device) return;
        
        socket.emit('consume', { 
            channelId, 
            transportId: recvTransportRef.current.id, 
            producerId, 
            rtpCapabilities: device.rtpCapabilities 
        }, async (params: any) => {
            if(!params) return;
            const consumer = await recvTransportRef.current?.consume({
                id: params.id,
                producerId: params.producerId,
                kind: params.kind,
                rtpParameters: params.rtpParameters
            });
            
            // Resume (if server created it paused)
            // socket.emit('resume-consumer'...)
            
            if(consumer) {
                const { track } = consumer;
                const stream = new MediaStream([track]);
                // Create audio element
                const audio = document.createElement('audio');
                audio.srcObject = stream;
                audio.play();
                // Add to state for UI
                setPeers(prev => [...prev, { socketId: producerSocketId, audio }]);
            }
        });
    });

    return () => {
        // Cleanup
        socket.off('new-producer');
        sendTransportRef.current?.close();
        recvTransportRef.current?.close();
    }

  }, [socket, channelId]);

  return { peers };
};
