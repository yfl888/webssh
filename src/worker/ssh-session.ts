import { SSHConnectionConfig } from '../types';
import {
  SSH_MSG_KEXINIT,
  SSH_MSG_NEWKEYS,
  SSH_MSG_KEX_ECDH_REPLY,
  SSH_MSG_USERAUTH_SUCCESS,
  SSH_MSG_USERAUTH_FAILURE,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_DISCONNECT,
  SSH_MSG_IGNORE,
  SSH_MSG_DEBUG
} from '../types';
import { SSHTransport } from '../ssh/transport';
import { SSHPacketParser, SSHPacketBuilder } from '../ssh/packet';
import { KEXInitBuilder } from '../ssh/kex';
import { ECDHKeyExchange } from '../ssh/kex-ecdh';
import { KeyDerivation } from '../ssh/keys';
import { SSHAESGCMCipher } from '../ssh/crypto';
import { SSHAuth } from '../ssh/auth';
import { SSHChannel } from '../ssh/channel';

export class SSHSession {
  private ws: WebSocket;
  private socket: any;
  private config: SSHConnectionConfig;

  private transport: SSHTransport;
  private packetParser: SSHPacketParser;
  private channel: SSHChannel;
  private encryptCipher: SSHAESGCMCipher | null = null;
  private decryptCipher: SSHAESGCMCipher | null = null;

  private seqNumSend: number = 0;
  private seqNumRecv: number = 0;
  private sessionID: Uint8Array | null = null;

  private kexInitLocal: Uint8Array | null = null;
  private kexInitRemote: Uint8Array | null = null;

  private ecdhKeyPair!: CryptoKeyPair;
  private ecdhPublicKeySSH!: Uint8Array;

  private state: 'connecting' | 'version' | 'kex' | 'auth' | 'shell' | 'ready'
    = 'connecting';

  constructor(ws: WebSocket, socket: any, config: SSHConnectionConfig) {
    this.ws = ws;
    this.socket = socket;
    this.config = config;
    this.transport = new SSHTransport();
    this.packetParser = new SSHPacketParser();
    this.channel = new SSHChannel();
  }

  async startHandshake(): Promise<void> {
    this.state = 'version';
    
    // 获取 writer 并发送版本字符串
    const writer = this.socket.writable.getWriter();
    const versionStr = 'SSH-2.0-CloudSSH_1.0\r\n';
    await writer.write(new TextEncoder().encode(versionStr));
    writer.releaseLock();
    
    this.startReading();
  }

  private async startReading(): Promise<void> {
    const reader = this.socket.readable.getReader();
    const decoder = new TextDecoder();

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        console.log('Received data, state:', this.state, 'length:', value.length);

        if (this.state === 'version') {
          const versionStr = decoder.decode(value);
          console.log('Version exchange:', versionStr.substring(0, 50));
          if (this.transport.handleVersionExchange(versionStr)) {
            console.log('Version exchange complete, starting KEX');
            this.state = 'kex';
            await this.startKEX();
          }
        } else {
          this.packetParser.feed(value);
          await this.processPackets();
        }
      }
    } catch (error) {
      console.error('SSH reading error:', error);
      this.ws.send(JSON.stringify({
        type: 'error',
        message: 'SSH 连接断开'
      }));
    }
  }

  private async startKEX(): Promise<void> {
    this.kexInitLocal = KEXInitBuilder.build();
    const packet = SSHPacketBuilder.build(
      this.kexInitLocal, 8, null, this.seqNumSend++
    );
    await this.writeSocket(packet);

    this.ecdhKeyPair = await ECDHKeyExchange.generateKeyPair();
    this.ecdhPublicKeySSH = await ECDHKeyExchange.exportPublicKeyForSSH(
      this.ecdhKeyPair
    );

    const ecdhInit = ECDHKeyExchange.buildInit(this.ecdhPublicKeySSH);
    const ecdhPacket = SSHPacketBuilder.build(
      ecdhInit, 8, null, this.seqNumSend++
    );
    await this.writeSocket(ecdhPacket);
  }

  private async writeSocket(data: Uint8Array): Promise<void> {
    const writer = this.socket.writable.getWriter();
    await writer.write(data);
    writer.releaseLock();
  }

  private async processPackets(): Promise<void> {
    const blockSize = this.decryptCipher ? 16 : 8;
    console.log('Processing packets, blockSize:', blockSize);

    while (true) {
      const packet = this.packetParser.nextPacket(
        blockSize,
        this.decryptCipher
          ? (data, seq) => this.decryptCipher!.decrypt(data, seq) as any
          : (data) => data,
        !!this.decryptCipher  // hasAuthTag: true when encryption is enabled
      );

      if (!packet) break;
      console.log('Got packet, payload length:', packet.payload.length, 'first byte:', packet.payload[0]);

      await this.handlePacket(packet);
    }
  }

  private async handlePacket(packet: any): Promise<void> {
    const msgType = packet.payload[0];
    console.log('Packet:', msgType, 'State:', this.state);

    switch (this.state) {
      case 'kex':
        await this.handleKEXPacket(msgType, packet.payload);
        break;

      case 'auth':
        await this.handleAuthPacket(msgType, packet.payload);
        break;

      case 'shell':
      case 'ready':
        await this.handleSessionPacket(msgType, packet.payload);
        break;
    }
  }

  private async handleKEXPacket(msgType: number, payload: Uint8Array): Promise<void> {
    switch (msgType) {
      case SSH_MSG_KEXINIT:
        this.kexInitRemote = payload;
        break;

      case SSH_MSG_KEX_ECDH_REPLY:
        await this.handleECDHReply(payload);
        break;

      case SSH_MSG_NEWKEYS:
        await this.enableEncryption();

        const newKeys = new Uint8Array([SSH_MSG_NEWKEYS]);
        const packet = SSHPacketBuilder.build(
          newKeys, 16,
          (data, seq) => this.encryptCipher!.encrypt(data, seq) as any,
          this.seqNumSend++
        );
        await this.writeSocket(packet);

        this.state = 'auth';
        await this.authenticate();
        break;
    }
  }

  private async handleECDHReply(payload: Uint8Array): Promise<void> {
    const { hostKey, serverPublicKey, signature } =
      ECDHKeyExchange.parseReply(payload);

    const sharedSecret = await ECDHKeyExchange.computeSharedSecret(
      this.ecdhKeyPair.privateKey,
      serverPublicKey
    );

    const H = await ECDHKeyExchange.computeExchangeHash(
      this.transport.getLocalVersion(),
      this.transport.getRemoteVersion(),
      this.kexInitLocal!,
      this.kexInitRemote!,
      hostKey,
      this.ecdhPublicKeySSH,
      serverPublicKey,
      sharedSecret
    );

    if (!this.sessionID) {
      this.sessionID = H;
    }

    const keys = await KeyDerivation.deriveKeys(sharedSecret, H, this.sessionID!);

    this.encryptCipher = new SSHAESGCMCipher(
      keys.encKeyClientToServer,
      keys.ivClientToServer
    );
    await this.encryptCipher.init();

    this.decryptCipher = new SSHAESGCMCipher(
      keys.encKeyServerToClient,
      keys.ivServerToClient
    );
    await this.decryptCipher.init();
  }

  private async enableEncryption(): Promise<void> {
    // Encryption is now active via this.decryptCipher
  }

  private async authenticate(): Promise<void> {
    const authRequest = SSHAuth.buildPasswordAuthRequest(
      this.config.username,
      this.config.password
    );

    const packet = SSHPacketBuilder.build(
      authRequest, 16,
      (data, seq) => this.encryptCipher!.encrypt(data, seq) as any,
      this.seqNumSend++
    );
    await this.writeSocket(packet);
  }

  private async handleAuthPacket(msgType: number, payload: Uint8Array): Promise<void> {
    switch (msgType) {
      case SSH_MSG_USERAUTH_SUCCESS:
        this.ws.send(JSON.stringify({
          type: 'status',
          message: '认证成功'
        }));
        this.state = 'shell';
        await this.openShell();
        break;

      case SSH_MSG_USERAUTH_FAILURE:
        this.ws.send(JSON.stringify({
          type: 'error',
          message: '认证失败：用户名或密码错误'
        }));
        this.close();
        break;
    }
  }

  private async openShell(): Promise<void> {
    console.log('Opening shell session...');
    const openMsg = this.channel.buildOpenSession();
    await this.sendEncrypted(openMsg);
  }

  private async handleSessionPacket(msgType: number, payload: Uint8Array): Promise<void> {
    console.log('Session packet:', msgType, 'state:', this.state);
    switch (msgType) {
      case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        console.log('Channel opened, sending PTY request');
        this.channel.handleOpenConfirmation(payload);
        const ptyReq = this.channel.buildPTYRequest(120, 40);
        await this.sendEncrypted(ptyReq);
        break;

      case SSH_MSG_CHANNEL_SUCCESS:
        console.log('Channel success, state:', this.state);
        if (this.state === 'shell') {
          console.log('Sending shell request');
          const shellReq = this.channel.buildShellRequest();
          await this.sendEncrypted(shellReq);
          this.state = 'ready';
        }
        break;

      case SSH_MSG_CHANNEL_DATA:
        const outputData = this.channel.handleChannelData(payload);
        this.ws.send(outputData.buffer);
        break;

      case SSH_MSG_CHANNEL_WINDOW_ADJUST:
        break;

      case SSH_MSG_CHANNEL_EOF:
      case SSH_MSG_CHANNEL_CLOSE:
        this.ws.send(JSON.stringify({
          type: 'status',
          message: '会话已结束'
        }));
        this.close();
        break;

      case SSH_MSG_DISCONNECT:
        this.ws.send(JSON.stringify({
          type: 'status',
          message: '服务器断开连接'
        }));
        this.close();
        break;

      case SSH_MSG_IGNORE:
      case SSH_MSG_DEBUG:
        break;
    }
  }

  handleWebSocketMessage(data: string | ArrayBuffer): void {
    if (this.state !== 'ready') return;

    if (typeof data === 'string') {
      try {
        const msg = JSON.parse(data);
        if (msg.type === 'resize') {
          this.handleResize(msg.cols, msg.rows);
          return;
        }
      } catch {
        const encoded = new TextEncoder().encode(data);
        const channelData = this.channel.buildChannelData(encoded);
        this.sendEncrypted(channelData);
      }
    } else {
      const channelData = this.channel.buildChannelData(
        new Uint8Array(data)
      );
      this.sendEncrypted(channelData);
    }
  }

  private async handleResize(cols: number, rows: number): Promise<void> {
    const resizeMsg = this.channel.buildWindowChange(cols, rows);
    await this.sendEncrypted(resizeMsg);
  }

  private async sendEncrypted(payload: Uint8Array): Promise<void> {
    if (!this.encryptCipher) {
      throw new Error('Encryption not initialized');
    }

    const encrypted = SSHPacketBuilder.build(
      payload, 16,
      (data, seq) => this.encryptCipher!.encrypt(data, seq) as any,
      this.seqNumSend++
    );
    await this.writeSocket(encrypted);
  }

  close(): void {
    try { this.socket.close(); } catch {}
    try { this.ws.close(); } catch {}
  }
}
