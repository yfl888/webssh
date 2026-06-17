import { SSHConnectionConfig } from '../types';
import {
  SSH_MSG_KEXINIT,
  SSH_MSG_NEWKEYS,
  SSH_MSG_KEX_ECDH_REPLY,
  SSH_MSG_SERVICE_REQUEST,
  SSH_MSG_SERVICE_ACCEPT,
  SSH_MSG_USERAUTH_SUCCESS,
  SSH_MSG_USERAUTH_FAILURE,
  SSH_MSG_GLOBAL_REQUEST,
  SSH_MSG_REQUEST_FAILURE,
  SSH_MSG_REQUEST_SUCCESS,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
  SSH_MSG_CHANNEL_SUCCESS,
  SSH_MSG_CHANNEL_FAILURE,
  SSH_MSG_CHANNEL_DATA,
  SSH_MSG_CHANNEL_WINDOW_ADJUST,
  SSH_MSG_CHANNEL_EOF,
  SSH_MSG_CHANNEL_CLOSE,
  SSH_MSG_DISCONNECT,
  SSH_MSG_IGNORE,
  SSH_MSG_DEBUG,
  SSH_MSG_UNIMPLEMENTED,
  SSH_MSG_CHANNEL_OPEN_FAILURE,
} from '../types';
import { SSHTransport } from '../ssh/transport';
import { SSHPacketParser, SSHPacketBuilder } from '../ssh/packet';
import { KEXInitBuilder, parseKEXInit, negotiate } from '../ssh/kex';
import { ECDHKeyExchange } from '../ssh/kex-ecdh';
import { KeyDerivation } from '../ssh/keys';
import { SSHAESGCMCipher } from '../ssh/crypto';
import { SSHAuth } from '../ssh/auth';
import { SSHChannel } from '../ssh/channel';

function findCRLF(data: Uint8Array): number {
  for (let i = 0; i < data.length - 1; i++) {
    if (data[i] === 0x0d && data[i + 1] === 0x0a) {
      return i;
    }
  }
  return -1;
}

export class SSHSession {
  private ws: WebSocket;
  private socket: any;
  private config: SSHConnectionConfig;

  private transport: SSHTransport;
  private packetParser: SSHPacketParser;
  private channel: SSHChannel;
  private encryptCipher: SSHAESGCMCipher | null = null;
  private decryptCipher: SSHAESGCMCipher | null = null;
  private derivedKeys: any = null;

  private seqNumSend: number = 0;
  private sessionID: Uint8Array | null = null;
  private sendMutex: Promise<void> = Promise.resolve();

  private kexInitLocal: Uint8Array | null = null;
  private kexInitRemote: Uint8Array | null = null;

  private ecdhKeyPair!: CryptoKeyPair;
  private ecdhRawPublicKey!: Uint8Array;

  private state: 'connecting' | 'version' | 'kex' | 'auth' | 'shell' | 'ready'
    = 'connecting';
  private hostKeyFingerprint: string = '';

  private versionRawBuffer: Uint8Array = new Uint8Array(0);
  private negotiatedCipherC2S: string = 'aes256-gcm@openssh.com';
  private negotiatedCipherS2C: string = 'aes256-gcm@openssh.com';

  private keepaliveInterval: ReturnType<typeof setInterval> | null = null;

  constructor(
    ws: WebSocket,
    socket: any,
    config: SSHConnectionConfig
  ) {
    this.ws = ws;
    this.socket = socket;
    this.config = config;

    this.transport = new SSHTransport();
    this.packetParser = new SSHPacketParser();
    this.channel = new SSHChannel();
  }

  async startHandshake(): Promise<void> {
    this.sendStatus('正在交换版本信息...');
    this.state = 'version';

    const writer = this.socket.writable.getWriter();
    await writer.write(new TextEncoder().encode('SSH-2.0-CloudSSH_1.0\r\n'));
    writer.releaseLock();

    this.startReading();
  }

  private async startReading(): Promise<void> {
    const reader = this.socket.readable.getReader();
    const decoder = new TextDecoder();

    let leftover: Uint8Array | null = null;

    try {
      while (true) {
        let value: Uint8Array;
        if (leftover) {
          value = leftover;
          leftover = null;
        } else {
          const result = await reader.read();
          if (result.done) {
            console.log('[SSH] Socket closed (EOF)');
            this.sendError('SSH 服务器断开连接 (Socket closed by remote)');
            this.close();
            break;
          }
          value = result.value;
        }

        if (this.state === 'version') {
          const merged = new Uint8Array(this.versionRawBuffer.length + value.length);
          merged.set(this.versionRawBuffer);
          merged.set(value, this.versionRawBuffer.length);
          this.versionRawBuffer = merged;

          let scanOffset = 0;
          let versionFound = false;
          let remaining: Uint8Array = new Uint8Array(0);

          while (scanOffset < this.versionRawBuffer.length) {
            let lfIndex = -1;
            for (let i = scanOffset; i < this.versionRawBuffer.length; i++) {
              if (this.versionRawBuffer[i] === 0x0a) {
                lfIndex = i;
                break;
              }
            }

            if (lfIndex === -1) {
              break;
            }

            const lineBytes = this.versionRawBuffer.slice(scanOffset, lfIndex + 1);
            scanOffset = lfIndex + 1;

            let lineStr = decoder.decode(lineBytes);
            if (lineStr.endsWith('\n')) lineStr = lineStr.slice(0, -1);
            if (lineStr.endsWith('\r')) lineStr = lineStr.slice(0, -1);

            if (lineStr.startsWith('SSH-')) {
              this.transport.handleVersionExchange(lineStr + '\r\n');
              remaining = this.versionRawBuffer.slice(scanOffset);
              versionFound = true;
              break;
            } else {
              console.log('[SSH] Pre-version banner: ' + lineStr);
            }
          }

          if (versionFound) {
            this.versionRawBuffer = new Uint8Array(0);
            console.log('[SSH] Version exchange complete, remote=' + this.transport.getRemoteVersion());
            this.sendStatus('版本交换完成，正在密钥协商...');
            this.state = 'kex';
            await this.startKEX();

            if (remaining.length > 0) {
              console.log('[SSH] Remaining data after version: ' + remaining.length + ' bytes');
              this.packetParser.feed(remaining);
              await this.processPackets();
            }
          } else {
            if (scanOffset > 0) {
              this.versionRawBuffer = this.versionRawBuffer.slice(scanOffset);
            }
          }
        } else {
          console.log('[SSH] Received ' + value.length + ' bytes, state=' + this.state);
          this.packetParser.feed(value);
          await this.processPackets();
        }
      }
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      console.error('[SSH] Read loop error:', errMsg, error instanceof Error ? error.stack : '');
      try {
        this.ws.send(JSON.stringify({ type: 'error', message: 'SSH 连接异常: ' + errMsg }));
      } catch {}
    }
  }

  private async startKEX(): Promise<void> {
    console.log('[KEX] Starting key exchange');
    this.kexInitLocal = KEXInitBuilder.build();

    const packet = await SSHPacketBuilder.build(
      this.kexInitLocal, 8, null, this.seqNumSend++
    );
    await this.writeSocket(packet);
    console.log('[KEX] KEXINIT sent');

    this.ecdhKeyPair = await ECDHKeyExchange.generateKeyPair();
    this.ecdhRawPublicKey = await ECDHKeyExchange.exportRawPublicKey(this.ecdhKeyPair);

    const ecdhInit = ECDHKeyExchange.buildInit(this.ecdhRawPublicKey);
    const ecdhPacket = await SSHPacketBuilder.build(
      ecdhInit, 8, null, this.seqNumSend++
    );
    await this.writeSocket(ecdhPacket);
    console.log('[KEX] ECDH_INIT sent, waiting for server reply');
  }

  private async writeSocket(data: Uint8Array): Promise<void> {
    const writer = this.socket.writable.getWriter();
    await writer.write(data);
    writer.releaseLock();
  }

  private async processPackets(): Promise<void> {
    const blockSize = this.decryptCipher ? 16 : 8;
    const hasDecrypt = !!this.decryptCipher;
    this.sendDebug(`processPackets: blockSize=${blockSize}, hasDecrypt=${hasDecrypt}, bufferLen=${this.packetParser.getBufferLength()}`);

    while (true) {
      try {
        const packet = await this.packetParser.nextPacket(
          blockSize,
          this.decryptCipher
            ? (data, seq, aad) => this.decryptCipher!.decrypt(data, seq, aad)
            : (data) => data,
          !!this.decryptCipher
        );

        if (!packet) {
          this.sendDebug(`No more packets, buffer remaining: ${this.packetParser.getBufferLength()}`);
          break;
        }

        this.sendDebug(`Received msgType=${packet.payload[0]}, state=${this.state}, payloadLen=${packet.payload.length}`);
        await this.handlePacket(packet);
      } catch (e) {
        const errMsg = e instanceof Error ? e.message : String(e);
        this.sendDebug(`processPackets ERROR: ${errMsg}`);
        this.sendError('数据包处理异常: ' + errMsg);
        this.close();
        return;
      }
    }
  }

  private async handlePacket(packet: any): Promise<void> {
    const msgType = packet.payload[0];

    // Transport-level messages handled regardless of state
    if (msgType === SSH_MSG_DISCONNECT) {
      this.sendStatus('服务器断开连接');
      this.close();
      return;
    }
    if (msgType === SSH_MSG_IGNORE || msgType === SSH_MSG_DEBUG || msgType === SSH_MSG_UNIMPLEMENTED) {
      return;
    }
    if (msgType === SSH_MSG_GLOBAL_REQUEST) {
      await this.handleGlobalRequest(packet.payload);
      return;
    }

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

  private async handleGlobalRequest(payload: Uint8Array): Promise<void> {
    // SSH_MSG_GLOBAL_REQUEST format:
    //   byte      SSH_MSG_GLOBAL_REQUEST (80)
    //   string    request_name
    //   boolean   want_reply
    //   ...       request-specific data
    let offset = 1;
    const nameLen = (payload[offset] << 24) | (payload[offset+1] << 16) |
                    (payload[offset+2] << 8) | payload[offset+3];
    offset += 4;
    const requestName = new TextDecoder().decode(payload.slice(offset, offset + nameLen));
    offset += nameLen;
    const wantReply = payload[offset] !== 0;

    this.sendDebug(`Global request: ${requestName}, wantReply=${wantReply}`);

    if (requestName === 'keepalive@openssh.com') {
      if (wantReply) {
        const reply = new Uint8Array([SSH_MSG_REQUEST_SUCCESS]);
        await this.sendEncrypted(reply);
      }
      return;
    }

    if (wantReply) {
      const reply = new Uint8Array([SSH_MSG_REQUEST_FAILURE]);
      await this.sendEncrypted(reply);
    }
  }

  private startKeepalive(): void {
    this.keepaliveInterval = setInterval(async () => {
      try {
        const ignoreMsg = new Uint8Array([SSH_MSG_IGNORE, 0, 0, 0, 0]);
        await this.sendEncrypted(ignoreMsg);
      } catch (e) {
        this.sendDebug('Keepalive send failed: ' + (e instanceof Error ? e.message : String(e)));
      }
    }, 25000);
  }

  private async handleKEXPacket(msgType: number, payload: Uint8Array): Promise<void> {
    this.sendDebug(`handleKEXPacket: msgType=${msgType}`);
    switch (msgType) {
      case SSH_MSG_KEXINIT: {
        this.kexInitRemote = payload;
        this.sendDebug('Received KEXINIT from server');
        try {
          const serverKex = parseKEXInit(payload);
          const clientKex = parseKEXInit(this.kexInitLocal!);
          this.negotiatedCipherC2S = negotiate(clientKex.encryptionC2S, serverKex.encryptionC2S);
          this.negotiatedCipherS2C = negotiate(clientKex.encryptionS2C, serverKex.encryptionS2C);
          this.sendDebug(`Negotiated C2S: ${this.negotiatedCipherC2S}, S2C: ${this.negotiatedCipherS2C}`);
        } catch (e) {
          const errMsg = e instanceof Error ? e.message : String(e);
          this.sendError('算法协商失败: ' + errMsg);
          this.close();
        }
        break;
      }

      case SSH_MSG_KEX_ECDH_REPLY:
        this.sendDebug('Received ECDH_REPLY');
        await this.handleECDHReply(payload);
        break;

      case SSH_MSG_NEWKEYS: {
        this.sendDebug(`Received NEWKEYS, seqNumSend=${this.seqNumSend}`);
        const newKeys = new Uint8Array([SSH_MSG_NEWKEYS]);
        const packet = await SSHPacketBuilder.build(
          newKeys, 8, null, this.seqNumSend++
        );
        await this.writeSocket(packet);
        this.sendDebug(`Client NEWKEYS sent, seqNumSend=${this.seqNumSend}`);

        await this.enableEncryption();
        this.sendDebug('Encryption enabled');

        this.state = 'auth';
        try {
          await this.sendServiceRequest();
          this.sendDebug('SERVICE_REQUEST sent successfully');
        } catch (e) {
          const errMsg = e instanceof Error ? e.message : String(e);
          this.sendDebug(`SERVICE_REQUEST failed: ${errMsg}`);
          this.sendError('SERVICE_REQUEST 失败: ' + errMsg);
          this.close();
        }
        break;
      }

      case SSH_MSG_UNIMPLEMENTED:
        this.sendDebug('Server sent UNIMPLEMENTED');
        break;

      default:
        this.sendDebug(`Unexpected msgType=${msgType} in kex state`);
        break;
    }
  }

  private async handleECDHReply(payload: Uint8Array): Promise<void> {
    this.sendDebug('Parsing ECDH_REPLY...');
    const { hostKey, serverRawPublicKey, signature } =
      ECDHKeyExchange.parseReply(payload);
    this.sendDebug(`ECDH_REPLY parsed: hostKey=${hostKey.length}, serverPubKey=${serverRawPublicKey.length}, sig=${signature.length}`);

    const sharedSecret = await ECDHKeyExchange.computeSharedSecret(
      this.ecdhKeyPair.privateKey,
      serverRawPublicKey
    );
    this.sendDebug(`Shared secret: ${sharedSecret.length} bytes`);

    const H = await ECDHKeyExchange.computeExchangeHash(
      this.transport.getLocalVersion(),
      this.transport.getRemoteVersion(),
      this.kexInitLocal!,
      this.kexInitRemote!,
      hostKey,
      this.ecdhRawPublicKey,
      serverRawPublicKey,
      sharedSecret
    );
    const hHex = Array.from(H).map(b => b.toString(16).padStart(2, '0')).join('');
    this.sendDebug(`Exchange hash H=${hHex}`);

    // Compute host key fingerprint (SHA-256)
    const fpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', hostKey));
    this.hostKeyFingerprint = 'SHA256:' + btoa(String.fromCharCode(...fpHash)).replace(/=+$/, '');
    this.sendStatus(`服务器指纹: ${this.hostKeyFingerprint}`);
    this.sendDebug(`Host key fingerprint: ${this.hostKeyFingerprint}`);

    // Verify host key signature to confirm exchange hash is correct
    try {
      const sigVerified = await this.verifyHostKeySignature(hostKey, signature, H);
      if (sigVerified === null) {
        this.sendDebug('Host key signature verification: UNSUPPORTED ALGORITHM');
        this.sendStatus('主机密钥签名验证被跳过（暂不支持该算法，但不影响连接）');
      } else {
        this.sendDebug(`Host key signature verification: ${sigVerified ? 'PASS' : 'FAIL'}`);
        if (!sigVerified) {
          this.sendError('主机密钥签名验证失败 - 可能会有安全风险或 Exchange Hash 计算错误，但不阻断连接。');
        }
      }
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e);
      this.sendDebug(`Signature verification error: ${errMsg}`);
    }

    if (!this.sessionID) {
      this.sessionID = H;
      this.sendDebug('Session ID set');
    }

    this.derivedKeys = await KeyDerivation.deriveKeys(sharedSecret, H, this.sessionID!);
    this.sendDebug('Keys derived, waiting for NEWKEYS');
  }

  private async verifyHostKeySignature(
    hostKeyBlob: Uint8Array,
    signatureBlob: Uint8Array,
    exchangeHash: Uint8Array
  ): Promise<boolean | null> {
    // Parse host key blob to get key type and raw key
    let offset = 0;
    const keyTypeLen = (hostKeyBlob[offset] << 24) | (hostKeyBlob[offset+1] << 16) |
                       (hostKeyBlob[offset+2] << 8) | hostKeyBlob[offset+3];
    offset += 4;
    const keyType = new TextDecoder().decode(hostKeyBlob.slice(offset, offset + keyTypeLen));
    offset += keyTypeLen;
    this.sendDebug(`Host key type: ${keyType}`);

    // Parse signature blob to get sig type and raw sig
    let sigOffset = 0;
    const sigTypeLen = (signatureBlob[sigOffset] << 24) | (signatureBlob[sigOffset+1] << 16) |
                       (signatureBlob[sigOffset+2] << 8) | signatureBlob[sigOffset+3];
    sigOffset += 4;
    const sigType = new TextDecoder().decode(signatureBlob.slice(sigOffset, sigOffset + sigTypeLen));
    sigOffset += sigTypeLen;
    const rawSigLen = (signatureBlob[sigOffset] << 24) | (signatureBlob[sigOffset+1] << 16) |
                      (signatureBlob[sigOffset+2] << 8) | signatureBlob[sigOffset+3];
    sigOffset += 4;
    const rawSig = signatureBlob.slice(sigOffset, sigOffset + rawSigLen);
    this.sendDebug(`Signature type: ${sigType}, raw sig len: ${rawSig.length}`);

    if (keyType === 'ssh-ed25519') {
      const rawKeyLen = (hostKeyBlob[offset] << 24) | (hostKeyBlob[offset+1] << 16) |
                        (hostKeyBlob[offset+2] << 8) | hostKeyBlob[offset+3];
      offset += 4;
      const rawKey = hostKeyBlob.slice(offset, offset + rawKeyLen);
      this.sendDebug(`Ed25519 public key: ${rawKey.length} bytes`);

      const pubKey = await crypto.subtle.importKey(
        'raw',
        rawKey,
        { name: 'Ed25519' },
        false,
        ['verify']
      );

      return await crypto.subtle.verify(
        'Ed25519',
        pubKey,
        rawSig,
        exchangeHash
      );
    } else if (keyType === 'ecdsa-sha2-nistp256') {
      // Parse ECDSA key
      const curveLen = (hostKeyBlob[offset] << 24) | (hostKeyBlob[offset+1] << 16) |
                       (hostKeyBlob[offset+2] << 8) | hostKeyBlob[offset+3];
      offset += 4 + curveLen;
      const rawKeyLen = (hostKeyBlob[offset] << 24) | (hostKeyBlob[offset+1] << 16) |
                        (hostKeyBlob[offset+2] << 8) | hostKeyBlob[offset+3];
      offset += 4;
      const rawKey = hostKeyBlob.slice(offset, offset + rawKeyLen);
      this.sendDebug(`ECDSA public key: ${rawKey.length} bytes`);

      const pubKey = await crypto.subtle.importKey(
        'raw',
        rawKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
      );

      // Convert SSH DER signature to raw r||s format for Web Crypto
      const ecdsaRawSig = this.convertSSHECDSASig(rawSig);
      this.sendDebug(`ECDSA raw sig: ${ecdsaRawSig.length} bytes`);

      return await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        pubKey,
        ecdsaRawSig,
        exchangeHash
      );
    } else if (keyType === 'ssh-rsa') {
      // Parse RSA key
      const eLen = (hostKeyBlob[offset] << 24) | (hostKeyBlob[offset+1] << 16) |
                   (hostKeyBlob[offset+2] << 8) | hostKeyBlob[offset+3];
      offset += 4;
      const eRaw = hostKeyBlob.slice(offset, offset + eLen);
      offset += eLen;
      
      const nLen = (hostKeyBlob[offset] << 24) | (hostKeyBlob[offset+1] << 16) |
                   (hostKeyBlob[offset+2] << 8) | hostKeyBlob[offset+3];
      offset += 4;
      const nRaw = hostKeyBlob.slice(offset, offset + nLen);
      
      // Determine hash algorithm based on signature type
      let hashAlgo = 'SHA-1';
      if (sigType === 'rsa-sha2-256') hashAlgo = 'SHA-256';
      else if (sigType === 'rsa-sha2-512') hashAlgo = 'SHA-512';
      
      this.sendDebug(`RSA public key: n=${nRaw.length} bytes, e=${eRaw.length} bytes, hash=${hashAlgo}`);

      // Convert to JWK format for import
      const jwk = {
        kty: "RSA",
        e: this.base64UrlEncodeUnsigned(eRaw),
        n: this.base64UrlEncodeUnsigned(nRaw),
        ext: true
      };

      try {
        const pubKey = await crypto.subtle.importKey(
          'jwk',
          jwk,
          { name: 'RSASSA-PKCS1-v1_5', hash: hashAlgo },
          false,
          ['verify']
        );

        return await crypto.subtle.verify(
          'RSASSA-PKCS1-v1_5',
          pubKey,
          rawSig,
          exchangeHash
        );
      } catch (e) {
         this.sendDebug(`RSA import/verify error: ${e}`);
         return false;
      }
    }

    this.sendDebug(`Unsupported key type for verification: ${keyType}`);
    return null; // Return null for unsupported algorithms instead of failing
  }

  // Convert Uint8Array to base64url string without leading zero bytes (useful for JWK mpint)
  private base64UrlEncodeUnsigned(buffer: Uint8Array): string {
    let start = 0;
    while (start < buffer.length - 1 && buffer[start] === 0x00) {
      start++;
    }
    let binary = '';
    for (let i = start; i < buffer.length; i++) {
      binary += String.fromCharCode(buffer[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  private convertSSHECDSASig(sshSig: Uint8Array): Uint8Array {
    // SSH ECDSA sig is: string r, string s (each mpint)
    let offset = 0;
    const rLen = (sshSig[offset] << 24) | (sshSig[offset+1] << 16) |
                 (sshSig[offset+2] << 8) | sshSig[offset+3];
    offset += 4;
    let r = sshSig.slice(offset, offset + rLen);
    offset += rLen;
    const sLen = (sshSig[offset] << 24) | (sshSig[offset+1] << 16) |
                 (sshSig[offset+2] << 8) | sshSig[offset+3];
    offset += 4;
    let s = sshSig.slice(offset, offset + sLen);

    // Strip leading zero bytes (mpint sign extension)
    if (r.length > 32 && r[0] === 0) r = r.slice(1);
    if (s.length > 32 && s[0] === 0) s = s.slice(1);

    // Pad to 32 bytes each
    const result = new Uint8Array(64);
    result.set(r, 32 - r.length);
    result.set(s, 64 - s.length);
    return result;
  }

  private async enableEncryption(): Promise<void> {
    const keys = this.derivedKeys;
    let encKeyC2S = keys.encKeyClientToServer;
    let encKeyS2C = keys.encKeyServerToClient;

    if (this.negotiatedCipherC2S === 'aes128-gcm@openssh.com') {
      encKeyC2S = encKeyC2S.slice(0, 16);
    }
    if (this.negotiatedCipherS2C === 'aes128-gcm@openssh.com') {
      encKeyS2C = encKeyS2C.slice(0, 16);
    }

    const toHex = (a: Uint8Array) => Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('');
    this.sendDebug(`ivC2S=${toHex(keys.ivClientToServer)}`);
    this.sendDebug(`encKeyC2S=${toHex(encKeyC2S)}`);
    this.sendDebug(`ivS2C=${toHex(keys.ivServerToClient)}`);
    this.sendDebug(`encKeyS2C=${toHex(encKeyS2C)}`);

    this.encryptCipher = new SSHAESGCMCipher(
      encKeyC2S,
      keys.ivClientToServer
    );
    await this.encryptCipher.init();

    this.decryptCipher = new SSHAESGCMCipher(
      encKeyS2C,
      keys.ivServerToClient
    );
    await this.decryptCipher.init();

    this.sendDebug('Ciphers initialized');
  }

  private async sendServiceRequest(): Promise<void> {
    const serviceName = 'ssh-userauth';
    const nameBytes = new TextEncoder().encode(serviceName);
    const serviceRequest = new Uint8Array(1 + 4 + nameBytes.length);
    serviceRequest[0] = SSH_MSG_SERVICE_REQUEST;
    new DataView(serviceRequest.buffer).setUint32(1, nameBytes.length, false);
    serviceRequest.set(nameBytes, 5);

    console.log('[AUTH] SERVICE_REQUEST payload len=' + serviceRequest.length + ', seqNum=' + this.seqNumSend);
    console.log('[AUTH] encryptCipher exists=' + !!this.encryptCipher);

    const packet = await SSHPacketBuilder.build(
      serviceRequest, 16,
      (data, seq, aad) => {
        console.log('[AUTH] Encrypting: dataLen=' + data.length + ', seq=' + seq + ', aadLen=' + aad?.length);
        return this.encryptCipher!.encrypt(data, seq, aad);
      },
      this.seqNumSend++,
      true
    );
    console.log('[AUTH] Encrypted packet len=' + packet.length + ', first16=' + Array.from(packet.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(''));
    await this.writeSocket(packet);
    console.log('[AUTH] SERVICE_REQUEST sent to socket');
  }

  private async authenticate(): Promise<void> {
    let authRequest: Uint8Array;

    if (this.config.authMethod === 'publickey' && this.config.privateKey) {
      this.sendStatus('正在使用密钥认证...');
      authRequest = await SSHAuth.buildPublicKeyAuthRequest(
        this.config.username,
        this.config.privateKey,
        this.sessionID!
      );
    } else {
      authRequest = SSHAuth.buildPasswordAuthRequest(
        this.config.username,
        this.config.password
      );
    }

    const packet = await SSHPacketBuilder.build(
      authRequest, 16,
      (data, seq, aad) => this.encryptCipher!.encrypt(data, seq, aad),
      this.seqNumSend++,
      true
    );
    await this.writeSocket(packet);
  }

  private async handleAuthPacket(msgType: number, payload: Uint8Array): Promise<void> {
    switch (msgType) {
      case SSH_MSG_SERVICE_ACCEPT:
        this.sendStatus('认证服务已接受，正在认证...');
        await this.authenticate();
        break;

      case SSH_MSG_USERAUTH_SUCCESS:
        this.sendStatus('认证成功');
        this.state = 'shell';
        this.startKeepalive();
        await this.openShell();
        break;

      case SSH_MSG_USERAUTH_FAILURE:
        this.sendError('认证失败：用户名或密码错误');
        this.close();
        break;

      case SSH_MSG_UNIMPLEMENTED:
        console.warn('[AUTH] Server sent UNIMPLEMENTED');
        break;
    }
  }

  private async openShell(): Promise<void> {
    const openMsg = this.channel.buildOpenSession();
    await this.sendEncrypted(openMsg);
  }

  private async handleSessionPacket(msgType: number, payload: Uint8Array): Promise<void> {
    switch (msgType) {
      case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        this.channel.handleOpenConfirmation(payload);
        const ptyReq = this.channel.buildPTYRequest(120, 40);
        await this.sendEncrypted(ptyReq);
        break;

      case SSH_MSG_CHANNEL_OPEN_FAILURE:
        this.sendError('通道打开被拒绝');
        this.close();
        break;

      case SSH_MSG_CHANNEL_SUCCESS:
        if (this.state === 'shell') {
          const shellReq = this.channel.buildShellRequest();
          await this.sendEncrypted(shellReq);
          this.state = 'ready';
          this.sendStatus('Shell 已就绪');
        }
        break;

      case SSH_MSG_CHANNEL_FAILURE:
        if (this.state === 'shell') {
          this.sendError('PTY 或 Shell 请求被拒绝');
          this.close();
        }
        break;

      case SSH_MSG_CHANNEL_DATA: {
        const outputData = this.channel.handleChannelData(payload);
        this.ws.send(outputData.slice().buffer as ArrayBuffer);
        const adjustMsg = this.channel.buildWindowAdjust(outputData.length);
        await this.sendEncrypted(adjustMsg);
        break;
      }

      case SSH_MSG_CHANNEL_WINDOW_ADJUST:
        break;

      case SSH_MSG_CHANNEL_EOF:
      case SSH_MSG_CHANNEL_CLOSE:
        this.sendStatus('会话已结束');
        this.close();
        break;

      case SSH_MSG_DISCONNECT:
        this.sendStatus('服务器断开连接');
        this.close();
        break;

      case SSH_MSG_IGNORE:
      case SSH_MSG_DEBUG:
      case SSH_MSG_UNIMPLEMENTED:
        break;
    }
  }

  async handleWebSocketMessage(data: string | ArrayBuffer): Promise<void> {
    if (this.state !== 'ready') return;

    if (typeof data === 'string') {
      if (data === '{"type":"ping"}') {
        this.ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }
      
      if (data.startsWith('{"type":"resize"')) {
        try {
          const msg = JSON.parse(data);
          if (msg.type === 'resize') {
            await this.handleResize(msg.cols, msg.rows);
            return;
          }
        } catch {}
      }
      
      const encoded = new TextEncoder().encode(data);
      const channelData = this.channel.buildChannelData(encoded);
      await this.sendEncrypted(channelData);
    } else {
      const channelData = this.channel.buildChannelData(new Uint8Array(data));
      await this.sendEncrypted(channelData);
    }
  }

  private async handleResize(cols: number, rows: number): Promise<void> {
    const resizeMsg = this.channel.buildWindowChange(cols, rows);
    await this.sendEncrypted(resizeMsg);
  }

  private async sendEncrypted(payload: Uint8Array): Promise<void> {
    const operation = this.sendMutex.then(async () => {
      if (!this.encryptCipher) {
        throw new Error('Encryption not initialized');
      }

      const encrypted = await SSHPacketBuilder.build(
        payload, 16,
        (data, seq, aad) => this.encryptCipher!.encrypt(data, seq, aad),
        this.seqNumSend++,
        true
      );
      await this.writeSocket(encrypted);
    });
    
    this.sendMutex = operation.catch(() => {}); // prevent unhandled rejections from blocking the queue
    await operation;
  }

  private sendStatus(message: string): void {
    try {
      this.ws.send(JSON.stringify({ type: 'status', message }));
    } catch {}
  }

  private sendError(message: string): void {
    try {
      this.ws.send(JSON.stringify({ type: 'error', message }));
    } catch {}
  }

  private sendDebug(message: string): void {
    // console.log('[DEBUG] ' + message);
    // try {
    //   this.ws.send(JSON.stringify({ type: 'status', message: '[DEBUG] ' + message }));
    // } catch {}
  }

  close(): void {
    if (this.keepaliveInterval) {
      clearInterval(this.keepaliveInterval);
      this.keepaliveInterval = null;
    }
    try { this.socket.close(); } catch {}
    try { this.ws.close(); } catch {}
  }
}
