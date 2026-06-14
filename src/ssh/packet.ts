import { SSHPacket } from '../types';
import { readUint32 } from './utils';

export class SSHPacketParser {
  private buffer: Uint8Array = new Uint8Array(0);
  private seqNum: number = 0;

  feed(data: Uint8Array): void {
    const merged = new Uint8Array(this.buffer.length + data.length);
    merged.set(this.buffer);
    merged.set(data, this.buffer.length);
    this.buffer = merged;
  }

  async nextPacket(blockSize: number, decrypt: (
    data: Uint8Array, seq: number, aad?: Uint8Array
  ) => Uint8Array | Promise<Uint8Array | null> | null, hasAuthTag: boolean = false): Promise<SSHPacket | null> {
    if (hasAuthTag) {
      if (this.buffer.length < 4) return null;
      const packetLength = readUint32(this.buffer, 0);
      const expectedSize = 4 + packetLength + 16;

      if (this.buffer.length < expectedSize) return null;

      const raw = this.buffer.slice(0, expectedSize);
      this.buffer = this.buffer.slice(expectedSize);

      const lengthField = raw.slice(0, 4);
      const dataToDecrypt = raw.slice(4);
      const decrypted = await decrypt(dataToDecrypt, this.seqNum, lengthField);
      if (!decrypted) return null;

      const paddingLength = decrypted[0];
      const payload = decrypted.slice(1, 1 + packetLength - 1 - paddingLength);

      this.seqNum++;

      return {
        length: packetLength,
        paddingLength,
        payload,
        mac: raw.slice(4 + packetLength),
      };
    }

    if (this.buffer.length < blockSize) return null;

    const header = await decrypt(
      this.buffer.slice(0, blockSize), this.seqNum
    );
    if (!header) return null;

    const packetLength = (header[0] << 24) | (header[1] << 16) |
                         (header[2] << 8) | header[3];

    const totalBlocks = Math.ceil((4 + packetLength) / blockSize);
    const totalSize = totalBlocks * blockSize;

    if (this.buffer.length < totalSize) return null;

    const encryptedPacket = this.buffer.slice(0, totalSize);
    this.buffer = this.buffer.slice(totalSize);

    const decrypted = await decrypt(encryptedPacket, this.seqNum);
    if (!decrypted) return null;

    const paddingLength = decrypted[4];
    const payload = decrypted.slice(5, 5 + packetLength - 1 - paddingLength);

    this.seqNum++;

    return {
      length: packetLength,
      paddingLength,
      payload,
    };
  }

  getSeqNum(): number {
    return this.seqNum;
  }

  resetSeqNum(): void {
    this.seqNum = 0;
  }

  getBufferLength(): number {
    return this.buffer.length;
  }
}

export class SSHPacketBuilder {
  static async build(
    payload: Uint8Array,
    blockSize: number,
    encrypt: ((data: Uint8Array, seq: number, aad?: Uint8Array) => Uint8Array | Promise<Uint8Array>) | null,
    seqNum: number,
    hasAuthTag: boolean = false
  ): Promise<Uint8Array> {
    const packetLength = 1 + payload.length;
    // For AES-GCM (hasAuthTag), padding aligns the encrypted portion
    // (padding_length + payload + padding) to blockSize.
    // The 4-byte packet_length is AAD, NOT part of the encrypted data.
    // For non-GCM, padding aligns the full packet (4 + data) to blockSize.
    const alignBase = hasAuthTag
      ? (1 + payload.length) % blockSize      // encrypted portion only
      : (4 + packetLength) % blockSize;        // full packet including length
    const paddingNeeded = blockSize - (alignBase || blockSize);
    const paddingLength = paddingNeeded < 4
      ? paddingNeeded + blockSize
      : paddingNeeded;

    const totalLength = 4 + 1 + payload.length + paddingLength;
    const packet = new Uint8Array(totalLength);

    const pl = 1 + payload.length + paddingLength;
    packet[0] = (pl >> 24) & 0xff;
    packet[1] = (pl >> 16) & 0xff;
    packet[2] = (pl >> 8) & 0xff;
    packet[3] = pl & 0xff;

    packet[4] = paddingLength;

    packet.set(payload, 5);

    const crypto = globalThis.crypto;
    const randomPadding = new Uint8Array(paddingLength);
    crypto.getRandomValues(randomPadding);
    packet.set(randomPadding, 5 + payload.length);

    if (encrypt) {
      if (hasAuthTag) {
        const lengthField = packet.slice(0, 4);
        const dataToEncrypt = packet.slice(4);
        const encryptedData = await encrypt(dataToEncrypt, seqNum, lengthField);
        const result = new Uint8Array(4 + encryptedData.length);
        result.set(lengthField, 0);
        result.set(encryptedData, 4);
        return result;
      }
      return await encrypt(packet, seqNum);
    }

    return packet;
  }
}
