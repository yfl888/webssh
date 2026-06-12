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

  nextPacket(blockSize: number, decrypt: (
    data: Uint8Array, seq: number
  ) => Uint8Array | null, hasAuthTag: boolean = false): SSHPacket | null {
    if (this.buffer.length < blockSize) return null;

    const header = decrypt(
      this.buffer.slice(0, blockSize), this.seqNum
    );
    if (!header) return null;

    const packetLength = (header[0] << 24) | (header[1] << 16) |
                         (header[2] << 8) | header[3];

    const totalBlocks = Math.ceil((4 + packetLength) / blockSize);
    const totalSize = totalBlocks * blockSize;

    // GCM 模式有 16 字节 auth tag，普通模式没有
    const expectedSize = hasAuthTag ? totalSize + 16 : totalSize;

    if (this.buffer.length < expectedSize) return null;

    const encryptedPacket = this.buffer.slice(0, expectedSize);
    this.buffer = this.buffer.slice(expectedSize);

    const decrypted = decrypt(encryptedPacket, this.seqNum);
    if (!decrypted) return null;

    const paddingLength = decrypted[4];
    const payload = decrypted.slice(5, 5 + packetLength - 1 - paddingLength);

    this.seqNum++;

    return {
      length: packetLength,
      paddingLength,
      payload,
      mac: hasAuthTag ? encryptedPacket.slice(totalSize) : undefined,
    };
  }

  getSeqNum(): number {
    return this.seqNum;
  }
}

export class SSHPacketBuilder {
  static build(
    payload: Uint8Array,
    blockSize: number,
    encrypt: ((data: Uint8Array, seq: number) => Uint8Array) | null,
    seqNum: number
  ): Uint8Array {
    const packetLength = 1 + payload.length;
    const paddingNeeded = blockSize - ((4 + packetLength) % blockSize);
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
      return encrypt(packet, seqNum);
    }

    return packet;
  }
}
