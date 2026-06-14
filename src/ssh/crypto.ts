export class SSHAESGCMCipher {
  private key: CryptoKey | null = null;
  private iv: Uint8Array;
  private rawKey: Uint8Array;

  constructor(rawKey: Uint8Array, iv: Uint8Array) {
    // Copy the IV so we own it; this is the mutable nonce state
    this.iv = new Uint8Array(iv);
    this.rawKey = rawKey;
  }

  async init(): Promise<void> {
    this.key = await crypto.subtle.importKey(
      'raw',
      this.rawKey,
      { name: 'AES-GCM', length: this.rawKey.length * 8 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Increment the 64-bit invocation counter stored in IV bytes [4..11]
   * using big-endian carry-over logic, per RFC 5647 §7.1.
   */
  private incIV(): void {
    for (let i = 11; i >= 4; i--) {
      this.iv[i]++;
      if (this.iv[i] !== 0) {
        break;
      }
    }
  }

  async encrypt(plaintext: Uint8Array, _seqNum?: number, aad?: Uint8Array): Promise<Uint8Array> {
    if (!this.key) throw new Error('Cipher not initialized');
    const nonce = new Uint8Array(this.iv);

    const alg: Record<string, unknown> = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
    if (aad) alg.additionalData = aad;

    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(alg as AesGcmParams, this.key, plaintext)
    );

    this.incIV();
    return encrypted;
  }

  async decrypt(ciphertext: Uint8Array, _seqNum?: number, aad?: Uint8Array): Promise<Uint8Array | null> {
    if (!this.key) throw new Error('Cipher not initialized');
    const nonce = new Uint8Array(this.iv);

    const alg: Record<string, unknown> = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
    if (aad) alg.additionalData = aad;

    try {
      const decrypted = new Uint8Array(
        await crypto.subtle.decrypt(alg as AesGcmParams, this.key, ciphertext)
      );
      this.incIV();
      return decrypted;
    } catch (e) {
      console.error('[CRYPTO] Decrypt failed, ciphertextLen:', ciphertext.length, 'error:', e instanceof Error ? e.message : String(e));
      return null;
    }
  }
}

export const REKEY_THRESHOLD = 1 << 30;

export function shouldRekey(seqNum: number): boolean {
  return seqNum >= REKEY_THRESHOLD;
}
