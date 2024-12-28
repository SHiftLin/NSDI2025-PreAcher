export default class KmerMinHash {
  constructor(k, weighted, seed) {
    this.k = k;
    this.weighted = weighted;
    this.BLOCK_SIZE = 16;
    this.keyPromise = this.generateKey(seed * 137);
    this.zero = '\0'.repeat(k);
    this.hsZero = new Set();
  }

  async init(maxZeroCnt = 20) {
    this.key = await this.keyPromise;
    for (let i = 0; i < maxZeroCnt; i++) {
      const hZero = await this.prpEnc(this.zero, i);
      this.hsZero.add(hZero);
    }
  }

  async generateKey(seed) {
    const seedBuffer = new TextEncoder().encode(seed.toString());
    const hashBuffer = await crypto.subtle.digest('SHA-256', seedBuffer);
    return new Uint8Array(hashBuffer);
  }

  async hmac(message, key) {
    const algo = { name: 'HMAC', hash: 'SHA-256' };
    const cryptoKey = await crypto.subtle.importKey('raw', key, algo, false, ['sign']);
    const signature = await crypto.subtle.sign(algo, cryptoKey, message);
    return new Uint8Array(signature);
  }

  async prpEnc(s, idx = 0) {
    const idxBuffer = new Uint8Array(this.BLOCK_SIZE / 8);
    new DataView(idxBuffer.buffer).setUint16(0, idx, false);
    const inputBuffer = new Uint8Array([...idxBuffer, ...new TextEncoder().encode(s)]);
    const hmacResult = await this.hmac(inputBuffer, this.key);
    return Array.from(hmacResult).map(byte => byte.toString(16).padStart(2, '0')).join('');
  }

  minWithoutZero(hs) {
    for (const h of hs) {
      if (!this.hsZero.has(h)) {
        return h;
      }
    }
    return Array.from(this.hsZero)[0];
  }

  async hash(str) {
    const lower = str.toLowerCase();
    const n = lower.length;
    const hs = new Set();
    const kmerCnt = new Map();

    for (let i = 0; i <= n - this.k; i++) {
      const kmer = lower.substring(i, i + this.k);
      let cnt = 0;

      if (this.weighted) {
        cnt = kmerCnt.get(kmer) || 0;
        kmerCnt.set(kmer, cnt + 1);
      }

      const h = await this.prpEnc(kmer, cnt);
      hs.add(h);
    }

    return this.minWithoutZero(hs);
  }
}