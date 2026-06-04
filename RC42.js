const crypto = require("crypto");

// ======================================================
// STANDARD RC4
// ======================================================

class RC4 {
  constructor(key) {
    this.S = Array.from({ length: 256 }, (_, i) => i);
    this.i = 0;
    this.j = 0;

    const keyBytes = Buffer.from(key);

    let j = 0;

    for (let i = 0; i < 256; i++) {
      j = (j + this.S[i] + keyBytes[i % keyBytes.length]) % 256;

      [this.S[i], this.S[j]] = [this.S[j], this.S[i]];
    }
  }

  generateKeystream(length) {
    const stream = Buffer.alloc(length);

    for (let k = 0; k < length; k++) {
      this.i = (this.i + 1) % 256;
      this.j = (this.j + this.S[this.i]) % 256;

      [this.S[this.i], this.S[this.j]] = [this.S[this.j], this.S[this.i]];

      stream[k] = this.S[(this.S[this.i] + this.S[this.j]) % 256];
    }

    return stream;
  }

  process(dataBuffer) {
    const keystream = this.generateKeystream(dataBuffer.length);

    const output = Buffer.alloc(dataBuffer.length);

    for (let i = 0; i < dataBuffer.length; i++) {
      output[i] = dataBuffer[i] ^ keystream[i];
    }

    return output;
  }
}

// ======================================================
// ENHANCED RC4
// ======================================================

class EnhancedRC4 {
  constructor(key) {
    this.S = Array.from({ length: 256 }, (_, i) => i);

    this.i = 0;
    this.j = 0;

    // Key Whitening
    const whitenedKey = crypto.createHash("sha256").update(key).digest();

    // Double KSA
    this.doubleKSA(whitenedKey);

    // RC4-Drop1024
    this.dropInitialBytes(1024);
  }

  doubleKSA(key) {
    let jKsa = 0;

    for (let round = 0; round < 2; round++) {
      for (let k = 0; k < 256; k++) {
        jKsa = (jKsa + this.S[k] + key[k % key.length]) % 256;

        [this.S[k], this.S[jKsa]] = [this.S[jKsa], this.S[k]];
      }
    }
  }

  dropInitialBytes(numBytes) {
    for (let k = 0; k < numBytes; k++) {
      this.i = (this.i + 1) % 256;
      this.j = (this.j + this.S[this.i]) % 256;

      [this.S[this.i], this.S[this.j]] = [this.S[this.j], this.S[this.i]];

      // Generate and discard
      this.S[(this.S[this.i] + this.S[this.j]) % 256];
    }
  }

  generateKeystream(length) {
    const stream = Buffer.alloc(length);

    for (let k = 0; k < length; k++) {
      this.i = (this.i + 1) % 256;
      this.j = (this.j + this.S[this.i]) % 256;

      [this.S[this.i], this.S[this.j]] = [this.S[this.j], this.S[this.i]];

      stream[k] = this.S[(this.S[this.i] + this.S[this.j]) % 256];
    }

    return stream;
  }

  process(dataBuffer) {
    const keystream = this.generateKeystream(dataBuffer.length);

    const output = Buffer.alloc(dataBuffer.length);

    for (let i = 0; i < dataBuffer.length; i++) {
      output[i] = dataBuffer[i] ^ keystream[i];
    }

    return output;
  }
}

// ======================================================
// RANDOMNESS TESTS
// ======================================================

function frequencyTest(buffer) {
  let ones = 0;
  let zeros = 0;

  for (const byte of buffer) {
    for (let bit = 0; bit < 8; bit++) {
      if ((byte >> bit) & 1) ones++;
      else zeros++;
    }
  }

  return {
    ones,
    zeros,
    ratio: ones / (ones + zeros),
  };
}

function entropyAnalysis(buffer) {
  const freq = new Array(256).fill(0);

  for (const byte of buffer) freq[byte]++;

  let entropy = 0;

  for (const count of freq) {
    if (count === 0) continue;

    const p = count / buffer.length;

    entropy -= p * Math.log2(p);
  }

  return entropy;
}

function byteDistribution(buffer) {
  const freq = new Array(256).fill(0);

  for (const byte of buffer) freq[byte]++;

  return freq;
}

// ======================================================
// PERFORMANCE TEST
// ======================================================

function performanceTest(CipherClass, key) {
  const data = Buffer.alloc(1000000, "A");

  const start = process.hrtime.bigint();

  const cipher = new CipherClass(key);

  cipher.process(data);

  const end = process.hrtime.bigint();

  return Number(end - start) / 1000000;
}

// ======================================================
// EVALUATION
// ======================================================

function evaluateCipher(name, CipherClass, key) {
  console.log("\n====================================");
  console.log(name);
  console.log("====================================");

  const cipher = new CipherClass(key);

  const keystream = cipher.generateKeystream(100000);

  const frequency = frequencyTest(keystream);

  const entropy = entropyAnalysis(keystream);

  const execTime = performanceTest(CipherClass, key);

  console.log("Entropy:", entropy.toFixed(6));

  console.log("Ones:", frequency.ones);

  console.log("Zeros:", frequency.zeros);

  console.log("1-Bit Ratio:", frequency.ratio.toFixed(6));

  console.log("Execution Time:", execTime.toFixed(3), "ms");

  return {
    entropy,
    ratio: frequency.ratio,
    execTime,
  };
}

// ======================================================
// ENCRYPTION / DECRYPTION DEMO
// ======================================================

const key = "MySuperSecretProjectKey";

const plaintext = "Hello Enhanced RC4 Project";

console.log("Original Text:");
console.log(plaintext);

const plainBuffer = Buffer.from(plaintext, "utf8");

const enc = new EnhancedRC4(key);

const ciphertext = enc.process(plainBuffer);

console.log("\nCiphertext (Hex):");

console.log(ciphertext.toString("hex"));

const dec = new EnhancedRC4(key);

const decrypted = dec.process(ciphertext);

console.log("\nDecrypted Text:");

console.log(decrypted.toString("utf8"));

// ======================================================
// RANDOMNESS + PERFORMANCE COMPARISON
// ======================================================

const rc4Result = evaluateCipher("STANDARD RC4", RC4, key);

const enhancedResult = evaluateCipher("ENHANCED RC4", EnhancedRC4, key);

// ======================================================
// FINAL COMPARISON TABLE
// ======================================================

console.log("\n");
console.log("====================================");
console.log("FINAL COMPARISON");
console.log("====================================");

console.table([
  {
    Algorithm: "Standard RC4",
    Entropy: rc4Result.entropy.toFixed(6),

    BitRatio: rc4Result.ratio.toFixed(6),

    Time_ms: rc4Result.execTime.toFixed(3),
  },
  {
    Algorithm: "Enhanced RC4",

    Entropy: enhancedResult.entropy.toFixed(6),

    BitRatio: enhancedResult.ratio.toFixed(6),

    Time_ms: enhancedResult.execTime.toFixed(3),
  },
]);

console.log("\nInterpretation:");
console.log("- Entropy closer to 8.0 indicates better randomness.");

console.log("- Bit ratio closer to 0.5 indicates balanced 0s and 1s.");

console.log("- Lower execution time indicates better performance.");
