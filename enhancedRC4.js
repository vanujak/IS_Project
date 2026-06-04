const crypto = require("crypto"); // Built-in Node.js crypto module
const readline = require("readline");

class EnhancedRC4 {
  constructor(key) {
    // Initialize the State array (S) with values 0 to 255
    this.S = Array.from({ length: 256 }, (_, index) => index);
    this.i = 0;
    this.j = 0;

    // 1. Proposed Improvement: Key Whitening using SHA-256
    // This guarantees a high-entropy 256-bit (32-byte) key
    const whitenedKey = crypto.createHash("sha256").update(key).digest();

    // 2. Proposed Improvement: Double Key Scheduling Algorithm (KSA)
    this.doubleKSA(whitenedKey);

    // 3. Proposed Improvement: Adaptive Keystream Filtering (Drop initial 1024 bytes)
    this.dropInitialBytes(1024);
  }

  // KSA applied twice to drastically improve state mixing
  doubleKSA(key) {
    let jKsa = 0;

    for (let round = 0; round < 2; round++) {
      for (let k = 0; k < 256; k++) {
        jKsa = (jKsa + this.S[k] + key[k % key.length]) % 256;

        // Swap S[k] and S[jKsa]
        let temp = this.S[k];
        this.S[k] = this.S[jKsa];
        this.S[jKsa] = temp;
      }
    }
  }

  // Discards biased initial bytes to defend against statistical attacks
  dropInitialBytes(numBytes) {
    for (let k = 0; k < numBytes; k++) {
      this.i = (this.i + 1) % 256;
      this.j = (this.j + this.S[this.i]) % 256;

      // Swap
      let temp = this.S[this.i];
      this.S[this.i] = this.S[this.j];
      this.S[this.j] = temp;

      // Generate byte but deliberately discard it (do not output)
      let discard = this.S[(this.S[this.i] + this.S[this.j]) % 256];
    }
  }

  // Pseudo-Random Generation Algorithm (PRGA) / Encryption & Decryption
  process(dataBuffer) {
    const output = Buffer.alloc(dataBuffer.length);

    for (let k = 0; k < dataBuffer.length; k++) {
      this.i = (this.i + 1) % 256;
      this.j = (this.j + this.S[this.i]) % 256;

      // Swap
      let temp = this.S[this.i];
      this.S[this.i] = this.S[this.j];
      this.S[this.j] = temp;

      // Generate Keystream Byte
      const keystreamByte = this.S[(this.S[this.i] + this.S[this.j]) % 256];

      // XOR operation to encrypt/decrypt
      output[k] = dataBuffer[k] ^ keystreamByte;
    }
    return output;
  }
}

// ==========================================
// TEST EXECUTION
// ==========================================

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

rl.question("Enter Secret Key: ", (secretKey) => {
  rl.question("Enter Plaintext: ", (plaintext) => {
    console.log("\nOriginal Text:", plaintext);

    const dataBuffer = Buffer.from(plaintext, "utf-8");

    // Encryption
    const rc4Encrypt = new EnhancedRC4(secretKey);
    const ciphertext = rc4Encrypt.process(dataBuffer);

    const hexCiphertext = ciphertext
      .toString("hex")
      .match(/.{1,2}/g)
      .join(" ");

    console.log("\nCiphertext (Hex):");
    console.log(hexCiphertext);

    // Decryption
    const rc4Decrypt = new EnhancedRC4(secretKey);
    const decryptedBuffer = rc4Decrypt.process(ciphertext);

    console.log("\nDecrypted Text:");
    console.log(decryptedBuffer.toString("utf-8"));

    rl.close();
  });
});
