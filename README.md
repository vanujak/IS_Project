# Enhancing RC4 Security Using Double Key Scheduling and Adaptive Keystream Filtering

## 👥 Project Team Details

- **Group No:** 23
- **Members:**
  - EG/2022/5131 - Karunaratne A.V.V.V.
  - EG/2022/5136 - Kavindi S.K.H.V.
  - EG/2022/5139 - Keerthirathna D.G.D.L.
  - EG/2022/5142 - Keragala A.M.K.

---

## 📝 Project Overview

### 1. Introduction & Problem Statement

The RC4 stream cipher is widely known for its simplicity and high speed in software implementations. However, it suffers from several well-documented vulnerabilities, particularly in its Key Scheduling Algorithm (KSA) and the presence of biases in the initial keystream output. These weaknesses make RC4 susceptible to statistical attacks, leading to potential leakage of sensitive information. Therefore, improving RC4 while maintaining its efficiency is an important research problem in modern cryptography.

### 2. Objectives

- To analyze the weaknesses in the standard RC4 algorithm.
- To design a modified RC4 algorithm with improved security features.
- To eliminate or reduce initial keystream biases.
- To enhance the randomness of the generated keystream.
- To compare the performance and security of the modified RC4 with the original RC4.

### 3. Proposed Methodology

The implementation improves on the standard Key Scheduling Algorithm (KSA) and Pseudo-Random Generation Algorithm (PRGA) through three distinct cryptographic modifications:

1. **Key Whitening:** Apply key whitening using SHA-256 before KSA to strengthen key randomness.
2. **Double Key Scheduling:** Use double key scheduling (KSA applied twice) to improve state mixing.
3. **Adaptive Keystream Filtering:** Discard biased initial bytes (the first 1024 bytes) before data processing.

---

## 🛠️ Implementation (Node.js / JavaScript)

The algorithm has been implemented in JavaScript using Node.js. It utilizes the native `crypto` module for high-performance SHA-256 hashing without requiring external third-party dependencies.

```javascript
const crypto = require("crypto");

class EnhancedRC4 {
  constructor(key) {
    this.S = Array.from({ length: 256 }, (_, index) => index);
    this.i = 0;
    this.j = 0;

    // 1. Key Whitening using SHA-256
    const whitenedKey = crypto.createHash("sha256").update(key).digest();

    // 2. Double Key Scheduling Algorithm (KSA)
    this.doubleKSA(whitenedKey);

    // 3. Adaptive Keystream Filtering
    this.dropInitialBytes(1024);
  }

  doubleKSA(key) {
    let jKsa = 0;

    for (let round = 0; round < 2; round++) {
      for (let k = 0; k < 256; k++) {
        jKsa = (jKsa + this.S[k] + key[k % key.length]) % 256;

        let temp = this.S[k];
        this.S[k] = this.S[jKsa];
        this.S[jKsa] = temp;
      }
    }
  }

  dropInitialBytes(numBytes) {
    for (let k = 0; k < numBytes; k++) {
      this.i = (this.i + 1) % 256;
      this.j = (this.j + this.S[this.i]) % 256;

      let temp = this.S[this.i];
      this.S[this.i] = this.S[this.j];
      this.S[this.j] = temp;

      this.S[(this.S[this.i] + this.S[this.j]) % 256];
    }
  }

  process(dataBuffer) {
    const output = Buffer.alloc(dataBuffer.length);

    for (let k = 0; k < dataBuffer.length; k++) {
      this.i = (this.i + 1) % 256;
      this.j = (this.j + this.S[this.i]) % 256;

      let temp = this.S[this.i];
      this.S[this.i] = this.S[this.j];
      this.S[this.j] = temp;

      const keystreamByte = this.S[(this.S[this.i] + this.S[this.j]) % 256];

      output[k] = dataBuffer[k] ^ keystreamByte;
    }

    return output;
  }
}

// ===============================
// Execution Sandbox
// ===============================

const secretKey = "MySuperSecretProjectKey";

const plaintext =
  "Hello, Group 23! This is an Enhanced RC4 test in JavaScript.";

console.log("Original Text:");
console.log(plaintext);

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
```

---

## ▶️ How to Run the Program

### Prerequisites

Before running the project, ensure that the following software is installed:

- Node.js (v14 or later recommended)
- npm (comes with Node.js)

Verify installation using:

```bash
node -v
npm -v
```

### Step 1: Create the Project File

Create a file named:

```text
enhanced_rc4.js
```

Copy the JavaScript implementation into this file.

### Step 2: Run the Program

Open a terminal in the project directory and execute:

```bash
node enhanced_rc4.js
```

### Step 3: Observe the Output

The program will display:

```text
Original Text:
Hello, Group 23! This is an Enhanced RC4 test in JavaScript.

Ciphertext (Hex):
<Encrypted hexadecimal output>

Decrypted Text:
Hello, Group 23! This is an Enhanced RC4 test in JavaScript.
```

### How It Works

1. The user provides a secret key and plaintext message.
2. The key is whitened using SHA-256.
3. The modified RC4 performs double key scheduling.
4. The first 1024 keystream bytes are discarded.
5. The remaining keystream is used to encrypt the plaintext.
6. Using the same key, the ciphertext is decrypted back to the original message.

### Expected Result

- The ciphertext appears as unreadable hexadecimal data.
- The decrypted text must exactly match the original plaintext.
- Successful recovery of the original message confirms correct encryption and decryption.

---

## ✅ Expected Output

```text
Original Text:
Hello, Group 23! This is an Enhanced RC4 test in JavaScript.

Ciphertext (Hex):
<Encrypted hexadecimal output>

Decrypted Text:
Hello, Group 23! This is an Enhanced RC4 test in JavaScript.
```

---

## 📌 Conclusion

The proposed Enhanced RC4 algorithm improves the security of the original RC4 stream cipher by incorporating SHA-256-based key whitening, double key scheduling, and adaptive keystream filtering. These modifications help reduce known RC4 biases and strengthen resistance against statistical attacks while preserving the lightweight and efficient nature of RC4. Experimental testing confirms that encryption and decryption operate correctly, demonstrating the feasibility of the proposed approach for secure data transmission.
