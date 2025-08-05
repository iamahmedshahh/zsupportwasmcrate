## WIP (Work in Progress)


This project provides high-performance cryptographic functions, written in Rust and compiled to WebAssembly (WASM), for use in a modern web application. 

The core Rust crate, `veruszsupportweb`, handles Zcash Sapling key generation and symmetric key derivation, which is then consumed by a Vue.js and TypeScript frontend.

This project performs a basic

**KA.DerivePublic**
**KA.Agree**
**KDF**

Exposes the functionality as simple API in form of an extension.

-----

## Prerequisites

Before you begin, ensure you have the following tools installed:

  * **Rust:** [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)
  * **wasm-pack:** `cargo install wasm-pack`
  * **Rustup:** sudo apt install rustup
  * **Must Install:** npm install vite-plugin-node-polyfills

-----

## Project Structure

The project is organized as follows:

  * **/veruszsupportweb/**: The native Rust crate containing all core cryptographic logic and WASM bindings.
  * zsupport (root): The Vue.js + TypeScript frontend application that consumes the WASM module.

-----

## Development Workflow

Follow these steps to build, test, and run the project.

### **1. Build the WebAssembly Module**

First, you must compile the Rust crate into a WebAssembly package.

```bash
# Navigate to the Rust crate directory
cd veruszsupportweb

# Build the WASM package
wasm-pack build --target web --release --out-dir pkg
```

This command compiles the Rust code and creates a self-contained NPM package in the `veruszsupportweb/pkg` directory.


### **2. Integrate WASM with the Vue Project**


This copies the package into your `node_modules`. You must re-run this command every time you rebuild the WASM package.

```bash
# From your Vue project's root directory
npm install ./veruszsupportweb/pkg
```

### **3. Run the Vue + TypeScript Project**

Finally, install the frontend dependencies and start the development server.

```bash
# From your Vue project's root directory
npm install
npm run build
```

### **4. Test the extension browser:


```bash
Go to chrome://extensions/
Click on load unpacked and select the dist folder
```

### **6. Test the interaction with a web app?:

```bash
npm run dev
```

Open the Url 

```bash
 VITE v7.0.6  ready in 181 ms

  ➜  Local:   http://localhost:5173/
  // Can be a different URL for You
```

The extension API's are being exposed in the App.vue

If you get errors make sure you are on the latest Node Version, use LTS


## Exposed API's and their definations:

The extension injects a global API object at `window.verusCrypto`. To use it, wait for the `verusCryptoReady` event before accessing the API.

### Getting Started

```javascript
window.addEventListener('verusCryptoReady', () => {
  console.log('Verus Crypto API is ready!');

  const verusCrypto = window.verusCrypto;

  try {
    const fromIdHex = verusCrypto.convertIDtoHex("Alice.vrsc@");
    const toIdHex = verusCrypto.convertIDtoHex("Bob.vrsc@");

    const channel = verusCrypto.zGetEncryptionAddress({
      seed: ''.padStart(64, 'a'),
      fromId: fromIdHex,
      toId: toIdHex
    });

    console.log('Channel Address:', channel.address);
  } catch (e) {
    console.error('API call failed:', e.message);
  }
});
```

---

### API Reference

#### `convertIDtoHex`

Converts a human-readable VerusID name into its raw hex representation. This is being done by Verus TypeScript Primitives Library

- **Signature:**  
  `convertIDtoHex(idName: string): string`

- **Parameters:**  
  - `idName` (`string`): The VerusID name (e.g., `"Alice.vrsc@"`).

- **Returns:**  
  - `string`: The hex-encoded i-address hash.

- **Example:**
  ```javascript
  const aliceIdHex = window.verusCrypto.convertIDtoHex("Alice.vrsc@");
  ```

---

#### `generateSpendingKey`

Generates a Sapling extended spending key for a given account.

- **Signature:**  
  `generateSpendingKey(seedHex: string, hdIndex: number): string`

- **Parameters:**  
  - `seedHex` (`string`): The master seed for the wallet
  - `hdIndex` (`number`): The account index to derive

- **Returns:**  
  - `string`: The hex-encoded extended spending key.

- **Example:**
  ```javascript
  const seed = ''.padStart(64, 'a');
  const spendingKey = window.verusCrypto.generateSpendingKey(seed, 0);
  ```

---

#### `zGetEncryptionAddress`

Generates a unique, unlinkable Sapling address and its corresponding Full Viewing Key (FVK) for a specific communication channel.

- **Signature:**  
  `zGetEncryptionAddress(params: object): { address: string, fvk: string, spendingKey?: string }`

- **Parameters:**  
  An object with the following properties:
  - `seed` (`string`, optional): master seed as a hex string.
  - `spendingKey` (`string`, optional): extended spending key as a hex string.
  - `hdIndex` (`number`, optional): Account index to derive from the seed (default: `0`).
  - `encryptionIndex` (`number`, optional): Sub-index for the final channel key (default: `0`).
  - `fromId` (`string`): Senders VerusID identifier as a hex string. (Automatic conversion)
  - `toId` (`string`): Recipient's VerusID as a hex string. (Automatic Conversion)
  - `returnSecret` (`boolean`, optional): If `true`, returns the extended spending key for the channel (default: `false`).

- **Returns:**  
  - `object`: `{ address, fvk, spendingKey? }`

---

#### `encryptMessage`

Encrypts a plaintext message for a given Sapling address.

- **Signature:**  
  `encryptMessage(address: string, message: string, returnSsk: boolean): { ephemeralPublicKey: string, ciphertext: string, symmetricKey?: string }`

- **Parameters:**  
  - `address` (`string`): Recipient's Sapling address.
  - `message` (`string`): Plaintext message to encrypt.
  - `returnSsk` (`boolean`): If `true`, returns the Symmetric Shared Key (SSK).

- **Returns:**  
  - `object`: `{ ephemeralPublicKey, ciphertext, symmetricKey? }`

---

#### `decryptMessage`

Decrypts a ciphertext using either a Full Viewing Key (FVK) or a direct Symmetric Shared Key (SSK).

- **Signature:**  
  `decryptMessage(params: object): string`

- **Parameters:**  
  An object with one of the following combinations:
  - Standard: `{ fvkHex, ephemeralPublicKeyHex, ciphertextHex }`
  - Optional: `{ symmetricKeyHex, ciphertextHex }`

- **Returns:**  
  - `string`: The original plaintext message.



## Licensing

This project is licensed under your choice of either the [MIT License](LICENSES/LICENSE-MIT) or the [Apache License, Version 2.0](LICENSES/LICENSE-APACHE-2.0).