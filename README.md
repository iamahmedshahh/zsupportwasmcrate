## Verus Encrypted Channel Key Derivation, Encryption and Decryption Extension

This extension provides functions, written in Rust and compiled to WebAssembly (WASM), for use in a modern web applications.

The core Rust crate, `veruszsupport`, handles Zcash Sapling key generation and symmetric key derivation, exposed via Chrome extension that injects a global API into web pages. 

This project's core logic is written in Rust which is then transalated into a wasm compatible code in Rust under veruszsupportweb library

See the `Test Web App` Section.

#### Core Logic:


https://github.com/iamahmedshahh/librustzcash/blob/ka_agree-security-fixes-updates/verus_zfunc/src/lib.rs


---

## Prerequisites

Before you begin, ensure you have the following tools installed:

- **Rust:** https://www.rust-lang.org/tools/install
- **wasm-pack:** `cargo install wasm-pack`
- **Rustup:** `sudo apt install rustup`
- **Must Install:** `npm install vite-plugin-node-polyfills`

---

## Project Structure

- **/veruszsupportweb/**: The native Rust crate containing all core cryptographic logic and WASM bindings.
- **zsupport (root)**: The Vue.js + TypeScript frontend application and Chrome extension that consumes the WASM module.
- **src/inject.ts**: Injected script that exposes `window.verusCrypto` API to web pages.
- **src/App.vue**: Test web page for generating AppEncryptionRequest QR codes.
- **proxy.ts**: Node.js proxy server that forwards RPC calls to verusd (required for CORS).

---

## Development Workflow

### 1. Build the WebAssembly Module
```bash
cd veruszsupportweb
wasm-pack build --target web --release --out-dir pkg
```

### 2. Integrate WASM with the Vue Project
```bash
yarn install ./veruszsupportweb/pkg
```

Re-run this every time you rebuild the WASM package.

### 3. Build the Extension
```bash
yarn install
yarn build
```

### 4. Load the Extension in Chrome
```
Go to chrome://extensions/
Enable Developer Mode
Click "Load unpacked" and select the dist folder
```

### 5. Run the Test Web App
```bash
yarn dev
```

Open the URL shown in terminal (e.g. `http://localhost:5173/`).

### 6. Run the verusd RPC Proxy

The test web app cannot call verusd directly due to CORS. A proxy server is required.
```bash
npx tsx proxy.ts
```

This starts a proxy on `http://localhost:27487` that forwards all RPC calls to verusd on port `27486`. Set the port to `27487` in the App.vue RPC config panel.

---

## Exposed APIs

The extension injects a global API at `window.verusCrypto`. Wait for the `verusCryptoReady` event before accessing it.

All functions operate on raw `Buffer` types at the boundary. Callers are responsible for encoding/decoding (bech32, hex) as needed.
```javascript
window.addEventListener('verusCryptoReady', () => {
  const verusCrypto = window.verusCrypto;
});
```

---

### `zGetEncryptionAddress`

Derives a deterministic Sapling z-address and associated keys for an encrypted communication channel between two VerusIDs.

**Signature:**
```typescript
zGetEncryptionAddress(params: {
  seed?:            Buffer;   // master seed bytes — provide seed OR spendingKey
  spendingKey?:     string;   // bech32 "secret-extended-key-main1..." 
  hdIndex?:         number;   // HD account index (default: 0, seed mode only)
  encryptionIndex?: number;   // channel sub-index (default: 0)
  fromId?:          Buffer;   // sender VerusID as raw hash160 bytes
  toId?:            Buffer;   // recipient VerusID as raw hash160 bytes
  returnSecret?:    boolean;  // if true, returns the channel spending key (default: false)
}): {
  address:     Buffer;         // raw 43-byte Sapling payment address
  ivk:         Buffer;         // 32-byte incoming viewing key
  extfvk:      Buffer;         // 169-byte extended full viewing key
  spendingKey: Buffer | null;  // 169-byte extended spending key, or null
}
```

**Example:**
```javascript
const { decodeDestination } = require('verus-typescript-primitives');
const { SaplingPaymentAddress } = require('verus-typescript-primitives');

const fromIdBytes = Buffer.from(decodeDestination('alice@'));
const toIdBytes   = Buffer.from(decodeDestination('bob@'));

const keys = window.verusCrypto.zGetEncryptionAddress({
  seed:            Buffer.from('aa'.repeat(32), 'hex'),
  encryptionIndex: 0,
  fromId:          fromIdBytes,
  toId:            toIdBytes,
});

// Convert raw address to bech32 string for display
const addr = new SaplingPaymentAddress();
addr.fromBuffer(keys.address);
console.log('Channel address:', addr.toAddressString()); // "zs1..."
console.log('IVK (hex):', keys.ivk.toString('hex'));
```

---

### `encryptData`

Encrypts arbitrary bytes for a given Sapling address.

**Signature:**
```typescript
encryptData(params: {
  address:         Buffer;   // raw 43-byte Sapling payment address
  data_to_encrypt: Buffer;   // data to encrypt
  returnSsk?:      boolean;  // if true, returns the symmetric session key (default: false)
}): {
  ephemeralPublicKey: Buffer;        // 32-byte EPK
  encrypted_data:     Buffer;        // ciphertext bytes
  symmetricKey:       Buffer | null; // symmetric session key, or null
}
```

**Example:**
```javascript
const encrypted = window.verusCrypto.encryptData({
  address:         keys.address,
  data_to_encrypt: Buffer.from('hello world'),
  returnSsk:       true,
});

console.log('EPK:', encrypted.ephemeralPublicKey.toString('hex'));
console.log('Encrypted Data:', encrypted.encrypted_data.toString('hex'));
```

---

### `decryptData`

Decrypts data using either IVK + EPK or a symmetric session key directly.

**Signature:**
```typescript
decryptData(params: {
  ivk?:            Buffer;  // 32-byte incoming viewing key (use with epk)
  epk?:            Buffer;  // 32-byte ephemeral public key (use with ivk)
  data_to_decrypt: Buffer;  // encrypted data bytes
  ssk?:            Buffer;  // symmetric session key — if provided, ivk and epk are ignored
}): Buffer  // decrypted plaintext bytes
```

**Example:**
```javascript
// Decrypt using IVK + EPK
const decryptedData = window.verusCrypto.decryptData({
  ivk:            keys.ivk,
  epk:            encrypted.ephemeralPublicKey,
  data_to_decrypt: encrypted.encrypted_data,
});

// Or decrypt using SSK directly
const decryptedData = window.verusCrypto.decryptData({
  ssk:            encrypted.symmetricKey,
  data_to_decrypt: encrypted.encrypted_data,
});

console.log('Decrypted:', plaintext.toString());
```

---

## Test Web App (App.vue)

The test web app at `http://localhost:5173/` derives channel keys by calling the extension which are then used to generate a signed `AppEncryptionRequest` as a QR code and deeplink that can be scanned by Verus Mobile

### How it works

1. **Key Derivation** — Calls `window.verusCrypto.zGetEncryptionAddress` via the injected extension API. Provide either a hex seed or a bech32 spending key, along with `fromId` and `toId` VerusID addresses. The extension WASM derives the channel keys deterministically.

2. **Request Building** — Constructs an `AppEncryptionRequestDetails` with the derived channel address as `encryptResponseToAddress`. Wraps it in a `GenericRequest` alongside an `AuthenticationRequest`.

3. **Signing** — Calls `signdata` RPC on verusd (via the proxy on port `27487`) with the request's SHA256 hash. The signature is attached to the request.

4. **QR Generation** — Encodes the signed request as a `verus://` deeplink and renders it as a QR code.

### Running the full test
```bash
# Terminal 1 — start verusd
verusd &

# Terminal 2 — start the RPC proxy (bridges browser → verusd, handles CORS)
npx tsx proxy.ts
# proxy running on http://localhost:27487 → verusd at localhost:27486

# Terminal 3 — start the test web app
yarn dev

# Terminal 4 — build and load extension in Chrome
yarn build
# Load dist/ as unpacked extension in chrome://extensions/
```

Then open `http://localhost:5173/`, fill in the Signing Identity field with a VerusID loaded in your verusd wallet, and click **Derive → Build → Sign → QR**. Scan the QR with Verus Mobile.

---

## Licensing

This project is licensed under your choice of either the [MIT License](LICENSES/LICENSE-MIT) or the [Apache License, Version 2.0](LICENSES/LICENSE-APACHE-2.0).