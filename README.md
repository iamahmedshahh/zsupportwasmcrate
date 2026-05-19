# veruszsupportlib

Sapling encryption and key derivation for Verus DREAM Apps.

WebAssembly powered library exposing three primitives:

- `z_getEncryptionAddress` — derive Sapling channel keys
- `encryptData` — encrypt bytes to a payment address
- `decryptData` — decrypt with viewing key + epk or just symmetric key

## Installation

```bash
yarn add veruszsupportlib
```

## Usage

### Derive channel keys

```typescript
import { z_getEncryptionAddress } from 'veruszsupportlib';

const keys = await z_getEncryptionAddress({
  seed:            seedBytes,        // Uint8Array
  fromId:          fromIdBytes,      // Uint8Array, 20 bytes (hash160)
  toId:            toIdBytes,        // Uint8Array, 20 bytes (hash160)
  encryptionIndex: 0,
});

// keys.address     → Uint8Array, 43 bytes
// keys.ivk         → Uint8Array, 32 bytes
// keys.extfvk      → Uint8Array
// keys.spendingKey → Uint8Array | null
```

### Encrypt data

```typescript
import { encryptData } from 'veruszsupportlib';

const encrypted = await encryptData({
  address: keys.address,
  data:    new TextEncoder().encode('hello'),
});

// encrypted.encryptedData       → Uint8Array
// encrypted.ephemeralPublicKey  → Uint8Array, 32 bytes
// encrypted.symmetricKey        → Uint8Array 169 bytes or null
```

### Decrypt data

Accepts any object with the encrypted fields — automatically picks ivk or ssk:

```typescript
import { decryptData } from 'veruszsupportlib';

const plaintext = await decryptData({
  objectdata: encrypted.encryptedData,
  ivk:        keys.ivk,
  epk:        encrypted.ephemeralPublicKey,
});
```

A `DataDescriptor` from `verus-typescript-primitives` also satisfies the input shape:

```typescript
import { DataDescriptor } from 'verus-typescript-primitives';

const descriptor = new DataDescriptor({
  objectdata: encryptedBytes,
  ivk:        ivkBuffer,
  epk:        epkBuffer,
});

const plaintext = await decryptData(descriptor);
```

## API

### z_getEncryptionAddress(params) → ChannelKeys

| Param           | Type       | Description                          |
|-----------------|------------|--------------------------------------|
| seed            | Uint8Array | Raw seed bytes (optional)            |
| spendingKey     | Uint8Array | 169 byte extended spending key (opt) |
| hdIndex         | number     | HD derivation index (optional)       |
| encryptionIndex | number     | Channel encryption index (optional)  |
| fromId          | Uint8Array | 20 byte hash160 of from VerusID      |
| toId            | Uint8Array | 20 byte hash160 of to VerusID        |
| returnSecret    | boolean    | Return the spending key in result    |

Returns `ChannelKeys` with `address`, `ivk`, `extfvk`, `spendingKey`.

### encryptData(params) → EncryptedPayload

| Param      | Type       | Description                          |
|------------|------------|--------------------------------------|
| address    | Uint8Array | 43 byte Sapling PaymentAddress       |
| data       | Uint8Array | Bytes to encrypt                     |
| returnSsk  | boolean    | Return the symmetric session key if requested    |

Returns `EncryptedPayload` with `encryptedData`, `ephemeralPublicKey`, `symmetricKey`.

### decryptData(descriptor) → Uint8Array

Accepts an object with `objectdata` and either:
- `ivk` (+ optional `epk`) — uses viewing key path
- `ssk` — uses symmetric key path

Returns decrypted bytes.

## Compatibility

| Environment              | Supported |
|--------------------------|-----------|
| Vite / Webpack / Rollup  | Yes       |
| Next.js, Nuxt, SvelteKit | Yes       |
| Node.js 16+              | Yes       |
| Deno, Bun                | Yes       |
| Electron, Tauri          | Yes       |

## License

MIT