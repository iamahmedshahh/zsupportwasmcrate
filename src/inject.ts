import { Buffer } from 'buffer';
import init, { z_get_encryptionaddress, encrypt_v_data, decrypt_v_data } from 'veruszsupport';

// ── Types — all bytes, no strings ──────────────────────────────

interface DerivationKeys {
  seed?:            Buffer;
  spendingKey?:     Buffer;
  hdIndex?:         number;
  encryptionIndex?: number;
  fromId?:          Buffer;  // caller should resolve them  toiAddress if needed, it should be acceptable as a buffer as a buffer 
  toId?:            Buffer;  
  returnSecret?:    boolean;
}

interface ChannelKeys {
  address:Buffer;        // caller can resolve to SaplingPaymentAddress.frombuffer and then toString if needed anywhere
  ivk:Buffer;        
  extfvk:Buffer;        
  spendingKey?: Buffer | null;
}

interface EncryptParams {
  address: Buffer;  
  data_to_encrypt: Buffer;
  returnSsk?: boolean;
}

interface EncryptedPayload {
  ephemeralPublicKey: Buffer;  
  encrypted_data: Buffer;
  symmetricKey?: Buffer | null;
}

interface DecryptParams {
  ivk?: Buffer;  
  epk?: Buffer;  
  data_to_decrypt: Buffer;
  ssk?: Uint8Array;
}


async function initializeApi() {
  try {
    (window as any).Buffer = Buffer;
    await init();

    const verusCryptoApi = {
      version: '5.0.0',

      /**
       * Derives channel keys.
       */
      zGetEncryptionAddress: (params: DerivationKeys): ChannelKeys => {
        const result = z_get_encryptionaddress(
          params.seed            ?? null,
          params.spendingKey     ?? null,
          params.hdIndex         ?? null,
          params.encryptionIndex ?? null,
          params.fromId          ?? null,
          params.toId            ?? null,
          params.returnSecret    ?? false
        );

        return {
          address:    Buffer.from(result.address),              
          ivk:        Buffer.from(result.ivk),             
          extfvk:     Buffer.from(result.extfvk),          
          spendingKey: result.spendingKey
            ? Buffer.from(result.spendingKey) : null,      
        };
      },

      /**
       * Encrypts data bytes
       */
      encryptData: (params: EncryptParams): EncryptedPayload => {

        const result = encrypt_v_data(
          params.address,
          params.data_to_encrypt,
          params.returnSsk ?? false
        );

        return {
          ephemeralPublicKey: Buffer.from(result.ephemeralPublicKey),
          encrypted_data:     Buffer.from(result.encryptedData),
          symmetricKey: result.symmetricKey
            ? Buffer.from(result.symmetricKey) : null,
        };
      },

      /**
       * Decrypts encrypted data
       */
      decryptData: (params: DecryptParams): Buffer => {
        return Buffer.from(decrypt_v_data(
          params.ivk  ?? null,
          params.epk  ?? null,
          params.data_to_decrypt,
          params.ssk  ?? null,
        ));
      },
    };

    (window as any).verusCrypto = verusCryptoApi;
    window.dispatchEvent(new CustomEvent('verusCryptoReady'));

  } catch (e) {
    console.error('Error injecting Verus Crypto API:', e);
  }
}

initializeApi();