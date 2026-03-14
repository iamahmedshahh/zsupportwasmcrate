import { Buffer } from 'buffer';
import init, { z_get_encryptionaddress, encrypt_v_data, decrypt_v_data } from 'veruszsupport';
import { bech32 } from 'bech32';

interface DerivationKeys {
  seed?:            Buffer;
  spendingKey?:     string;
  hdIndex?:         number;
  encryptionIndex?: number;
  fromId?:          Buffer;  
  toId?:            Buffer;  
  returnSecret?:    boolean;
}

interface ChannelKeys {
  address:Buffer;        
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
  ssk?: Buffer;
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

      const spendingKeyBytes = params.spendingKey
        ? Buffer.from(bech32.fromWords(bech32.decode(params.spendingKey, 1000).words))
        : null;

        const result = z_get_encryptionaddress(
          params.seed            ?? null,
          spendingKeyBytes     ?? null,
          params.hdIndex         ?? null,
          params.encryptionIndex ?? null,
          params.fromId          ?? null,
          params.toId            ?? null,
          params.returnSecret    ?? false
        );

        return {
          address: Buffer.from(result.address),              
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