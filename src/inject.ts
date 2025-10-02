import { Buffer } from 'buffer';
import init, {
  z_getencryptionaddress, 
  encrypt_message,
  decrypt_message,
  generate_spending_key
} from 'veruszsupport';


interface ZGetEncryptionAddressParams {
  seed?: string;
  spendingKey?: string;
  hdIndex?: number;
  encryptionIndex?: number;
  fromId?: string;
  toId?: string;
  returnSecret?: boolean;
}

interface DecryptParams {
  fvkHex?: string;
  ephemeralPublicKeyHex?: string;
  ciphertextHex: string;
  symmetricKeyHex?: string;
}

async function initializeApi() {
  try {
    (window as any).Buffer = Buffer;
    await init();
    const verusCryptoApi = {
      version: '4.0.0', 

      /**
       * Generates a hex-encoded Sapling extended spending key for a given account.
       * @param {string} seedHex - The master seed for the wallet.
       * @param {number} hdIndex - The account index to derive.
       * @returns {string} The hex-encoded extended spending key.
       */
      generateSpendingKey: (seedHex: string, hdIndex: number): string => {
        return generate_spending_key(seedHex, hdIndex);
      },
      
    /**
     * ...
     * @param {object} params - The parameters for key generation. `params.spendingKey` must be a bech32-encoded string.
     * @returns {ChannelKeys} An object containing the address and various key formats.
     */
      zGetEncryptionAddress: (params: ZGetEncryptionAddressParams) => {
        return z_getencryptionaddress(params);
      },

      /**
       * Encrypts a message for a given Sapling address.
       * @param {string} address - The recipient's Sapling address.
       * @param {string} message - The plaintext message to encrypt.
       * @param {boolean} returnSsk - If true, the final symmetric key will be returned.
       * @returns {{ephemeralPublicKey: string, ciphertext: string, symmetricKey?: string}}
       */
      encryptMessage: (address: string, message: string, returnSsk: boolean) => {
        return encrypt_message(address, message, returnSsk);
      },

      /**
       * Decrypts a message using either an FVK or a direct symmetric key.
       * @param {DecryptParams} params - The parameters for decryption.
       * @returns {string} The original plaintext message.
       */
      decryptMessage: (params: DecryptParams): string => {
        return decrypt_message(params);
      },
    };


    (window as any).verusCrypto = verusCryptoApi;
    window.dispatchEvent(new CustomEvent('verusCryptoReady'));
    console.log('Verus Crypto API Injected and ready.');

  } catch (e) {
    console.error(' Error injecting Verus Crypto API:', e);
  }
}

initializeApi();