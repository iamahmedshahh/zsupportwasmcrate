import init, {
  z_getencryptionaddress, 
  encrypt_message,
  decrypt_message,
} from 'zcash_web_crypto_lib';

interface ZGetEncryptionAddressParams {
  seed?: string;
  spendingKey?: string;
  hdIndex?: number;
  encryptionIndex?: number;
  fromId: string;
  toId: string;
}

interface DecryptParams {
  fvkHex?: string;
  ephemeralPublicKeyHex?: string;
  ciphertextHex: string;
  symmetricKeyHex?: string;
}

async function initializeApi() {
  try {
    await init();

    const verusCryptoApi = {
      version: '4.0.0', 

      /**
       * Generates a unique, unlinkable Sapling address and its corresponding FVK.
       * This is a flexible API that can derive from a seed or a spending key.
       * @param {object} params - The parameters for key generation.
       * @returns {{address: string, fvk: string}} An object containing the channel's Mainnet address and FVK.
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