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
       * Encrypts a message for a given Sapling address on Mainnet.
       * @param {string} address - The recipient's Sapling address.
       * @param {string} message - The plaintext message to encrypt.
       * @returns {{ephemeralPublicKey: string, ciphertext: string}} An object with the encrypted data.
       */
      encryptMessage: (address: string, message: string) => {
        return encrypt_message(address, message);
      },

      /**
       * Decrypts a message using the recipient's FVK.
       * @param {string} fvkHex - The receiver's hex-encoded DFVK for the channel.
       * @param {string} ephemeralPublicKeyHex - The ephemeral public key from the sender.
       * @param {string} ciphertextHex - The hex-encoded ciphertext to decrypt.
       * @returns {string} The original plaintext message.
       */
      decryptMessage: (fvkHex: string, ephemeralPublicKeyHex: string, ciphertextHex: string): string => {
        return decrypt_message(fvkHex, ephemeralPublicKeyHex, ciphertextHex);
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