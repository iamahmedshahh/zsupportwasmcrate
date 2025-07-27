
import init, {
  generate_channel_keys, 
  encrypt_message,
  decrypt_message,
} from 'zcash_web_crypto_lib';


async function initializeApi() {
  try {
    await init();

    const verusCryptoApi = {
      version: '2.0.0', 

      /**
       * @param {string} seedHex - The user's primary 32-byte seed as a hex string.
       * @param {string} fromIdHex - A unique identifier for the sender as a hex string.
       * @param {string} toIdHex - A unique identifier for the recipient as a hex string.
       * @param {number} networkId - The network ID (0 for Mainnet, 1 for Testnet).
       * @returns {{address: string, fvk: string}} An object containing the channel's address and FVK.
       */
      generateChannelKeys: (seedHex: string, fromIdHex: string, toIdHex: string, networkId: 0 | 1) => {
        const resultJson = generate_channel_keys(seedHex, fromIdHex, toIdHex, networkId);
        return JSON.parse(resultJson as string);
      },

      /**
       * @param {string} address - The recipient's Sapling address (usually from generateChannelKeys).
       * @param {string} message - The plaintext message to encrypt.
       * @param {number} networkId - The network ID.
       * @returns {{ephemeralPublicKey: string, ciphertext: string}} An object with the encrypted data.
       */
      encryptMessage: (address: string, message: string, networkId: 0 | 1) => {
        const resultJson = encrypt_message(address, message, networkId);
        return JSON.parse(resultJson as string);
      },

      /**
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

    console.log(' Verus Crypto API Injected and ready.');

  } catch (e) {
    console.error('Error injecting Verus Crypto API:', e);
  }
}

initializeApi();