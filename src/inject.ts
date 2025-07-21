import init, {
  generate_sapling_address_from_seed,
  generate_sapling_fvk_from_seed,
  generate_symmetric_key_sender_wasm,
  get_symmetric_key_receiver_wasm,
  prepare_handshake,
  verify_handshake,
  derive_encryption_address, 
  encrypt_message,     
  decrypt_message,
} from 'zcash_web_crypto_lib';

/**
 * @param hexString The input hex string.
 * @returns The resulting byte array.
 */
function hexToUint8Array(hexString: string): Uint8Array {
    if (typeof hexString !== 'string' || hexString.length % 2 !== 0) {
        throw new Error("Invalid hexString provided.");
    }
    const arrayBuffer = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
        const byteValue = parseInt(hexString.substr(i, 2), 16);
        if (isNaN(byteValue)) {
            throw new Error("Invalid hexString contains non-hex characters.");
        }
        arrayBuffer[i / 2] = byteValue;
    }
    return arrayBuffer;
}


async function initializeApi() {
  try {
    await init();

    const verusCryptoApi = {
      /**
       * Generates a standard Sapling address.
       */
      generateAddress: (seedHex: string, networkId: 0 | 1): string => {
        return generate_sapling_address_from_seed(seedHex, networkId);
      },

      /**
       * Generates a standard Sapling FVK.
       */
      generateFVK: (seedHex: string, networkId: 0 | 1): string => {
        return generate_sapling_fvk_from_seed(seedHex, networkId);
      },

      /**
       * Generates a symmetric key for a sender.
       */
      generateSenderSymmetricKey: (address: string, rseedHex: string, networkId: 0 | 1) => {
        const rseedBytes = hexToUint8Array(rseedHex);
        const resultJson = generate_symmetric_key_sender_wasm(address, rseedBytes, networkId);
        return JSON.parse(resultJson as string);
      },

      /**
       * Derives a symmetric key for a receiver.
       */
      deriveReceiverSymmetricKey: (fvkHex: string, ephemeralPublicKeyHex: string, networkId: 0 | 1): string => {
        const epkBytes = hexToUint8Array(ephemeralPublicKeyHex);
        return get_symmetric_key_receiver_wasm(fvkHex, epkBytes, networkId);
      },
      
       /**
       * Encrypts a message for a given Sapling address.
       * @param {string} address - The recipient's Sapling address.
       * @param {string} message - The plaintext message to encrypt.
       * @param {number} networkId - The network ID (0 for Mainnet, 1 for Testnet).
       * @returns {{ephemeralPublicKey: string, ciphertext: string}} An object with the encrypted data.
       */
      encryptMessage: (address: string, message: string, networkId: 0 | 1) => {
        const resultJson = encrypt_message(address, message, networkId);
        return JSON.parse(resultJson as string);
      },

      /**
       * Decrypts a message using the recipient's FVK.
       * @param {string} fvkHex - The receiver's hex-encoded Diversifiable Full Viewing Key.
       * @param {string} ephemeralPublicKeyHex - The ephemeral public key from the sender.
       * @param {string} ciphertextHex - The hex-encoded ciphertext to decrypt.
       * @returns {string} The original plaintext message.
       */
      decryptMessage: (fvkHex: string, ephemeralPublicKeyHex: string, ciphertextHex: string): string => {
        return decrypt_message(fvkHex, ephemeralPublicKeyHex, ciphertextHex);
      },

      /**
       * Prepares a handshake challenge.
       */
      prepareHandshake: (seedHex: string, networkId: 0 | 1) => {
        const resultJson = prepare_handshake(seedHex, networkId);
        return JSON.parse(resultJson as string);
      },

      /**
       * Verifies a handshake challenge.
       */
      verifyHandshake: (fvkHex: string, ephemeralPublicKeyHex: string, keyProofHex: string): boolean => {
        return verify_handshake(fvkHex, ephemeralPublicKeyHex, keyProofHex);
      },

      /**
       * @param {string} seedHex - The user's primary 32-byte seed, as a hex string.
       * @param {string} fromIdHex - A unique identifier for the sender (e.g., a VerusID), as a hex string.
       * @param {string} toIdHex - A unique identifier for the recipient (e.g., a VerusID), as a hex string.
       * @param {number} networkId - The network ID (0 for Mainnet, 1 for Testnet).
       * @returns {string} The derived single-purpose encryption address.
       */
      deriveEncryptionAddress: (seedHex: string, fromIdHex: string, toIdHex: string, networkId: 0 | 1): string => {
        return derive_encryption_address(seedHex, fromIdHex, toIdHex, networkId);
      }
    };

    (window as any).verusCrypto = verusCryptoApi;

    window.dispatchEvent(new CustomEvent('verusCryptoReady'));

    console.log('Verus Crypto API Injected and ready.');

  } catch (e) {
    console.error(' Error injecting Verus Crypto API:', e);
  }
}

initializeApi();