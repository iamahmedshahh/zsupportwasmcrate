
import init, {
  generate_sapling_address_from_seed,
  generate_sapling_fvk_from_seed,
  generate_symmetric_key_sender_wasm,
  get_symmetric_key_receiver_wasm,
  prepare_handshake,
  verify_handshake,
} from 'zcash_web_crypto_lib';

/**
 * @param {string} hexString The input hex string.
 * @returns {Uint8Array} The resulting byte array.
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
       * @param {string} seedHex - A 64-character hexadecimal string representing a 32-byte seed.
       * @param {number} networkId - The network ID (0 for Mainnet, 1 for Testnet).
       * @returns {string} The generated Sapling address.
       */
      generateAddress: (seedHex: string, networkId: 0 | 1): string => {
        return generate_sapling_address_from_seed(seedHex, networkId);
      },

      /**
       * @param {string} seedHex - A 64-character hexadecimal string representing a 32-byte seed.
       * @param {number} networkId - The network ID (0 for Mainnet, 1 for Testnet).
       * @returns {string} The hex-encoded Diversifiable Full Viewing Key.
       */
      generateFVK: (seedHex: string, networkId: 0 | 1): string => {
        return generate_sapling_fvk_from_seed(seedHex, networkId);
      },

      /**
       * @param {string} address - The recipient's Sapling address.
       * @param {string} rseedHex - A 64-character hexadecimal string for the note's randomness.
       * @param {number} networkId - The network ID (0 for Mainnet, 1 for Testnet).
       * @returns {{symmetricKey: string, ephemeralPublicKey: string}} An object containing the hex-encoded keys.
       */
      generateSenderSymmetricKey: (address: string, rseedHex: string, networkId: 0 | 1) => {
        const rseedBytes = hexToUint8Array(rseedHex);
        const resultJson = generate_symmetric_key_sender_wasm(address, rseedBytes, networkId);
        return JSON.parse(resultJson as string);
      },

      /**
       * @param {string} fvkHex - The receiver's hex-encoded Diversifiable Full Viewing Key.
       * @param {string} ephemeralPublicKeyHex - The ephemeral public key from the sender.
       * @param {number} networkId - The network ID (0 for Mainnet, 1 for Testnet).
       * @returns {string} The derived hex-encoded symmetric key.
       */
      deriveReceiverSymmetricKey: (fvkHex: string, ephemeralPublicKeyHex: string, networkId: 0 | 1): string => {
        const epkBytes = hexToUint8Array(ephemeralPublicKeyHex);
        return get_symmetric_key_receiver_wasm(fvkHex, epkBytes, networkId);
      },
      
      /**
       * Prepares a handshake from the extension's.
       * @param {string} seedHex - The seed representing the extension's identity.
       * @param {number} networkId - The network ID.
       * @returns {{ephemeralPublicKey: string, keyProof: string}} A challenge object.
       */
      prepareHandshake: (seedHex: string, networkId: 0 | 1) => {
        const resultJson = prepare_handshake(seedHex, networkId);
        return JSON.parse(resultJson as string);
      },

      /**
       * Verifies a handshake.
       * @param {string} fvkHex - The FVK corresponding to the seed used in prepareHandshake.
       * @param {string} ephemeralPublicKeyHex - The ephemeral public key from the challenge.
       * @param {string} keyProofHex - The key proof hash from the challenge.
       * @returns {boolean} True if the handshake is successful, false otherwise.
       */
      verifyHandshake: (fvkHex: string, ephemeralPublicKeyHex: string, keyProofHex: string): boolean => {
        return verify_handshake(fvkHex, ephemeralPublicKeyHex, keyProofHex);
      },
    };

    (window as any).verusCrypto = verusCryptoApi;

    window.dispatchEvent(new CustomEvent('verusCryptoReady'));

    console.log('Verus Crypto API Injected and ready.');

  } catch (e) {
    console.error('Error injecting Verus Crypto API:', e);
  }
}

initializeApi();