<script setup lang="ts">
import { ref, onMounted } from 'vue';

interface RpcParams {
  seed?: string;
  spendingKey?: string;
  hdIndex?: number;
  encryptionIndex?: number;
  fromId: string;
  toId: string;
}

interface VerusCryptoAPI {
  zGetEncryptionAddress: (params: RpcParams) => { address: string, fvk: string };
  encryptMessage: (address: string, message: string) => { ephemeralPublicKey: string, ciphertext: string };
  decryptMessage: (fvkHex: string, ephemeralPublicKeyHex: string, ciphertextHex: string) => string;
}

const isApiReady = ref(false);
const testInProgress = ref(false);
const testError = ref('');
const testResults = ref<Record<string, any> | null>(null);

// Inputs for the test
const seedHex = ref(''.padStart(64, 'a'));
const fromIdHex = ref('616c69636540'); // "alice@" in hex
const toIdHex = ref('626f6240');     // "bob@" in hex
const messageToEncrypt = ref('This is a secret message!');
const hdIndex = ref(0);
const encryptionIndex = ref(0);

onMounted(() => {
  const setupApi = () => {
    if ((window as any).verusCrypto) {
      isApiReady.value = true;
    }
  };
  window.addEventListener('verusCryptoReady', setupApi);
  setupApi();
});

// 2. Update the test function to use the new object-based parameters
async function runFullTest() {
  if (!isApiReady.value) {
    testError.value = "API is not ready.";
    return;
  }
  
  testError.value = '';
  testResults.value = null;
  testInProgress.value = true;

  try {
    const verusCrypto = (window as any).verusCrypto as VerusCryptoAPI;

    // Construct the parameter object
    const params: RpcParams = {
      seed: seedHex.value,
      fromId: fromIdHex.value,
      toId: toIdHex.value,
      hdIndex: hdIndex.value,
      encryptionIndex: encryptionIndex.value,
    };

    // Generate the channel keys using the new method
    const channel = verusCrypto.zGetEncryptionAddress(params);

    // Encrypt a message using the channel's address
    const encryptedPayload = await verusCrypto.encryptMessage(
      channel.address,
      messageToEncrypt.value
    );

    // Decrypt the message using the channel's FVK
    const decryptedMessage = await verusCrypto.decryptMessage(
      channel.fvk,
      encryptedPayload.ephemeralPublicKey,
      encryptedPayload.ciphertext
    );

    // Verify the result and display
    const messagesMatch = messageToEncrypt.value === decryptedMessage;
    testResults.value = {
      '--- Channel Setup ---': '',
      'Channel Address': channel.address,
      'Channel FVK': `${channel.fvk.substring(0, 40)}...`,
      '--- Encryption ---': '',
      'Original Message': messageToEncrypt.value,
      'Ciphertext': `${encryptedPayload.ciphertext.substring(0, 40)}...`,
      '--- Decryption ---': '',
      'Decrypted Message': decryptedMessage,
      '--- Verification ---': '',
      'Success?': messagesMatch ? ' Yes, messages match!' : ' No, messages do not match!',
    };

  } catch (e: any) {
    console.error("Test failed:", e);
    testError.value = e.message || 'An unknown error occurred.';
  } finally {
    testInProgress.value = false;
  }
}
</script>

<template>
  <div class="test-interface">
    <h2>Verus-Style End-to-End Encryption Test</h2>
    <div v-if="!isApiReady" class="status pending">Waiting for Verus Crypto API...</div>
    <div v-else class="status ready"> API Ready</div>
    
    <div>
      <label for="seed">Master Seed:</label>
      <input id="seed" v-model="seedHex" size="70" />
    </div>
    <div>
      <label for="fromId">From ID (Hex):</label>
      <input id="fromId" v-model="fromIdHex" />
    </div>
     <div>
      <label for="toId">To ID (Hex):</label>
      <input id="toId" v-model="toIdHex" />
    </div>
    <div>
      <label for="hdIndex">HD Index (for initial derivation):</label>
      <input id="hdIndex" type="number" v-model="hdIndex" />
    </div>
    <div>
      <label for="encryptionIndex">Encryption Index (for final derivation):</label>
      <input id="encryptionIndex" type="number" v-model="encryptionIndex" />
    </div>
    <div>
      <label for="message">Message to Encrypt:</label>
      <input id="message" v-model="messageToEncrypt" />
    </div>

    <button @click="runFullTest" :disabled="!isApiReady || testInProgress">
      {{ testInProgress ? 'Running...' : 'Run Full Test' }}
    </button>
    
    <div v-if="testError" class="error">
      <strong>Error:</strong>
      <pre>{{ testError }}</pre>
    </div>

    <div v-if="testResults" class="result">
      <strong>Test Results:</strong>
      <pre>{{ JSON.stringify(testResults, null, 2) }}</pre>
    </div>
  </div>
</template>

<style scoped>
.test-interface { max-width: 600px; margin: 2em auto; padding: 1.5em; border: 1px solid #444; border-radius: 8px; }
.status { margin-bottom: 1em; font-weight: bold; }
.pending { color: #f0ad4e; }
.ready { color: #5cb85c; }
input { width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; background-color: #333; color: #eee; border: 1px solid #555; border-radius: 4px; }
button { padding: 10px 15px; cursor: pointer; border-radius: 5px; border: 1px solid transparent; transition: background-color 0.2s; }
button:disabled { opacity: 0.5; cursor: not-allowed; }
.result, .error { margin-top: 1em; word-wrap: break-word; text-align: left; }
.result pre, .error pre { background-color: #282c34; color: #abb2bf; padding: 10px; border-radius: 5px; white-space: pre-wrap; }
.error pre { color: #ff5555; }
</style>