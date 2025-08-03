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
interface DecryptParams {
  fvkHex?: string;
  ephemeralPublicKeyHex?: string;
  ciphertextHex: string;
  symmetricKeyHex?: string;
}
interface VerusCryptoAPI {
  generateSpendingKey: (seedHex: string, hdIndex: number) => string;
  zGetEncryptionAddress: (params: RpcParams) => { address: string, fvk: string };
  encryptMessage: (address: string, message: string, returnSsk: boolean) => { ephemeralPublicKey: string, ciphertext: string, symmetricKey?: string };
  decryptMessage: (params: DecryptParams) => string;
}

const isApiReady = ref(false);
const testInProgress = ref(false);
const testError = ref('');
const testResults = ref<Record<string, any> | null>(null);

const inputMode = ref('seed'); // 'seed' or 'spendingKey'
const seedHex = ref(''.padStart(64, 'a'));
const spendingKeyHex = ref('');
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

// function to pre-fill the spending key input for easy testing
function generateAndSetSpendingKey() {
  if (!isApiReady.value) return;
  const verusCrypto = (window as any).verusCrypto as VerusCryptoAPI;
  spendingKeyHex.value = verusCrypto.generateSpendingKey(seedHex.value, hdIndex.value);
}

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

    // construct the parameter object based on the selected input mode
    let params: RpcParams;
    if (inputMode.value === 'seed') {
      params = {
        seed: seedHex.value,
        fromId: fromIdHex.value,
        toId: toIdHex.value,
        hdIndex: hdIndex.value,
        encryptionIndex: encryptionIndex.value,
      };
    } else {
      if (!spendingKeyHex.value) throw new Error("Spending key is required for this mode.");
      params = {
        spendingKey: spendingKeyHex.value,
        fromId: fromIdHex.value,
        toId: toIdHex.value,
        encryptionIndex: encryptionIndex.value,
      };
    }

    // generate the channel keys
    const channel = verusCrypto.zGetEncryptionAddress(params);

    // encrypt a message, requesting the SSK back
    const encryptedPayload = await verusCrypto.encryptMessage(
      channel.address,
      messageToEncrypt.value,
      true // returnSsk = true
    );

    // decrypt the message using the flexible object parameter
    const decryptedMessage = await verusCrypto.decryptMessage({
      fvkHex: channel.fvk,
      ephemeralPublicKeyHex: encryptedPayload.ephemeralPublicKey,
      ciphertextHex: encryptedPayload.ciphertext,
    });
    
    // verify the result and display
    const messagesMatch = messageToEncrypt.value === decryptedMessage;
    testResults.value = {
      'Input Mode': inputMode.value,
      '--- Channel Setup ---': '',
      'Channel Address': channel.address,
      'Channel FVK': `${channel.fvk.substring(0, 40)}...`,
      '--- Encryption ---': '',
      'Original Message': messageToEncrypt.value,
      'Returned SSK': `${encryptedPayload.symmetricKey?.substring(0, 40) || 'Not Requested'}...`,
      'Ciphertext': `${encryptedPayload.ciphertext.substring(0, 40)}...`,
      '--- Decryption ---': '',
      'Decrypted Message': decryptedMessage,
      '--- Verification ---': '',
      'Success?': messagesMatch ? '✅ Yes, messages match!' : '❌ No, mismatch!',
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
    <div v-else class="status ready">✅ API Ready</div>
    
    <div class="input-mode">
      <label><input type="radio" v-model="inputMode" value="seed" /> Use Seed</label>
      <label><input type="radio" v-model="inputMode" value="spendingKey" /> Use Spending Key</label>
    </div>

    <div v-if="inputMode === 'seed'">
      <label for="seed">Master Seed (Hex):</label>
      <input id="seed" v-model="seedHex" size="70" />
    </div>
    <div v-if="inputMode === 'spendingKey'">
      <label for="spendingKey">Extended Spending Key (Hex):</label>
      <textarea id="spendingKey" v-model="spendingKeyHex" rows="3"></textarea>
      <button @click="generateAndSetSpendingKey" :disabled="!isApiReady">Generate from Seed Above</button>
    </div>

    <div>
      <label for="fromId">From ID (Hex):</label>
      <input id="fromId" v-model="fromIdHex" />
    </div>
     <div>
      <label for="toId">To ID (Hex):</label>
      <input id="toId" v-model="toIdHex" />
    </div>
    <div v-if="inputMode === 'seed'">
      <label for="hdIndex">HD Index:</label>
      <input id="hdIndex" type="number" v-model="hdIndex" />
    </div>
    <div>
      <label for="encryptionIndex">Encryption Index:</label>
      <input id="encryptionIndex" type="number" v-model="encryptionIndex" />
    </div>
    <div>
      <label for="message">Message to Encrypt:</label>
      <input id="message" v-model="messageToEncrypt" />
    </div>

    <button @click="runFullTest" :disabled="!isApiReady || testInProgress">
      {{ testInProgress ? 'Running...' : 'Run Full Test' }}
    </button>
    
    <div v-if="testError" class="error"><strong>Error:</strong><pre>{{ testError }}</pre></div>
    <div v-if="testResults" class="result"><strong>Test Results:</strong><pre>{{ JSON.stringify(testResults, null, 2) }}</pre></div>
  </div>
</template>

<style scoped>

.test-interface { max-width: 600px; margin: 2em auto; padding: 1.5em; border: 1px solid #444; border-radius: 8px; }
.status { margin-bottom: 1em; font-weight: bold; }
.pending { color: #f0ad4e; }
.ready { color: #5cb85c; }
.input-mode { margin-bottom: 1em; }
.input-mode label { margin-right: 1em; cursor: pointer; }
input, textarea { width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; background-color: #333; color: #eee; border: 1px solid #555; border-radius: 4px; font-family: monospace; }
textarea { resize: vertical; }
button { padding: 10px 15px; margin-top: 5px; cursor: pointer; border-radius: 5px; border: 1px solid transparent; transition: background-color 0.2s; }
button:disabled { opacity: 0.5; cursor: not-allowed; }
.result, .error { margin-top: 1em; word-wrap: break-word; text-align: left; }
.result pre, .error pre { background-color: #282c34; color: #abb2bf; padding: 10px; border-radius: 5px; white-space: pre-wrap; }
.error pre { color: #ff5555; }
</style>