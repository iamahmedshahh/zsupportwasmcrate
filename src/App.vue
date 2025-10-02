<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Buffer } from 'buffer';
(window as any).Buffer = Buffer;

interface RpcParams {
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

interface ChannelKeys {
  address: string;
  fvk: string;
  fvkHex: string;
  dfvkHex: string; 
  spendingKey?: string;
  ivk?: string;
}

interface VerusCryptoAPI {
  generateSpendingKey: (seedHex: string, hdIndex: number) => string;
  zGetEncryptionAddress: (params: RpcParams) => ChannelKeys;
  encryptMessage: (address: string, message: string, returnSsk: boolean) => { ephemeralPublicKey: string, ciphertext: string, symmetricKey?: string };
  decryptMessage: (params: DecryptParams) => string;
}

const isApiReady = ref(false);
const testInProgress = ref(false);
const testError = ref<{ title: string; message: string } | null>(null);
const testResults = ref<Record<string, any> | null>(null);

const inputMode = ref('seed');
const seedHex = ref(''.padStart(64, 'a'));
const spendingKeyInput = ref(''); 
const messageToEncrypt = ref('This is a secret message!');
const hdIndex = ref(0);
const encryptionIndex = ref(0);
const returnSecret = ref(false);

onMounted(() => {
  const setupApi = () => {
    if ((window as any).verusCrypto) {
      isApiReady.value = true;
    }
  };
  window.addEventListener('verusCryptoReady', setupApi);
  setupApi();
});

function generateAndSetSpendingKey() {
  if (!isApiReady.value) return;
  const verusCrypto = (window as any).verusCrypto as VerusCryptoAPI;

  alert('Generated HEX spending key. You must convert it to bech32 to use it in the test below.');
  spendingKeyInput.value = verusCrypto.generateSpendingKey(seedHex.value, hdIndex.value);
}

async function runFullTest() {
  if (!isApiReady.value) {
    testError.value = { title: "API Error", message: "API is not ready." };
    return;
  }
  
  testError.value = null;
  testResults.value = null;
  testInProgress.value = true;

  try {
    const verusCrypto = (window as any).verusCrypto as VerusCryptoAPI;
    let baseParams = {
      encryptionIndex: encryptionIndex.value,
      returnSecret: returnSecret.value,
      fromId: '237cc65dbb032174f0133e2f450f9afb5645e715',
      toId: 'ac57fe88ff9dbcc6562196fc6ba426d35d638366',
    };

    let params: RpcParams;

    if (inputMode.value === 'seed') {
      params = {
        ...baseParams,
        seed: seedHex.value,
        hdIndex: hdIndex.value,
      };
    } else {
      if (!spendingKeyInput.value) throw new Error("Spending key is required for this mode.");
      params = {
        ...baseParams,
        spendingKey: spendingKeyInput.value,
      };
    }

    const channel = verusCrypto.zGetEncryptionAddress(params);

    const encryptedPayload = verusCrypto.encryptMessage(
      channel.address,
      messageToEncrypt.value,
      true // Requesting SSK for completeness, though not used in decryption test
    );

    // FIX: Use the correct key format for decryption (`channel.fvkHex`)
    const decryptedMessage = verusCrypto.decryptMessage({
      fvkHex: channel.dfvkHex, // <-- This was the critical bug
      ephemeralPublicKeyHex: encryptedPayload.ephemeralPublicKey,
      ciphertextHex: encryptedPayload.ciphertext,
    });
    
    const messagesMatch = messageToEncrypt.value === decryptedMessage;
    testResults.value = {
      'Input Mode': inputMode.value,
      '--- Channel Setup ---': '',
      'Channel Address': channel.address,
      'Channel XFVK (Bech32)': `${channel.fvk.substring(0, 40)}...`,
      'Channel DFVK (Hex)': `${channel.dfvkHex.substring(0, 40)}...`, 
      'Returned IVK (Hex)': `${channel.ivk?.substring(0, 40)}...`,
      'Returned Spending Key': channel.spendingKey ? `${channel.spendingKey.substring(0, 40)}...` : 'Not Requested',
      '--- Encryption & Decryption ---': '',
      'Original Message': messageToEncrypt.value,
      'Decrypted Message': decryptedMessage,
      '--- Verification ---': '',
      'Success?': messagesMatch ? '✅ Yes, messages match!' : '❌ No, mismatch!',
    };

  } catch (e: any) {
    console.error("Test failed:", e);
    testError.value = { title: "Runtime Error", message: e.message || 'An unknown error occurred.' };
  } finally {
    testInProgress.value = false;
  }
}
</script>

<template>
  <div class="test-interface">
    <h2>Verus-Style End-to-End Encryption Test</h2>
    <div v-if="!isApiReady" class="status pending">Waiting for Verus Crypto API...</div>
    <div v-else class="status ready">API Ready</div>
    
    <div class="input-mode">
      <label><input type="radio" v-model="inputMode" value="seed" /> Use Seed</label>
      <label><input type="radio" v-model="inputMode" value="spendingKey" /> Use Spending Key</label>
    </div>

    <div v-if="inputMode === 'seed'">
      <label for="seed">Master Seed (Hex):</label>
      <input id="seed" v-model="seedHex" size="70" />
    </div>
    <div v-if="inputMode === 'spendingKey'">
      <label for="spendingKey">Extended Spending Key (Bech32):</label>
      <textarea id="spendingKey" v-model="spendingKeyInput" rows="3"></textarea>
      <button @click="generateAndSetSpendingKey" :disabled="!isApiReady">Generate from Seed Above (Hex)</button>
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

    <div class="input-mode">
        <label>
            <input type="checkbox" v-model="returnSecret" /> Return Private Spending Key
        </label>
    </div>

    <button @click="runFullTest" :disabled="!isApiReady || testInProgress">
      {{ testInProgress? 'Running...' : 'Run Full Test' }}
    </button>
    
    <div v-if="testError" class="error"><strong>Error:</strong><pre>{{ testError.title }}: {{ testError.message }}</pre></div>
    <div v-if="testResults" class="result"><strong>Test Results:</strong><pre>{{ JSON.stringify(testResults, null, 2) }}</pre></div>
  </div>
</template>

<style scoped>
.test-interface { max-width: 600px; margin: 2em auto; padding: 1.5em; border: 1px solid #444; border-radius: 8px; }
.status { margin-bottom: 1em; font-weight: bold; }
.pending { color: #f0ad4e; }
.ready { color: #5cb85c; }
.input-mode { margin: 1em 0; }
.input-mode label { margin-right: 1em; cursor: pointer; }
input, textarea { width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; background-color: #333; color: #eee; border: 1px solid #555; border-radius: 4px; font-family: monospace; }
textarea { resize: vertical; }
button { padding: 10px 15px; margin-top: 5px; cursor: pointer; border-radius: 5px; border: 1px solid transparent; transition: background-color 0.2s; }
button:disabled { opacity: 0.5; cursor: not-allowed; }
.result,.error { margin-top: 1em; word-wrap: break-word; text-align: left; }
.result pre,.error pre { background-color: #282c34; color: #abb2bf; padding: 10px; border-radius: 5px; white-space: pre-wrap; }
.error pre { color: #ff5555; }
</style>