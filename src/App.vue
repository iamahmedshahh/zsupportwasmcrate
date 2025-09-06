<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Buffer } from 'buffer';
(window as any).Buffer = Buffer;

// Interfaces remain the same, but ensure RpcParams has optional IDs
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
interface VerusCryptoAPI {
  generateSpendingKey: (seedHex: string, hdIndex: number) => string;
  zGetEncryptionAddress: (params: RpcParams) => { address: string, fvk: string, spendingKey?: string };
  encryptMessage: (address: string, message: string, returnSsk: boolean) => { ephemeralPublicKey: string, ciphertext: string, symmetricKey?: string };
  decryptMessage: (params: DecryptParams) => string;
  convertIDtoHex: (idName: string) => string;
}

const isApiReady = ref(false);
const testInProgress = ref(false);
const testError = ref('');
const testResults = ref<Record<string, any> | null>(null);

const inputMode = ref('seed');
const seedHex = ref(''.padStart(64, 'a'));
const spendingKeyHex = ref('');
const fromIdName = ref('Alice.vrsc@');
const toIdName = ref('Bob.vrsc@');
const messageToEncrypt = ref('This is a secret message!');
const hdIndex = ref(0);
const encryptionIndex = ref(0);
const returnSecret = ref(false);

const useFromId = ref(true);
const useToId = ref(true);

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

    // NEW: Conditionally convert IDs to hex based on checkbox state
    const fromIdHex = useFromId.value? verusCrypto.convertIDtoHex(fromIdName.value) : undefined;
    const toIdHex = useToId.value? verusCrypto.convertIDtoHex(toIdName.value) : undefined;

    let params: RpcParams;
    if (inputMode.value === 'seed') {
      params = {
        seed: seedHex.value,
        fromId: fromIdHex,
        toId: toIdHex,
        hdIndex: hdIndex.value,
        encryptionIndex: encryptionIndex.value,
        returnSecret: returnSecret.value,
      };
    } else {
      if (!spendingKeyHex.value) throw new Error("Spending key is required for this mode.");
      params = {
        spendingKey: spendingKeyHex.value,
        fromId: fromIdHex,
        toId: toIdHex,
        encryptionIndex: encryptionIndex.value,
        returnSecret: returnSecret.value,
      };
    }

    const channel = verusCrypto.zGetEncryptionAddress(params);

    const encryptedPayload = await verusCrypto.encryptMessage(
      channel.address,
      messageToEncrypt.value,
      true
    );

    const decryptedMessage = await verusCrypto.decryptMessage({
      fvkHex: channel.fvk,
      ephemeralPublicKeyHex: encryptedPayload.ephemeralPublicKey,
      ciphertextHex: encryptedPayload.ciphertext,
    });
    
    const messagesMatch = messageToEncrypt.value === decryptedMessage;
    testResults.value = {
      'Input Mode': inputMode.value,
      '--- Channel Setup ---': '',
      'Using fromId': useFromId.value? fromIdName.value : 'No (null)',
      'Using toId': useToId.value? toIdName.value : 'No (null)',
      'Channel Address': channel.address,
      'Channel FVK': `${channel.fvk.substring(0, 40)}...`,
      'Returned Spending Key': channel.spendingKey? `${channel.spendingKey.substring(0, 40)}...` : 'Not Requested',
      '--- Encryption ---': '',
      'Original Message': messageToEncrypt.value,
      'Returned SSK': `${encryptedPayload.symmetricKey?.substring(0, 40) || 'Not Requested'}...`,
      '--- Decryption ---': '',
      'Decrypted Message': decryptedMessage,
      '--- Verification ---': '',
      'Success?': messagesMatch? ' Yes, messages match!' : ' No, mismatch!',
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
      <label for="spendingKey">Extended Spending Key (Hex):</label>
      <textarea id="spendingKey" v-model="spendingKeyHex" rows="3"></textarea>
      <button @click="generateAndSetSpendingKey" :disabled="!isApiReady">Generate from Seed Above</button>
    </div>

    <div class="input-mode">
        <label>
            <input type="checkbox" v-model="useFromId" /> Include 'From ID'
        </label>
        <label>
            <input type="checkbox" v-model="useToId" /> Include 'To ID'
        </label>
    </div>

    <div v-if="useFromId">
      <label for="fromId">From ID:</label>
      <input id="fromId" v-model="fromIdName" />
    </div>
     <div v-if="useToId">
      <label for="toId">To ID:</label>
      <input id="toId" v-model="toIdName" />
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
    
    <div v-if="testError" class="error"><strong>Error:</strong><pre>{{ testError }}</pre></div>
    <div v-if="testResults" class="result"><strong>Test Results:</strong><pre>{{ JSON.stringify(testResults, null, 2) }}</pre></div>
  </div>
</template>

<style scoped>
/* Styles remain the same */
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