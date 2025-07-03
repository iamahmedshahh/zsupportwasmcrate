<script setup lang="ts">
import { ref, onMounted } from 'vue';

// 1. Import the new FVK generator function
import init, {
  generate_sapling_address_from_seed,
  generate_sapling_fvk_from_seed, // <-- ADD THIS
  generate_symmetric_key_sender_wasm,
  get_symmetric_key_receiver_wasm,
} from 'zcash_web_crypto_lib';

const wasmInitialized = ref(false);
const seedHex = ref(''.padStart(64, 'a'));
const saplingAddress = ref('');
const error = ref('');

const testInProgress = ref(false);
const testError = ref('');
const testResults = ref<Record<string, any> | null>(null);


// Initialize the WASM module when the component is mounted
onMounted(async () => {
  try {
    await init();
    wasmInitialized.value = true;
    console.log("WASM Initialized in App.vue");
  } catch (e) {
    console.error("Error initializing WASM", e);
    error.value = "Failed to load the crypto module.";
  }
});

function generateAddress() {
  if (!wasmInitialized.value) {
    error.value = "WASM module not ready.";
    return;
  }
  error.value = '';
  saplingAddress.value = '';
  try {
    const address = generate_sapling_address_from_seed(seedHex.value, 0); // Network 1 = Testnet
    saplingAddress.value = address;
  } catch (e) {
    console.error(e);
    error.value = `An error occurred: ${e}`;
  }
}

function getRandomHex(bytes: number): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function runSymmetricKeyTest() {
  if (!wasmInitialized.value) {
    testError.value = "WASM module not ready.";
    return;
  }
  testError.value = '';
  testResults.value = null;
  testInProgress.value = true;

  try {
    const testSeed = getRandomHex(32);
    const networkId = 0; // Mainnet = 0, Testnet = 1

    const address = generate_sapling_address_from_seed(testSeed, networkId);
    
    const fvkStringForTest = generate_sapling_fvk_from_seed(testSeed, networkId);

    const rseed = getRandomHex(32);

    const senderResultJson = generate_symmetric_key_sender_wasm(address, hexToUint8Array(rseed), networkId);
    const senderResult = JSON.parse(senderResultJson);

    const receiverKey = get_symmetric_key_receiver_wasm(
      fvkStringForTest,
      hexToUint8Array(senderResult.ephemeral_public_key),
      networkId
    );

    const keysMatch = senderResult.symmetric_key === receiverKey;

    testResults.value = {
      'Test Seed': testSeed,
      'Derived Address': address,
      'Derived FVK (Hex)': fvkStringForTest,
      'Sender Rseed': rseed,
      '--- Sender Output ---': ' ',
      'Ephemeral Public Key': senderResult.ephemeral_public_key,
      'Sender\'s Symmetric Key': senderResult.symmetric_key,
      '--- Receiver Output ---': ' ',
      'Receiver\'s Symmetric Key': receiverKey,
      '--- Verification ---': ' ',
      'Keys Match?': keysMatch ? '✅ Yes' : '❌ No',
    };

  } catch (e: any) {
    console.error("Symmetric key test failed:", e);
    testError.value = `Test failed: ${e.message || e}`;
  } finally {
    testInProgress.value = false;
  }
}

function hexToUint8Array(hexString: string): Uint8Array {
    if (hexString.length % 2 !== 0) {
        throw "Invalid hexString";
    }
    const arrayBuffer = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
        const byteValue = parseInt(hexString.substr(i, 2), 16);
        if (isNaN(byteValue)) {
            throw "Invalid hexString";
        }
        arrayBuffer[i / 2] = byteValue;
    }
    return arrayBuffer;
}
</script>
<template>

  <div class="wallet-interface">
    <h2>Sapling Address Generator</h2>
    <div v-if="!wasmInitialized" class="loading">Loading Crypto Module...</div>
    <div v-else>
      <div>
        <label for="seed">Seed (64 hex characters):</label>
        <input id="seed" v-model="seedHex" size="70" />
      </div>
      <button @click="generateAddress">Generate Address</button>
      <div v-if="error" class="error">{{ error }}</div>
      <div v-if="saplingAddress" class="result">
        <strong>Generated Testnet Address:</strong>
        <pre>{{ saplingAddress }}</pre>
      </div>
    </div>
  </div>

  <hr>

  <div class="wallet-interface">
    <h2>End-to-End Symmetric Key Test</h2>
    <div v-if="!wasmInitialized" class="loading">Loading Crypto Module...</div>
    <div v-else>
      <button @click="runSymmetricKeyTest" :disabled="testInProgress">
        {{ testInProgress ? 'Running Test...' : 'Run Full Test' }}
      </button>
      <div v-if="testError" class="error">{{ testError }}</div>
      <div v-if="testResults" class="result">
        <strong>Test Results:</strong>
        <pre>{{ JSON.stringify(testResults, null, 2) }}</pre>
      </div>
    </div>
  </div>

</template>

<style scoped>
.logo {
  height: 6em;
  padding: 1.5em;
  will-change: filter;
  transition: filter 300ms;
}
.logo:hover {
  filter: drop-shadow(0 0 2em #646cffaa);
}
.logo.vue:hover {
  filter: drop-shadow(0 0 2em #42b883aa);
}

hr {
  margin: 2em 0;
}
.wallet-interface {
  text-align: left;
  max-width: 600px;
  margin: 2em auto;
  padding: 1em;
  border: 1px solid #ddd;
  border-radius: 8px;
}
.wallet-interface input {
  width: 100%;
  padding: 8px;
  margin: 8px 0;
  box-sizing: border-box;
}
.wallet-interface button {
  padding: 10px 15px;
  cursor: pointer;
}
.wallet-interface button:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}
.error {
  color: red;
  margin-top: 10px;
}
.result {
  margin-top: 10px;
  word-wrap: break-word;
}
.result pre {
  background-color: #000000;
  padding: 10px;
  border-radius: 5px;
  white-space: pre-wrap;
}
</style>