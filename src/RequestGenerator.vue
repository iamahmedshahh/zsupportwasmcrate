<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Buffer } from 'buffer';
import {
  BigNumber,
  toIAddress,
  decodeDestination,
  SaplingPaymentAddress,
  CompactIAddressObject,
  AppEncryptionRequestDetails,
  AppEncryptionRequestOrdinalVDXFObject,
  AuthenticationRequestDetails,
  AuthenticationRequestOrdinalVDXFObject,
  VerifiableSignatureData,
} from 'verus-typescript-primitives';
import { primitives } from 'verusid-ts-client';
import { bech32 } from 'bech32';


(window as any).Buffer = Buffer;

interface ChannelKeys {
  address:    Buffer;
  ivk:        Buffer;
  extfvk:     Buffer;
  spendingKey?: Buffer | null;
}

interface VerusCryptoAPI {
  zGetEncryptionAddress: (params: any) => ChannelKeys;
}

const isApiReady  = ref(false);
const isLoading   = ref(false);
const error       = ref<string | null>(null);
const copied      = ref(false);
const step        = ref<'idle' | 'derived' | 'signed' | 'done'>('idle');

const rpcHost     = ref('localhost');
const rpcPort     = ref(27487);
const rpcUser     = ref('user');
const rpcPass     = ref('pass');
const systemID    = ref('i5w5MuNik5NtLcYmNzcvaoixooEebB6MGV');
const signingID   = ref('');

const inputMode       = ref<'seed' | 'spendingKey'>('seed');
const seedHex         = ref('aa'.repeat(32))
const spendingKeyInput  = ref('');
const hdIndex         = ref(0);
const encryptionIndex = ref(0);
const fromIdInput     = ref('i94XrwNp9cMghEZ16fq7Fcd3XE57VNBWvo');
const toIdInput       = ref('i94XrwNp9cMghEZ16fq7Fcd3XE57VNBWvo');
const derivationNumber = ref(0);
const derivationID     = ref('');
const requestID        = ref('');
const returnEsk        = ref(false);
const skipEncryption   = ref(false);

const channelKeys  = ref<ChannelKeys | null>(null);
const deeplinkUri  = ref<string | null>(null);
const qrDataUrl    = ref<string | null>(null);
const statusLog    = ref<string[]>([]);

const log = (msg: string) => statusLog.value.push(msg);

const resolveId = (id: string): Uint8Array => {
  if (id.startsWith('i') && id.length > 30)
    return new Uint8Array(decodeDestination(id));
  return new Uint8Array(decodeDestination(toIAddress(id, 'VRSC')));
};

async function generateQR(text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const render = () => {
      const div = document.createElement('div');
      div.style.cssText = 'position:fixed;top:-9999px;left:-9999px;';
      document.body.appendChild(div);
      new (window as any).QRCode(div, {
        text, width: 280, height: 280,
        colorDark: '#00ff88', colorLight: '#0a0a0a',
        correctLevel: (window as any).QRCode.CorrectLevel.M,
      });
      setTimeout(() => {
        const canvas = div.querySelector('canvas') as HTMLCanvasElement;
        const img    = div.querySelector('img') as HTMLImageElement;
        document.body.removeChild(div);
        if (canvas) resolve(canvas.toDataURL());
        else if (img?.src) resolve(img.src);
        else reject(new Error('QR render failed'));
      }, 400);
    };
    if ((window as any).QRCode) { render(); return; }
    const s = document.createElement('script');
    s.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
    s.onload = render;
    s.onerror = () => reject(new Error('Failed to load QR library'));
    document.head.appendChild(s);
  });
  
}
async function generate() {
  if (!isApiReady.value) return;

  error.value       = null;
  isLoading.value   = true;
  statusLog.value   = [];
  channelKeys.value = null;
  deeplinkUri.value = null;
  qrDataUrl.value   = null;
  step.value        = 'idle';

  try {
    const verusCrypto = (window as any).verusCrypto as VerusCryptoAPI;

    log('▸ Deriving channel keys via extension WASM...');

    const fromIdBytes = resolveId(fromIdInput.value);
    const toIdBytes   = resolveId(toIdInput.value);

    const seedBytes = inputMode.value === 'seed'
      ? Buffer.from(seedHex.value, 'hex') : undefined;

    const spendingKeyBytes = inputMode.value === 'spendingKey' && spendingKeyInput.value
      ? Buffer.from(bech32.fromWords(bech32.decode(spendingKeyInput.value.trim(), 1000).words))
      : undefined;

    const keys = verusCrypto.zGetEncryptionAddress({
      seed:            seedBytes,
      spendingKey:     spendingKeyBytes,
      hdIndex:         inputMode.value === 'seed' ? hdIndex.value : undefined,
      encryptionIndex: encryptionIndex.value,
      fromId:          fromIdBytes,
      toId:            toIdBytes,
      returnSecret:    returnEsk.value,
    });

    const addr = new SaplingPaymentAddress();
    addr.fromBuffer(Buffer.from(keys.address));
    const addressString = addr.toAddressString();

    channelKeys.value = keys;
    log(`✓ Channel keys derived`);
    log(`  address: ${addressString}`);
    step.value = 'derived';

    log('▸ Building AppEncryptionRequest...');

    const authDetails = new AuthenticationRequestDetails();
    const authRequest = new AuthenticationRequestOrdinalVDXFObject({ data: authDetails });

    let flags = new BigNumber(0);
    if (derivationID.value)  flags = flags.or(AppEncryptionRequestDetails.FLAG_HAS_DERIVATION_ID);
    if (requestID.value)     flags = flags.or(AppEncryptionRequestDetails.FLAG_HAS_REQUEST_ID);
    if (returnEsk.value)     flags = flags.or(AppEncryptionRequestDetails.FLAG_RETURN_ESK);
    if (!skipEncryption.value && keys.address)
      flags = flags.or(AppEncryptionRequestDetails.FLAG_HAS_ENCRYPT_RESPONSE_TO_ADDRESS);

    const encryptToAddr = !skipEncryption.value ? addr : null;

    const encDetailsParams: any = {
      version:          AppEncryptionRequestDetails.DEFAULT_VERSION,
      flags,
      derivationNumber: new BigNumber(derivationNumber.value),
    };

    if (derivationID.value)
      encDetailsParams.derivationID = CompactIAddressObject.fromAddress(derivationID.value);
    if (requestID.value)
      encDetailsParams.requestID = CompactIAddressObject.fromAddress(requestID.value);
    if (encryptToAddr)
      encDetailsParams.encryptResponseToAddress = encryptToAddr;

    const encDetails = new AppEncryptionRequestDetails(encDetailsParams);
    const encRequest = new AppEncryptionRequestOrdinalVDXFObject({ data: encDetails });

    log(`✓ AppEncryptionRequestDetails built`);
    log(`  derivationNumber: ${derivationNumber.value}`);
    log(`  derivationID: ${derivationID.value || '(not set)'}`);
    log(`  requestID: ${requestID.value || '(not set)'}`);
    log(`  returnEsk: ${returnEsk.value}`);
    log(`  encryptResponseToAddress: ${skipEncryption.value ? '(skipped)' : addressString}`);

    const req = new primitives.GenericRequest({
      details:   [authRequest, encRequest],
      createdAt: new BigNumber(Math.floor(Date.now() / 1000)),
    });

    req.signature = new VerifiableSignatureData({
      systemID:   CompactIAddressObject.fromAddress(systemID.value),
      identityID: CompactIAddressObject.fromAddress(signingID.value),
    });

    req.setSigned();
    log(`✓ GenericRequest built (${req.details.length} details)`);

    const rpcCall = async (method: string, params: any[]): Promise<any> => {
      log(`  → RPC ${method} ${JSON.stringify(params).substring(0, 80)}...`);
      const response = await fetch(`http://${rpcHost.value}:${rpcPort.value}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + btoa(`${rpcUser.value}:${rpcPass.value}`),
        },
        body: JSON.stringify({ jsonrpc: '1.0', id: 'verus', method, params }),
      });
      log(`  ← HTTP ${response.status}`);
      const data = await response.json();
      log(`  ← body: ${JSON.stringify(data).substring(0, 120)}`);
      if (data.error) throw new Error(JSON.stringify(data.error));
      return data.result;
    };

    log(`▸ Signing with verusd at ${rpcHost.value}:${rpcPort.value}...`);

    let sigResult: any;
    try {
      sigResult = await rpcCall('signdata', [{
        address:  signingID.value,
        datahash: req.getRawDataSha256().toString('hex'),
      }]);
      log(`  signdata raw result: ${JSON.stringify(sigResult)}`);
    } catch (e: any) {
      log(`✗ rpcCall threw: ${e.message}`);
      throw e;
    }

    if (!sigResult?.signature) {
      throw new Error(`Signing failed: ${JSON.stringify(sigResult)}`);
    }

    req.signature.signatureAsVch = Buffer.from(sigResult.signature, 'base64');
    log(`✓ Signed successfully`);
    step.value = 'signed';

    const dl = req.toWalletDeeplinkUri();
    deeplinkUri.value = dl;
    log(`✓ Deeplink generated (${dl.length} chars)`);

    log('▸ Rendering QR code...');
    qrDataUrl.value = await generateQR(dl);
    log('✓ Done — scan with Verus Mobile');
    step.value = 'done';

  } catch (e: any) {
    error.value = e.message || String(e);
    log(`✗ Error: ${e.message}`);
  } finally {
    isLoading.value = false;
  }
}

async function copyDeeplink() {
  if (!deeplinkUri.value) return;
  await navigator.clipboard.writeText(deeplinkUri.value);
  copied.value = true;
  setTimeout(() => { copied.value = false; }, 2000);
}

const stepLabel = computed(() => ({
  idle:    '',
  derived: 'Keys derived',
  signed:  'Signed',
  done:    'Ready to scan',
}[step.value]));

onMounted(() => {
  const check = () => { if ((window as any).verusCrypto) isApiReady.value = true; };
  window.addEventListener('verusCryptoReady', check);
  check();
});
</script>

<template>
  <div class="app">
    <header class="header">
      <div class="logo">
        <span class="logo-mark">V</span>
        <div>
          <div class="logo-title">VERUS CHANNEL</div>
          <div class="logo-sub">AppEncryptionRequest Generator</div>
        </div>
      </div>
      <div class="status" :class="isApiReady ? 'ready' : 'waiting'">
        <span class="dot" />
        {{ isApiReady ? 'Extension Ready' : 'Waiting for Extension' }}
      </div>
    </header>

    <main class="main">
      <section class="panel left-panel">

        <div class="section-block">
          <div class="block-title">verusd RPC</div>
          <div class="row2">
            <div class="field-group">
              <label class="label">Host</label>
              <input class="input" v-model="rpcHost" />
            </div>
            <div class="field-group">
              <label class="label">Port</label>
              <input class="input small" type="number" v-model="rpcPort" />
            </div>
          </div>
          <div class="row2">
            <div class="field-group">
              <label class="label">RPC User</label>
              <input class="input" v-model="rpcUser" />
            </div>
            <div class="field-group">
              <label class="label">RPC Password</label>
              <input class="input" type="password" v-model="rpcPass" />
            </div>
          </div>
          <div class="field-group">
            <label class="label">System ID</label>
            <input class="input mono" v-model="systemID" />
          </div>
          <div class="field-group">
            <label class="label">Signing Identity</label>
            <input class="input mono" v-model="signingID" placeholder="i... identity in wallet" />
          </div>
        </div>

        <div class="section-block">
          <div class="block-title">Channel Key Derivation</div>
          <div class="field-group">
            <label class="label">From Identity</label>
            <input class="input mono" v-model="fromIdInput" placeholder="i5UL... or alice@" />
          </div>
          <div class="field-group">
            <label class="label">To Identity</label>
            <input class="input mono" v-model="toIdInput" placeholder="iCpZ... or bob@" />
          </div>
          <div class="field-group">
            <label class="label">Key Source</label>
            <div class="radio-group">
              <label class="radio"><input type="radio" v-model="inputMode" value="seed" /><span>HD Seed</span></label>
              <label class="radio"><input type="radio" v-model="inputMode" value="spendingKey" /><span>Spending Key</span></label>
            </div>
          </div>
          <div v-if="inputMode === 'seed'" class="field-group">
            <label class="label">Seed (hex) <span class="hint">{{ seedHex.length / 2 }} bytes</span></label>
            <input class="input mono" v-model="seedHex" />
          </div>
          <div class="field-group">
            <label class="label">HD Index</label>
            <input class="input small" type="number" v-model="hdIndex" min="0" />
          </div>
          <div class="field-group">
            <label class="label">Enc. Index</label>
            <input class="input small" type="number" v-model="encryptionIndex" min="0" />
          </div>
          <div v-if="inputMode === 'spendingKey'" class="field-group">
            <label class="label">Spending Key (bech32)</label>
            <textarea class="input mono" rows="2" v-model="spendingKeyInput" placeholder="secret-extended-key-main1..." />
          </div>
        </div>

        <div class="section-block">
          <div class="block-title">AppEncryptionRequest Params</div>
          <div class="field-group">
            <label class="label">Derivation Number</label>
            <input class="input small" type="number" v-model="derivationNumber" min="0" />
          </div>
          <div class="field-group">
            <label class="label">Derivation ID <span class="hint">optional</span></label>
            <input class="input mono" v-model="derivationID" placeholder="i... identity" />
          </div>
          <div class="field-group">
            <label class="label">Request ID <span class="hint">optional</span></label>
            <input class="input mono" v-model="requestID" placeholder="i... identity" />
          </div>
          <div class="checkboxes">
            <label class="checkbox">
              <input type="checkbox" v-model="returnEsk" />
              <span>Return ESK (spending key)</span>
            </label>
            <label class="checkbox">
              <input type="checkbox" v-model="skipEncryption" />
              <span>Skip response encryption</span>
            </label>
          </div>
        </div>

        <button class="btn-generate" @click="generate" :disabled="!isApiReady || isLoading || !signingID">
          <span v-if="isLoading" class="spinner" />
          <span v-else>⬡ Derive → Build → Sign → QR</span>
        </button>

        <div v-if="error" class="error-box">{{ error }}</div>
      </section>

      <section class="panel right-panel">

        <div class="log-box">
          <div class="block-title">Progress</div>
          <div v-if="statusLog.length === 0" class="log-empty">Waiting to generate...</div>
          <div v-for="(line, i) in statusLog" :key="i" class="log-line"
            :class="{ error: line.startsWith('✗'), success: line.startsWith('✓'), info: line.startsWith('▸') }">
            {{ line }}
          </div>
        </div>

        <div class="qr-section">
          <div v-if="!qrDataUrl" class="qr-placeholder">
            <div class="qr-icon">⬡</div>
            <div class="qr-hint">QR code will appear here</div>
            <div class="qr-hint-sub">Scan with Verus Mobile to establish encrypted channel</div>
          </div>
          <div v-else class="qr-generated">
            <div class="qr-wrap" v-html='`<img src="${qrDataUrl}" style="width:280px;height:280px;border-radius:4px;image-rendering:pixelated;display:block;" />`'></div>
            <div class="qr-caption">
              <span class="step-badge">{{ stepLabel }}</span>
              Scan with Verus Mobile
            </div>
          </div>
        </div>

        <div v-if="channelKeys" class="keys-section">
          <div class="block-title">Derived Channel Keys</div>
          <div class="kv-row">
            <span class="kv-key">address</span>
            <span class="kv-val">{{
              (() => { const a = new SaplingPaymentAddress(); a.fromBuffer(Buffer.from(channelKeys.address)); return a.toAddressString(); })()
            }}</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">ivk</span>
            <span class="kv-val">{{ Buffer.from(channelKeys.ivk).toString('hex').substring(0,24) }}...</span>
          </div>
          <div class="kv-row">
            <span class="kv-key">extfvk</span>
            <span class="kv-val">{{ Buffer.from(channelKeys.extfvk).toString('hex').substring(0,24) }}...</span>
          </div>
          <div v-if="channelKeys.spendingKey" class="kv-row">
            <span class="kv-key">esk</span>
            <span class="kv-val">{{ Buffer.from(channelKeys.spendingKey).toString('hex').substring(0, 32) }}...</span>
          </div>
        </div>

        <div v-if="deeplinkUri" class="deeplink-section">
          <div class="block-title">Deep Link</div>
          <div class="deeplink-uri">{{ deeplinkUri.substring(0, 100) }}...</div>
          <button class="btn-copy" @click="copyDeeplink">
            {{ copied ? '✓ Copied' : 'Copy Full URI' }}
          </button>
        </div>

      </section>
    </main>
  </div>
</template>

<style scoped>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;600;800&display=swap');

* { box-sizing: border-box; margin: 0; padding: 0; }

.app {
  min-height: 100vh;
  background: #3165D3;
  color: #ffffff;
  font-family: 'Syne', sans-serif;
  background-image:
    radial-gradient(ellipse at 10% 10%, rgba(0,255,136,0.05) 0%, transparent 50%),
    radial-gradient(ellipse at 90% 90%, rgba(0,160,90,0.03) 0%, transparent 50%);
}

.header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 1.2rem 2rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}
.logo { display: flex; align-items: center; gap: 1rem; }
.logo-mark {
  width: 38px; height: 38px; background: #ffffff; color: #080c0a;
  font-size: 1.3rem; font-weight: 800;
  display: flex; align-items: center; justify-content: center;
  clip-path: polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);
}
.logo-title { font-size: 0.95rem; font-weight: 800; letter-spacing: 0.15em; color: #ffffff; }
.logo-sub   { font-size: 0.65rem; color: #ffffff; letter-spacing: 0.08em; }

.status {
  display: flex; align-items: center; gap: 0.5rem;
  font-size: 0.72rem; letter-spacing: 0.1em;
  padding: 0.35rem 0.9rem; border-radius: 2px; border: 1px solid;
}
.status.ready   { color: #ffffff; border-color: rgba(255, 255, 255, 0.3); background: rgba(0,255,136,0.05); }
.status.waiting { color: #555; border-color: rgba(80,80,80,0.3); }
.dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1}50%{opacity:0.3} }

.main { display: grid; grid-template-columns: 420px 1fr; min-height: calc(100vh - 65px); }
.panel { padding: 1.5rem 2rem; overflow-y: auto; }
.left-panel  { border-right: 1px solid rgba(0,255,136,0.07); display: flex; flex-direction: column; gap: 1.5rem; }
.right-panel { display: flex; flex-direction: column; gap: 1.2rem; background: rgba(0,255,136,0.01); }

.section-block {
  display: flex; flex-direction: column; gap: 0.8rem;
  padding: 1rem; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 4px;
}
.block-title {
  font-size: 0.62rem; letter-spacing: 0.2em; color: #ffffff;
  text-transform: uppercase; margin-bottom: 0.2rem;
}

.field-group { display: flex; flex-direction: column; gap: 0.3rem; }
.row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 0.8rem; }

.label {
  font-size: 0.65rem; letter-spacing: 0.1em; color: #ffffff;
  text-transform: uppercase; display: flex; justify-content: space-between;
}
.hint { font-size: 0.6rem; color: #2a4a3a; text-transform: none; letter-spacing: 0; font-family: 'Share Tech Mono', monospace; }

.input {
  background: rgba(0,255,136,0.03); border: 1px solid rgba(0,255,136,0.1);
  border-radius: 3px; color: #000000; padding: 0.5rem 0.7rem;
  font-family: 'Share Tech Mono', monospace; font-size: 0.78rem;
  outline: none; transition: border-color 0.2s; width: 100%;
}
.input:focus { border-color: rgba(110, 110, 110, 0.35); }
.input.mono  { font-size: 0.72rem; }
.input.small { width: 80px; }
textarea.input { resize: vertical; }

.radio-group { display: flex; gap: 1.2rem; }
.radio { display: flex; align-items: center; gap: 0.4rem; cursor: pointer; font-size: 0.78rem; color: #ffffff; }
.radio input { accent-color: #000000; }

.checkboxes { display: flex; flex-direction: column; gap: 0.5rem; }
.checkbox { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; font-size: 0.78rem; color: #fefffe; }
.checkbox input { accent-color: #000000; }

.btn-generate {
  padding: 0.9rem; background: transparent; border: 1px solid #ffffff;
  color: #ffffff; font-family: 'Syne', sans-serif; font-size: 0.78rem;
  font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase;
  cursor: pointer; border-radius: 3px; position: relative; overflow: hidden;
  transition: color 0.2s;
}
.btn-generate::before {
  content: ''; position: absolute; inset: 0; background: #ffffff;
  transform: scaleX(0); transform-origin: left; transition: transform 0.2s;
}
.btn-generate:hover::before { transform: scaleX(1); }
.btn-generate:hover { color: #080c0a; }
.btn-generate:disabled { opacity: 0.25; cursor: not-allowed; border-color: #333; color: #333; }
.btn-generate:disabled::before { display: none; }
.btn-generate > span { position: relative; }

.spinner {
  display: inline-block; width: 13px; height: 13px; position: relative;
  border: 2px solid rgba(0,255,136,0.25); border-top-color: #00ff88;
  border-radius: 50%; animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

.error-box {
  padding: 0.7rem; border: 1px solid rgba(255,70,70,0.3);
  background: rgba(255,70,70,0.05); color: #ff7070;
  font-size: 0.72rem; font-family: 'Share Tech Mono', monospace; border-radius: 3px;
}

.log-box {
  padding: 1rem; border: 1px solid rgb(255, 255, 255);
  border-radius: 4px; display: flex; flex-direction: column; gap: 0.5rem;
  min-height: 100px;
}
.log-empty { font-size: 0.72rem; color: #2a4a3a; font-family: 'Share Tech Mono', monospace; }
.log-line  { font-size: 0.72rem; font-family: 'Share Tech Mono', monospace; color: #ffffff; line-height: 1.5; }
.log-line.success { color: #ffffff; }
.log-line.error   { color: #ff6060; }
.log-line.info    { color: #ffffff; }

.qr-section {
  display: flex; justify-content: center; align-items: center; min-height: 320px;
  border: 1px solid rgb(243, 243, 243); border-radius: 4px; background: rgba(255, 255, 255, 0.25);
}
.qr-placeholder { text-align: center; display: flex; flex-direction: column; align-items: center; gap: 0.5rem; }
.qr-icon { font-size: 2.5rem; color: rgb(255, 255, 255); animation: float 3s ease-in-out infinite; }
@keyframes float { 0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)} }
.qr-hint     { font-size: 0.8rem; color: #ffffff; }
.qr-hint-sub { font-size: 0.68rem; color: #ffffff; }

.qr-generated { display: flex; flex-direction: column; align-items: center; gap: 0.8rem; padding: 1.5rem; }
.qr-caption { display: flex; align-items: center; gap: 0.6rem; font-size: 0.68rem; letter-spacing: 0.12em; color: #ffffff; text-transform: uppercase; }
.step-badge { background: rgb(0, 0, 0); border: 1px solid rgb(252, 252, 252); color: #ffffff; padding: 0.15rem 0.5rem; border-radius: 2px; font-size: 0.62rem; }

.keys-section, .deeplink-section {
  padding: 1rem; border: 1px solid rgba(0,255,136,0.08);
  border-radius: 4px; display: flex; flex-direction: column; gap: 0.6rem;
}
.kv-row { display: grid; grid-template-columns: 70px 1fr; gap: 0.8rem; align-items: start; }
.kv-key { font-size: 0.65rem; color: #ffffff; font-family: 'Share Tech Mono', monospace; padding-top: 1px; }
.kv-val { font-family: 'Share Tech Mono', monospace; font-size: 0.7rem; color: #868686; word-break: break-all; }

.deeplink-uri { font-family: 'Share Tech Mono', monospace; font-size: 0.68rem; color: #ffffff; word-break: break-all; }
.btn-copy {
  align-self: flex-start; padding: 0.35rem 0.75rem;
  background: transparent; border: 1px solid rgba(0,255,136,0.2);
  color: #ffffff; font-size: 0.68rem; letter-spacing: 0.08em;
  cursor: pointer; border-radius: 2px; font-family: 'Syne', sans-serif;
  transition: background 0.2s;
}
.btn-copy:hover { background: rgba(0,255,136,0.07); }
</style>