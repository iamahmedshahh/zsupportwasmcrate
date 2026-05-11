import init, {
  z_get_encryptionaddress,
  encrypt_v_data,
  decrypt_v_data,
} from 'veruszsupport';

// Kicks off the moment the library is imported.

const wasmReady = init();


export interface DerivationParams {
  seed?:            Uint8Array;   // variable length
  spendingKey?:     Uint8Array;   // 169 bytes
  hdIndex?:         number;
  encryptionIndex?: number;
  fromId?:          Uint8Array;   // 20 bytes (hash160)
  toId?:            Uint8Array;   // 20 bytes (hash160)
  returnSecret?:    boolean;
}

export interface ChannelKeys {
  address:     Uint8Array;        // 43 bytes (PaymentAddress)
  ivk:         Uint8Array;        // 32 bytes
  extfvk:      Uint8Array;
  spendingKey: Uint8Array | null; // 169 bytes — only if returnSecret: true
}

export interface EncryptParams {
  address:    Uint8Array;         // 43 bytes (PaymentAddress)
  data:       Uint8Array;         // plaintext bytes to encrypt
  returnSsk?: boolean;            // whether to return the symmetric session key
}

export interface EncryptedPayload {
  ephemeralPublicKey: Uint8Array;        // 32 bytes
  encryptedData:      Uint8Array;
  symmetricKey:       Uint8Array | null; // 32 bytes — only if returnSsk: true
}

export interface DecryptParams {
  ivk?:  Uint8Array;   // 32 bytes — incoming viewing key
  epk?:  Uint8Array;   // 32 bytes — ephemeral public key
  data:  Uint8Array;   // the encrypted bytes
  ssk?:  Uint8Array;   // 32 bytes — symmetric session key (alternative to ivk+epk)
}


export async function deriveKeys(params: DerivationParams): Promise<ChannelKeys> {
  await wasmReady;

  const result = z_get_encryptionaddress(
    params.seed            ?? null,
    params.spendingKey     ?? null,
    params.hdIndex         ?? null,
    params.encryptionIndex ?? null,
    params.fromId          ?? null,
    params.toId            ?? null,
    params.returnSecret    ?? false,
  );

  return {
    address:     new Uint8Array(result.address),
    ivk:         new Uint8Array(result.ivk),
    extfvk:      new Uint8Array(result.extfvk),
    spendingKey: result.spendingKey ? new Uint8Array(result.spendingKey) : null,
  };
}


export async function encryptData(params: EncryptParams): Promise<EncryptedPayload> {
  await wasmReady;

  const result = encrypt_v_data(
    params.address,
    params.data,
    params.returnSsk ?? false,
  );

  return {
    ephemeralPublicKey: new Uint8Array(result.ephemeralPublicKey),
    encryptedData:      new Uint8Array(result.encryptedData),
    symmetricKey:       result.symmetricKey ? new Uint8Array(result.symmetricKey) : null,
  };
}

/**
 * Decrypts data encrypted to a Sapling PaymentAddress.
 * Either provide ivk + epk (viewing key path),
 * or ssk alone (symmetric key path if you have it from encryptData).
 */
export async function decryptData(params: DecryptParams): Promise<Uint8Array> {
  await wasmReady;

  return new Uint8Array(
    decrypt_v_data(
      params.ivk  ?? null,
      params.epk  ?? null,
      params.data,
      params.ssk  ?? null,
    )
  );
}