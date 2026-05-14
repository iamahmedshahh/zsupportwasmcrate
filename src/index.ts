import {
  z_get_encryptionaddress,
  encrypt_v_data,
  decrypt_v_data,
} from 'veruszsupport';


export interface DerivationParams {
  seed?:            Uint8Array;   
  spendingKey?:     Uint8Array;   
  hdIndex?:         number;
  encryptionIndex?: number;
  fromId?:          Uint8Array;   
  toId?:            Uint8Array;   
  returnSecret?:    boolean;
}

export interface ChannelKeys {
  address:     Uint8Array;        
  ivk:         Uint8Array;     
  extfvk:      Uint8Array;
  spendingKey: Uint8Array | null; 
}

export interface EncryptParams {
  address:    Uint8Array;         
  data:       Uint8Array;
  returnSsk?: boolean;
}

export interface EncryptedPayload {
  ephemeralPublicKey: Uint8Array;      
  encryptedData:      Uint8Array;
  symmetricKey:       Uint8Array | null; 
}

export interface DecryptParams {
  ivk?:  Uint8Array | null;   
  epk?:  Uint8Array | null;   
  data:  Uint8Array;
  ssk?:  Uint8Array | null;   
}

// imitates the shape of DataDescriptor from verus-typescript-primitives, but only the fields relevant to decryption
export interface EncryptedDescriptor {
  objectdata: Uint8Array;
  epk?:       Uint8Array | null;
  ivk?:       Uint8Array | null;
  ssk?:       Uint8Array | null;
}

/**
 * Derives Sapling channel keys for encryption/decryption.
 */
export function z_getEncryptionAddress(params: DerivationParams): ChannelKeys {
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

export function encryptData(params: EncryptParams): EncryptedPayload {
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
 * Decrypts directly from a DataDescriptor shaped object.
 * Automatically picks the right key — ivk first, then ssk.
 * A real DataDescriptor from verus-typescript-primitives satisfies
 * the EncryptedDescriptor interface and can be passed directly.
 */
export function decryptData(descriptor: EncryptedDescriptor): Uint8Array {
  const ivk = descriptor.ivk ?? null;
  const epk = descriptor.epk ?? null;
  const ssk = descriptor.ssk ?? null;

  if (ivk) return new Uint8Array(decrypt_v_data(ivk, epk, descriptor.objectdata, null));
  if (ssk) return new Uint8Array(decrypt_v_data(null, null, descriptor.objectdata, ssk));

  throw new Error('descriptor has no decryption key — needs ivk or ssk');
}