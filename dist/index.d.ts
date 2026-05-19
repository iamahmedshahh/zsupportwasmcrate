export interface DerivationParams {
    seed?: Uint8Array;
    spendingKey?: Uint8Array;
    hdIndex?: number;
    encryptionIndex?: number;
    fromId?: Uint8Array;
    toId?: Uint8Array;
    returnSecret?: boolean;
}
export interface ChannelKeys {
    address: Uint8Array;
    ivk: Uint8Array;
    extfvk: Uint8Array;
    spendingKey: Uint8Array | null;
}
export interface EncryptParams {
    address: Uint8Array;
    data: Uint8Array;
    returnSsk?: boolean;
}
export interface EncryptedPayload {
    ephemeralPublicKey: Uint8Array;
    objectdata: Uint8Array;
    symmetricKey: Uint8Array | null;
}
export interface EncryptedDescriptor {
    objectdata: Uint8Array;
    epk?: Uint8Array | null;
    ivk?: Uint8Array | null;
    ssk?: Uint8Array | null;
}
/**
 * Derives Sapling channel keys for encryption/decryption.
 */
export declare function z_getEncryptionAddress(params: DerivationParams): ChannelKeys;
export declare function encryptData(params: EncryptParams): EncryptedPayload;
/**
 * Decrypts directly from a DataDescriptor shaped object.
 * Automatically picks the right key — ivk first, then ssk.
 * A real DataDescriptor from verus-typescript-primitives satisfies
 * the EncryptedDescriptor interface and can be passed directly.
 */
export declare function decryptData(descriptor: EncryptedDescriptor): Uint8Array;
