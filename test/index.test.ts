import { DataDescriptor } from 'verus-typescript-primitives';
import { decryptData } from '../src/index';
import { it, expect } from 'vitest';
import { Buffer } from 'buffer';


it('decrypts real contentmultimap data', () => {

  const descriptor = new DataDescriptor({
    objectdata: Buffer.from('data', 'hex'),
    epk:        Buffer.from('epk', 'hex'),
    ivk:        Buffer.from('ivk', 'hex'),
  });

  const decrypted = decryptData(descriptor);

  console.log('decrypted:', new TextDecoder().decode(decrypted));
});