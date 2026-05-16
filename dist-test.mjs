import { z_getEncryptionAddress } from './dist/index.es.js';

const keys = z_getEncryptionAddress({
  seed: new Uint8Array(32).fill(0xaa),
});

console.log('address length:', keys.address.toString('hex'));  
console.log('ivk length:', keys.ivk.toString('hex'));          
console.log('✓ library works');