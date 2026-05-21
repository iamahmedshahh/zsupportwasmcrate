import { z_getEncryptionAddress } from './dist/index.es.js';

const keys = z_getEncryptionAddress({
  seed: new Uint8Array(32).fill(0xaa),
});

console.log('address length:', Buffer.from(keys.address).toString('hex'));   
console.log('ivk length:', Buffer.from(keys.ivk).toString('hex'));          
console.log('✓ library works');



// == to do ==
//  on javascript we can zeroize manually by just keys.spendingKey.fill(0);  // overwrite with zeroes