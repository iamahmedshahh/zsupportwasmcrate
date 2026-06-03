// // import { z_getEncryptionAddress } from './dist/index.es.js';

// // const keys = z_getEncryptionAddress({
// //   seed: new Uint8Array(32).fill(0xaa),
// // });

// // console.log('address length:', Buffer.from(keys.address).toString('hex'));   
// // console.log('ivk length:', Buffer.from(keys.ivk).toString('hex'));          
// // console.log('✓ library works');



// // == to do ==
// //  on javascript we can zeroize manually by just keys.spendingKey.fill(0);  // overwrite with zeroes


// import { z_getEncryptionAddress, encryptData } from './dist/index.es.js';
// import { Buffer } from 'buffer';
// import { SaplingPaymentAddress } from 'verus-typescript-primitives';

// const seed = new Uint8Array(Buffer.from('aa'.repeat(32), 'hex'));

// const keys = z_getEncryptionAddress({
//   seed,
//   fromId:          new Uint8Array(20).fill(1),
//   toId:            new Uint8Array(20).fill(2),
//   encryptionIndex: 0,
//   returnSecret:    true,
// });

// const addr = new SaplingPaymentAddress();
// addr.fromBuffer(Buffer.from(keys.address));
// const addressString = addr.toAddressString();

// const plaintext = new TextEncoder().encode('hello from library test');

// const encrypted = encryptData({
//   address: keys.address,
//   data:    plaintext,
//   returnSsk: true,
// });

// console.log('encrypted keys:', Object.keys(encrypted));
// console.log('encrypted:', encrypted);

// console.log('Channel address (bech32):');
// console.log(`  ${addressString}`);
// console.log('\nSpending key (hex) — import to daemon if needed:');
// console.log(`  ${Buffer.from(keys.spendingKey).toString('hex')}`);
// console.log('\nEncrypted data (hex):');
// console.log(`  ${Buffer.from(encrypted.objectdata).toString('hex')}`);
// console.log('\nEphemeral public key (hex):');
// console.log(`  ${Buffer.from(encrypted.ephemeralPublicKey).toString('hex')}`);
// console.log('\nIVK (hex) — needed for daemon decryption:');
// console.log(`  ${Buffer.from(keys.ivk).toString('hex')}`);
// console.log('\nExpected plaintext after decrypt:');
// console.log(`  "${new TextDecoder().decode(plaintext)}"`);


// import { decryptData } from './dist/index.es.js';

// const decrypted = decryptData({
//   objectdata: new Uint8Array(Buffer.from('', 'hex')),
//   epk:        new Uint8Array(Buffer.from('', 'hex')),
//   ivk:        keys.ivk,   // the ivk you derived earlier
// });

// console.log('decrypted hex:', Buffer.from(decrypted).toString('hex'));
// console.log('decrypted utf8:', new TextDecoder().decode(decrypted));