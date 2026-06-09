import {
  z_getEncryptionAddress,
  encryptDescriptor,
  decryptDescriptor,
  DataDescriptor,
} from './dist/index.es.js';

import { Buffer } from 'buffer';


const seed = new Uint8Array(Buffer.from('aa'.repeat(32), 'hex'));

const keys = z_getEncryptionAddress({
  seed,
  fromId:          new Uint8Array(20).fill(1),
  toId:            new Uint8Array(20).fill(2),
  encryptionIndex: 0,
  returnSecret:    true,
});

console.log('═══ Channel keys ═══');
console.log('ivk:', Buffer.from(keys.ivk).toString('hex'));


const message = 'hello from library';

const inputDescriptor = new DataDescriptor({
  objectdata: Buffer.from(message),
  // salt omitted — encryptDescriptor generates one
});

console.log('\n═══ Input descriptor ═══');
console.log(JSON.stringify(inputDescriptor.toJson(), null, 2));


const result = encryptDescriptor({
  descriptor: inputDescriptor,
  address:    keys.address,
  returnSsk:  true,
});

console.log('\n═══ encryptDescriptor() result ═══');
console.log('returned object keys:', Object.keys(result));
console.log('\nresult.descriptor (the encrypted DataDescriptor):');
console.log(JSON.stringify(result.descriptor.toJson(), null, 2));
console.log('\nresult.ssk (symmetric key, hex):');
console.log(`  ${Buffer.from(result.ssk).toString('hex')}`);

console.log('\nraw fields on the returned descriptor:');
console.log('  version:    ', result.descriptor.version.toString());
console.log('  flags:      ', result.descriptor.flags.toString());
console.log('  objectdata: ', result.descriptor.objectdata.toString('hex'), `(${result.descriptor.objectdata.length} bytes)`);
console.log('  epk:        ', result.descriptor.epk.toString('hex'), `(${result.descriptor.epk.length} bytes)`);


const decryptedInner = decryptDescriptor({
  descriptor: result.descriptor,
  ivk:        keys.ivk,
});

console.log('\n═══ decryptDescriptor() result ═══');
console.log('inner descriptor JSON:');
console.log(JSON.stringify(decryptedInner.toJson(), null, 2));
console.log('\ndecrypted message:', decryptedInner.objectdata.toString('utf8'));
console.log('decrypted type (hex):', decryptedInner.mimeType);
console.log('roundtrip ok?     ', decryptedInner.objectdata.toString('utf8') === message);


const daemonPayload = {
  datadescriptor: {
    version:    1,
    flags:      5,
    objectdata: result.descriptor.objectdata.toString('hex'),
    epk:        result.descriptor.epk.toString('hex'),
  },
  ivk: Buffer.from(keys.ivk).toString('hex'),
};

console.log('\n═══ Daemon verification ═══');
console.log(`./verus decryptdata '${JSON.stringify(daemonPayload)}'`);
console.log('\n(Expected output: the message in hex →', Buffer.from(message).toString('hex'), ')');