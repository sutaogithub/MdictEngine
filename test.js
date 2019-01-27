const crypto = require('crypto');

const hash = crypto.createHash('ripemd');
hash.update('sssss');
console.log(hash.digest('hex'));

// const hashes = crypto.getHashes();
// console.log(hashes);