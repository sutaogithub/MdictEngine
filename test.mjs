import Ripemd from "crypto-api/src/hasher/ripemd";
import {toHex} from "crypto-api/src/encoder/hex";

let hasher = new Ripemd({length:128});
hasher.update(Buffer.from([0x95,0x36,0x00,0x00]));
console.log(toHex(hasher.finalize()));



// const crypto = require('./crypto-api.js');


// let hasher = crypto.getHasher('ripemd128');
// // hasher.update(Buffer.from([0x1c,0x3a,0xb8,0x86,0x95,0x36,0x00,0x00]));

// hasher.update(Buffer.from([0x95,0x36,0x00,0x00]));

// let raw = hasher.finalize();
// console.log(crypto.encoder.toHex(raw));




// var hasher = crypto.getHasher('ripemd128');
// hasher.update(Buffer.from([0x01,0x02,0x03]));
// console.log(hasher.finalize());
// console.log(ripemd128(Buffer.from([0x01,0x02,0x03])));
// function ripemd128(byte) {
//     1c 3a b8 86 95 36 00 00
//         let hasher = crypto.getHasher('ripemd128');
//         hasher.update(byte);
//         let raw = hasher.finalize();
//         let buf = Buffer.alloc(raw.length);
//         for (let i = 0, l = raw.length; i < l; i++) {
//             buf[i] = parseInt(raw.charCodeAt(i));
//         }
//         return buf;
// }



// let array  =[ 'GeneratedByEngineVersion="2.0"',
// 'RequiredEngineVersion="2.0"',
// 'Format="Html"',
// 'KeyCaseSensitive="No"',
// 'StripKey="Yes"',
// 'Encrypted="2"',
// 'RegisterBy="EMail"',
// 'Description="&lt;font size=3 color=red&gt;《collins英汉双解学习词典》by sxingbai&lt;/font&gt;"',
// 'Title="collins双解词典"',
// 'Encoding="UTF-8"',
// 'CreationDate="2012-6-19"',
// 'Compact="Yes"',
// 'Compat="Yes"',
// 'Left2Right="Yes"',
// 'DataSourceFormat="106"',
// 'StyleSheet=""' ];

// // console.log(array.toString())

// let json = JSON.parse("{"+array.toString()+"}");
// console.log(json);

// let buf1 = Buffer.from([0x01,0x02]);
// let buf2 = Buffer.from([0x01,0x02]);
// let buf3 = buf1+buf2;
// console.log(Buffer.concat([buf1,buf2],4));