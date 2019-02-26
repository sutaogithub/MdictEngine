const mdict = require("./mdict-engine");
const fs = require("fs");

const MDX = mdict.MDX;
const MDD = mdict.MDD;


let mdx = new MDX("./niujin.mdx",'./mdx_records');
// console.log(mdx._key_list);
// console.log(mdx.serach('abandon'));
let fd = fs.openSync('./result',"w");
fs.writeSync(fd,mdx.serach("abandon").data);
fs.closeSync(fd);