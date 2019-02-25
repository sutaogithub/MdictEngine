const mdict = require("./mdict-engine");
const MDX = mdict.MDX;
const MDD = mdict.MDD;


let mdx = new MDX("./niujin.mdx",'./mdx_records');
console.log(mdx.header);
