const mdict = require("./mdict-engine");
const fs = require("fs");
const MDX = mdict.MDX;
const MDD = mdict.MDD;


function res_path_map(record, basepath) {
    if (!basepath) {
        return;
    }
    let res_paths = record.match(/(href="[^#{1}].*?")|(src=".*?")/g);
    //去重
    let paths_set= new Set(res_paths);
    // res_paths.forEach(item=> paths_set.add(item));
    for (let item of paths_set) {
        let temp = item.replace(/href=('|")|src=('|")|sound:\/\/|entry:\/\/|('|")/g, "");
        new_path = item.replace(temp,basepath+temp);

        record = record.replace(new RegExp(item,"g"),new_path);
        console.log(item+"  replace:   "+new_path);
    }
    return record;
}

let mdx = new MDX("./niujin.mdx", './dict_res');
// let mdd = new MDD("./niujin.mdd");
// mdd.extract("./dict_res");
// console.log(mdx._key_list);
// console.log(mdx.serach('abandon'));


let record = mdx.serach("when").data;
record = res_path_map(record,"../dict_res/");
let fd = fs.openSync('./result',"w");
fs.writeSync(fd,record);
fs.closeSync(fd);
// console.log(record);

