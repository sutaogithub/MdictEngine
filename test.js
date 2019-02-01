const fs =  require("fs");
const path =  require('path');

let node_modules = fs.statSync('./node_modules');

let ss = './node/ee/ss/s';
ss = ss.replace(/\\/g,path.sep);
console.log(ss);
console.log(path.dirname(ss));

for(let index of item_wrapper()){
    console.log(index);
}
// let path = '.\node\ee\ss';

// path.replace(/\\/g,)


// estract('.\node\ee\ss');

// function estract(path){
//     if(!fs.existsSync(path)) {
//         fs.mkdirSync(path);
//     }

// }

function item_wrapper( ){
    function* items(){
        yield 1;
        yield 2;
        yield 3;
    }
     return items();
}
