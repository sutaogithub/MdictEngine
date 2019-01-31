const fs =  require("fs")

let f = fs.createReadStream("./collins.mdx");

 async function asyncfunc() {  
    return new Promise(resolve => {
        let f = fs.createReadStream("./collins.mdx");
        f.on('readable', function () {
            resolve(f);
        });
    });
}


async function test() {
    let ret = await asyncfunc()

    console.log(f.read(8));
}

