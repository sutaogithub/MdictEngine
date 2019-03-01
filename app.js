const mdict = require("./mdict-engine");
const fs = require("fs");
const MDX = mdict.MDX;
const MDD = mdict.MDD;
const express = require('express');
const ejs = require('ejs');

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
let app = express();
app.set("views","./views");
app.set('view engine','ejs');
app.use("/resource",express.static('resource'));
app.use("/dict_res",express.static('dict_res'));


//交互方式
app.get('/',function (req, res) {
    res.render('home');
});
app.get('/search',function (req, res) {
   let word = req.param("word","");
   let meaning = mdx.serach(word);
   if(meaning!=-1){
      res.json({status:0,html:res_path_map(meaning.data,"../dict_res/"),msg:"search success"});
   } else{
      res.json({status:-1,html:"",msg:"error"});
   }
});

app.listen(3000);