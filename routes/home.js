const mdict = require("./mdict-engine");
const fs = require("fs");
const MDX = mdict.MDX;
const MDD = mdict.MDD;

const express = require('express');
let router = express.Router();


router.get('/home', function (req, res) {
    res.send('Birds home page')
});


module.exports = router