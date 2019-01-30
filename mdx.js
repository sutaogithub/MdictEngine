const struct = require('python-struct');
const utf8 = require('utf8');
const fs = require("fs");
const adler32 = require("adler32");
const assert = require('assert');
const streamifier = require('streamifier');
const crypto = require('./crypto-api.js');
const zlib = require('zlib');
const lzo = require("lzo-decompress");
const Long = require("long");



function _unescape_entities(text) {
    text = text.replace(/&lt;/g, '<');
    text = text.replace(/&gt;/g, '>');
    text = text.replace(/&quot;/g, '"');
    text = text.replace(/&amp;/g, '&');
    return text;
}

// function  _decrypt_regcode_by_email(reg_code, email){
//     email_digest = ripemd128(email.decode().encode('utf-16-le'))
//     s20 = Salsa20(key=email_digest, IV=b"\x00"*8, rounds=8)
//     encrypt_key = s20.encryptBytes(reg_code)
//     return encrypt_key
// }

function ripemd128(byte) {
    let temp =_buffer_to_hex(byte);
    // console.log(temp);
    let hasher = crypto.getHasher('ripemd128');
    hasher.update(temp);
    let raw = hasher.finalize();
    // console.log(crypto.encoder.toHex(raw));
    let buf = Buffer.alloc(raw.length);
    for (let i = 0, l = raw.length; i < l; i++) {
        buf[i] = parseInt(raw.charCodeAt(i));
    }
    return buf;
}

function _mdx_decrypt(comp_block){
    let key = ripemd128(Buffer.concat([comp_block.slice(4,8),struct.pack('<L', 0x3695)],8));
    // console.log(key);
    let block_decrypt = _fast_decrypt(comp_block.slice(8,comp_block.length), key);
    let block_header = comp_block.slice(0,8);
    return Buffer.concat([block_header,block_decrypt],block_decrypt.length+block_header.length) ;
}

function _fast_decrypt(data, key){
    let previous = 0x36;
    for(let i = 0;i<data.length;i++){
        let t = (data[i] >> 4 | data[i] << 4) & 0xff;
        t = t ^ previous ^ (i & 0xff) ^ key[i % key.length];
        previous = data[i];
        data[i] = t;
    }       
    return data;
}

function _buffer_to_hex (buffer){
    let result = '';
    for(let i = 0;i<buffer.length;i++){
        let hex =String.fromCharCode(buffer[i]);
        result+=hex; 
    }
    return result;
}

function _buffer_equals(buf1, buf2) {
    var len = buf1.length;
    if (len !== buf2.length) {
        return false;
    }
    for (var i = 0; i < len; i++) {
        if (buf1[i] !== buf2[i]) {
            return false;
        }
    }
    return true;
}


function _parse_long (number){
    //将long对象转成一个整数，注意此方法存在溢出的风险。
    if(number instanceof Long){
        return number.high * Math.pow(2, 32) + number.low;   
    } else {
        return number;
    }
}



class MDict {

    constructor(fname, encoding = '', passcode = null) {
        //"./collins_en_ch.mdx"
        this._fname = fname;
        this._encoding = encoding.toUpperCase();
        this._passcode = passcode;
        this.header = this._read_header();


        // try{
        this._read_keys();
        // }
        // except:
        //     print("Try Brutal Force on Encrypted Key Blocks")
        //     self._key_list = self._read_keys_brutal()
    }

    _parse_header(header_text) {
        let taglist = header_text.match(/(\w+)="((.|\r|\n)*?)"/g);
        let tagdict = {};
        for (let item of taglist) {
            let first_equal = item.indexOf("=");
            let key = item.substring(0,first_equal);
            let value = item.substring(first_equal+1,item.length);
            tagdict[key] = _unescape_entities(value.replace(/"/g, ""));
        }
        return tagdict;
    }

    _read_header() {
        let fd = fs.openSync(this._fname, "r");
        let buffer4 = Buffer.alloc(4);
        let file_pointer = 0;

        fs.readSync(fd, buffer4, 0, 4, null);
        file_pointer += 4;

        let header_bytes_size = struct.unpack('>I', buffer4)[0];
        let header_bytes = Buffer.alloc(header_bytes_size);
        fs.readSync(fd, header_bytes, 0, header_bytes_size, null);
        file_pointer += header_bytes_size;

        let checksum = adler32.sum(header_bytes);
        fs.readSync(fd, buffer4, 0, 4, null);
        file_pointer += 4;
        assert.strictEqual(checksum, struct.unpack('<I', buffer4)[0]);
        this._key_block_offset = file_pointer;

        fs.closeSync(fd);

        
        let header_text = header_bytes.toString("utf16le", 0, header_bytes.length - 2);
        // console.log(header_text);        
        let header_tag = this._parse_header(header_text);
        // console.log(header_tag);

        if (!this._encoding) {
            let encoding = header_tag['Encoding']
            // GB18030 > GBK > GB2312
            if (encoding == 'GBK' || encoding == 'GB2312') {
                encoding = 'GB18030'
                this._encoding = encoding
            }
            if (!header_tag['Encrypted'] || header_tag['Encrypted'] == 'No') {
                this._encrypt = 0;
            } else if (header_tag['Encrypted'] == 'Yes') {
                this._encrypt = 1;
            } else {
                this._encrypt = parseInt(header_tag['Encrypted']);
            }
        }

        this._stylesheet = {};
        if (header_tag['StyleSheet']) {
            //这里断行没有考虑\r后续学会正则表达式后加上
            let lines = header_tag['StyleSheet'].split(/\n/g);
            for (let i = 0; i < lines.length; i += 3) {
                this._stylesheet[lines[i]] = (lines[i + 1], lines[i + 2]);
            }
        }

        this._version = parseFloat(header_tag['GeneratedByEngineVersion']);
        if (this._version < 2.0) {
            this._number_width = 4;
            this._number_format = '>I';
        } else {
            this._number_width = 8;
            this._number_format = '>Q';
        }
        return header_tag
    }

    _read_keys() {
        let fd = fs.openSync(this._fname, "r");
        let file_pointer = this._key_block_offset;

        let num_bytes = 0;
        if (this._version >= 2.0) {
            num_bytes = 8 * 5;
        } else {
            num_bytes = 4 * 4;
        }

        let unit_buffer = Buffer.alloc(num_bytes);
        fs.readSync(fd, unit_buffer, 0, num_bytes, file_pointer);
        file_pointer += num_bytes;

        //这里解码需要更详细的了解
        // if (this._encrypt & 1){
        //     if (this._passcode){
        //         throw new Error('user identification is needed to read encrypted file');
        //     }
        //     regcode, userid = this._passcode;

        //     // if isinstance(userid, unicode){
        //     //     userid = userid.encode('utf8')
        //     // }
        //     if (this.header['RegisterBy'] == 'EMail'){
        //         encrypted_key = _decrypt_regcode_by_email(regcode, userid)

        //     }else{
        //         encrypted_key = _decrypt_regcode_by_deviceid(regcode, userid)
        //     }
        //     block = _salsa_decrypt(block, encrypted_key)
        // }
        let sf = streamifier.createReadStream(unit_buffer);
        let num_key_blocks = this._read_number(sf);
        this._num_entries = this._read_number(sf)
        let key_block_info_decomp_size = 0;
        if (this._version >= 2.0) {
            let key_block_info_decomp_size = this._read_number(sf);
        }
        let key_block_info_size = this._read_number(sf)
        let key_block_size = this._read_number(sf)

        //4 bytes: adler checksum of previous 5 numbers
        if (this._version >= 2.0) {
            let buffer4 = Buffer.alloc(4);
            fs.readSync(fd, buffer4, 0, 4, file_pointer);
            file_pointer += 4;
            let checksum = adler32.sum(unit_buffer);
            assert.strictEqual(checksum, struct.unpack('>I', buffer4)[0]);
        }

        // read key block info, which indicates key block's compressed and decompressed size
        let key_block_info = Buffer.alloc(key_block_info_size);
        fs.readSync(fd, key_block_info, 0, key_block_info_size, file_pointer);
        file_pointer += key_block_info_size;
        let  key_block_info_list = this._decode_key_block_info(key_block_info);
        assert.strictEqual(num_key_blocks, key_block_info_list.length);

        //read key block  
        let key_block_compressed = Buffer.alloc(key_block_size);
        fs.readSync(fd, key_block_compressed, 0, key_block_size, file_pointer);
        file_pointer+=key_block_size;

        //extract key block
        let key_list = this._decode_key_block(key_block_compressed, key_block_info_list);

        this._record_block_offset = file_pointer;

        fs.closeSync(fd);

        return key_list;
    }

     _decode_key_block(key_block_compressed, key_block_info_list){

        console.log(key_block_info_list);

        let key_list = [];
        let i = 0;
        for (let item of key_block_info_list){
            console.log(key_block_compressed.length);
            
            let start = i;
            let end = i + item['compressed_size'];
            // 4 bytes : compression type
            let key_block_type = key_block_compressed.slice(start,start+4);
            // 4 bytes : adler checksum of decompressed key block
            console.log("slice : start = "+start+"  end = "+end);
            let checksum = struct.unpack('>I', key_block_compressed.slice(start+4,start+8))[0];
            let key_block;
            

            if (_buffer_equals(key_block_type,Buffer.from([0x00,0x00,0x00,0x00]))){
                key_block = key_block_compressed.slice(start+8,end);
                console.log("no compression");
            }else if (_buffer_equals(key_block_type,Buffer.from([0x01,0x00,0x00,0x00]))){
                if (lzo ==null){
                    console.log("LZO compression is not supported");
                    break;
                }
                console.log("lzo decompression");
                
                 // decompress key block
                let header =Buffer.concat([Buffer.from([0xf0]),struct.pack('>I', item['decompressed_size'])],5);
                let compress_byte = Buffer.concat([header, key_block_compressed.slice(start+8,end)],end-start-3);
                key_block = lzo.decompress(compress_byte,compress_byte.length);
            }else if (_buffer_equals(key_block_type,Buffer.from([0x02,0x00,0x00,0x00]))){
                // decompress key block
                console.log("zlib decompression");
                key_block = zlib.inflateSync(key_block_compressed.slice(start+8,end));
            }
            //extract one single key block into a key list
            // key_list.push(this._split_key_block(key_block));
            //notice that adler32 returns signed value
            // console.log(typeof key_block);
            // assert.strictEqual(checksum,adler32.sum(key_block) & 0xffffffff);
            i += item['compressed_size'];
            console.log("\n");
        } 
        return key_list;
    }
  



    _decode_key_block_info(key_block_info_compressed) {
        let key_block_info = null;
        if (this._version >= 2){
            //zlib compression
            assert.strictEqual(_buffer_equals(key_block_info_compressed.slice(0,4),Buffer.from([0x02,0x00,0x00,0x00])), true );
            //decrypt if needed
            if (this._encrypt & 0x02) {
                key_block_info_compressed = _mdx_decrypt(key_block_info_compressed);
                // let fd = fs.openSync('compress_byte', "w");
                // fs.writeFileSync(fd, key_block_info_compressed);
            }
            //decompress
            key_block_info = zlib.inflateSync(key_block_info_compressed.slice(8,key_block_info_compressed.length));
            //adler checksum
            let checksum = struct.unpack('>I', key_block_info_compressed.slice(4,8))[0];
            assert.strictEqual(checksum, adler32.sum(key_block_info) & 0xffffffff);
        }else{
            // no compression
            key_block_info = key_block_info_compressed
        }

        // decode
        let key_block_info_list = [];
        let num_entries = 0;
        let i = 0;
        let byte_format ,byte_width,text_term;

        if (this._version>= 2) {
            byte_format = '>H';
            byte_width = 2;
            text_term = 1;
        } else{
            byte_format = '>B';
            byte_width = 1;
            text_term = 0;
        }
        while (i < key_block_info.length){
            // number of entries in current key block
            num_entries += _parse_long(struct.unpack(this._number_format, key_block_info.slice(i,i+this._number_width))[0]);
            i += this._number_width;
            // text head size
            let text_head_size = struct.unpack(byte_format, key_block_info.slice(i,i+byte_width))[0];
            i += byte_width;
            // text head
            if (this._encoding != 'UTF-16'){
                i += text_head_size + text_term;            
            }else {
                i += (text_head_size + text_term) * 2;  
            }
            // text tail size
            let text_tail_size = struct.unpack(byte_format, key_block_info.slice(i,i+byte_width))[0];
            i += byte_width;
            // text tail
            if (this._encoding != 'UTF-16'){
                i += text_tail_size + text_term;                
            }else{
                i += (text_tail_size + text_term) * 2 ;               
            }
            //key block compressed size
            let key_block_compressed_size = _parse_long(struct.unpack(this._number_format, key_block_info.slice(i,i+this._number_width))[0]);
            i += this._number_width;
            // key block decompressed size
            let key_block_decompressed_size =_parse_long(struct.unpack(this._number_format, key_block_info.slice(i,i+this._number_width))[0]);
            i += this._number_width;
            key_block_info_list.push({'compressed_size':key_block_compressed_size,'decompressed_size':key_block_decompressed_size});
        }
        return key_block_info_list;
    }

    _read_number(f) {
        if (this._version < 2.0) {
            //_number_format ='>I'
            return struct.unpack(this._number_format, f.read(this._number_width))[0];
        } else {
            //_number_format ='>Q',对于长整型，unpack返回的是一个包含高位和低位值的对象
            let temp = f.read(this._number_width);
            let long = struct.unpack(this._number_format, temp)[0];
            //将高位左移动32位，js中超过32位的数字不能用位运算符
            return _parse_long(long);
        }
    }

  

}



let o = new MDict("./collins.mdx");


//Long { low: 1006650368, high: 1648, unsigned: true }