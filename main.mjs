// totp.js - 单文件实现 TOTP (SHA1 + Base32)
import { createServer } from 'node:http';
import cron from 'node-cron';
import crypto from 'crypto';
import qrcode from 'qrcode';

class TOTP {
    static base32Decode(base32) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = 0;
        let value = 0;
        let output = [];

        base32 = base32.replace(/=+$/, '').toUpperCase();
        for (let i = 0; i < base32.length; i++) {
            const idx = alphabet.indexOf(base32[i]);
            if (idx === -1) throw new Error('Invalid Base32 character: ' + base32[i]);
            value = (value << 5) | idx;
            bits += 5;

            if (bits >= 8) {
                bits -= 8;
                output.push((value >>> bits) & 0xff);
            }
        }
        return Buffer.from(output);
    }

    static generate(secret, digits = 6, timeStep = 30) {
        const key = TOTP.base32Decode(secret);
        const counter = Math.floor(Date.now() / 1000 / timeStep);

        const buffer = Buffer.alloc(8);
        buffer.writeBigUInt64BE(BigInt(counter), 0);

        const hmac = crypto.createHmac('sha1', key);
        hmac.update(buffer);
        const hash = hmac.digest();

        const offset = hash[hash.length - 1] & 0x0f;
        const truncated = hash.slice(offset, offset + 4);
        truncated[0] &= 0x7f;
        const code = ((truncated[0] << 24) | (truncated[1] << 16) | (truncated[2] << 8) | truncated[3]) % 1000000;

        return code.toString().padStart(digits, '0');
    }
}

const secret = '32charactersNUMandCHARstringHERE'.toUpperCase(); // thats exactly 32 chars and within 2-7 LOLOL
const digits = 6;
const peroid = 30;
const qrshare = "otpauth://totp/localhost:gate?issuer=localhost&secret=" + secret + "&algorithm=SHA1&digits=" + digits + "&period=" + peroid;
let totp = TOTP.generate(secret, digits, peroid);
console.log('Instant TOTP:', totp);

function updateTOTP() {
    const newTotp = TOTP.generate(secret, digits, peroid);
    if (newTotp !== totp) {
        console.log('TOTP updated:', newTotp);
        totp = newTotp;
    }
}


const server = createServer(async (req, res) => {
    if (req.url === '/totp/share') {
        const pngBuffer = await qrcode.toBuffer(qrshare, { type: 'png' });
        res.writeHead(200, { 'Content-Type': 'image/png' });
        res.end(pngBuffer);
    } else if (req.url === '/totp/uri') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(qrshare);
    } else if (req.url === '/totp') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ totp: totp }));
    } else if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Hello World!\n');
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found\n');
    }
});

server.listen(3000, '127.0.0.1', () => {
    var task = cron.schedule('*/30 * * * * *', updateTOTP);
    task.start();
    updateTOTP();
});
