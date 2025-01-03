'use strict'

import {ArrayToString, EncryptRSAOAEP, ImportRSAOAEP, StringToArray} from "./util.js";
import KmerMinHash from "./kmerhash.js";

async function sha256(password) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
    return ArrayToString(hashBuffer);
}

async function LSH(username, password) {
    const minHasher = new KmerMinHash(5, true, username);
    await minHasher.init();  // Initialize the hashers, async operation
    return await minHasher.hash(password);
}


async function EncryptNonceBase64(msg) {
    const pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3CRFJtrxpZtbGLKaipXK6qLB76IBfXW7ZAPknezDPXvjD4ziYJJUwuk96l9se5rZFXylASrxiPzFqlNj/XyxPij50r7l5jCQJdPUTjOOzk+80M8EoOew30InKoVmMK0IiK/0vPyq7kJtCWVKbWg4Y/DbxKkY3GKKGlVfSrOWC3KUsWyttb4j8v4WQ0iw/8Xq+PYltahK2m1uKCI8Kl4QxP+b0kAExYWDH0YJuO0167DuhRy51jYJULCRs6h0v1QOlOP/nQA2a7EWATBY6LQ8uf31huH0x0rAsTnMXtJ5qkFP3G4w8D4wgAY2m6v7RhqnJk924snE523R/fr3+QHAtwIDAQAB";
    let pub = await ImportRSAOAEP(atob(pubkey), false);
    // Random human readable nonce
    const Nonce = crypto.getRandomValues(new Uint8Array(16));
    const Nonced_password = btoa(ArrayToString(Nonce)) + " " + msg;
    const encrypted = await EncryptRSAOAEP(pub, StringToArray(Nonced_password));
    return btoa(ArrayToString(encrypted));
}

async function LoginInterface(info, loginURL) {
    if (info.password.includes(" ")) {
        console.log("Password contains space(s)")
        return false;
    }
    const encrypted = await EncryptNonceBase64(info.password);
    const lsh_password = await LSH(info.username, info.password);
    const hash_lsh_password = await sha256(lsh_password);

    const req = new Request(loginURL, {
        method: 'POST',
        body: JSON.stringify({
            u: info.username,
            h: btoa(hash_lsh_password),
            M: encrypted
        })
    });
    return await fetch(req);
}

async function SignupInterface(info, signupURL) {
    if (info.password.includes(" ")) {
        console.log("Password contains space(s)")
        return false;
    }
    const encrypted = await EncryptNonceBase64(info.password);

    const req = new Request(signupURL, {
        method: 'POST',
        body: JSON.stringify({
            u: info.username,
            M: encrypted
        })
    });
    return await fetch(req);
}

function pemToArrayBuffer(pem) {
    const base64 = pem
        .replace(/-----BEGIN [A-Z ]+-----/g, '')
        .replace(/-----END [A-Z ]+-----/g, '')
        .replace(/\s+/g, '');

    const binaryString = atob(base64);
    const len = binaryString.length;
    const arrayBuffer = new ArrayBuffer(len);
    const uint8Array = new Uint8Array(arrayBuffer);

    for (let i = 0; i < len; i++) {
        uint8Array[i] = binaryString.charCodeAt(i);
    }

    return arrayBuffer;
}

export async function test_pem() {
    let pem = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3CRFJtrxpZtbGLKaipXK6qLB76IBfXW7ZAPknezDPXvjD4ziYJJUwuk96l9se5rZFXylASrxiPzFqlNj/XyxPij50r7l5jCQJdPUTjOOzk+80M8EoOew30InKoVmMK0IiK/0vPyq7kJtCWVKbWg4Y/DbxKkY3GKKGlVfSrOWC3KUsWyttb4j8v4WQ0iw/8Xq+PYltahK2m1uKCI8Kl4QxP+b0kAExYWDH0YJuO0167DuhRy51jYJULCRs6h0v1QOlOP/nQA2a7EWATBY6LQ8uf31huH0x0rAsTnMXtJ5qkFP3G4w8D4wgAY2m6v7RhqnJk924snE523R/fr3+QHAtwIDAQAB";

    // pem = pemToArrayBuffer(pem);
    const pub = await ImportRSAOAEP(atob(pem), false);
    console.log(pub);
    const text = "123123";
    const encrypted = await EncryptRSAOAEP(pub, StringToArray(text));
    // To base64
    console.log(btoa(ArrayToString(encrypted)));
}

export {LoginInterface, SignupInterface};