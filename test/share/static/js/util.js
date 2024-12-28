"use strict";


async function SignMsg(key, message) {
    return await crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: "SHA-256"
        },
        key,
        message
    );
}


async function EncryptAES(message, K, CTR) {
    return await crypto.subtle.encrypt(
        {
            name: "AES-CTR",
            counter: CTR,
            length: 64
        },
        K,
        message
    );
}

async function DecryptAES(ciphertext, K, CTR) {
    return await crypto.subtle.decrypt(
        {
            name: "AES-CTR",
            counter: CTR,
            length: 64
        },
        K,
        ciphertext,
    );
}

async function ImportAESKey(key) {
    return await crypto.subtle.importKey(
        "raw",
        key,
        "AES-CTR",
        false,
        ["encrypt", "decrypt"]
    );
}

async function ExportCryptoKey(key, isPrivate) {
    const exported = await crypto.subtle.exportKey(isPrivate ? "pkcs8" : "spki", key);
    return ArrayToString(exported);
}

async function GenerateECDSAKeyPair() {
    return await crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256",
        },
        true,
        ["sign", "verify"]
    );
}

async function ImportRSAOAEP(key, isPrivate) {
    const binaryDer = StringToArray(key);

    return crypto.subtle.importKey(
        isPrivate ? "pkcs8" : "spki",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        isPrivate ? ["decrypt"] : ["encrypt"],
    );
}

async function EncryptRSAOAEP(publicKey, msg) {
    return crypto.subtle.encrypt(
        {
            name: "RSA-OAEP",
        },
        publicKey,
        msg,
    );
}

async function ImportECDSAKey(pemContent, isPrivate) {
    return await crypto.subtle.importKey(
        isPrivate ? "pkcs8" : "spki",
        pemContent,
        {
            name: "ECDSA",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        true,
        isPrivate ? ["sign"] : ["verify"]
    );
}

function StringToArray(str) {
    let len = str.length;
    let array = new Uint8Array(len);
    for (let i = 0; i < len; i++)
        array[i] = str.charCodeAt(i);
    return array;
}

function ArrayToString(array) { // array: Uint8Array | ArrayBuffer
    if (array instanceof ArrayBuffer) return String.fromCharCode.apply(null, new Uint8Array(array));
    else return String.fromCharCode.apply(null, array);
}

function ConcatArray(bufs, returnBuf = false) { // bufs: [Uint8Array | ArrayBuffer]
    let total_len = 0;
    for (let buf of bufs)
        total_len += buf.byteLength;

    let offset = 0
    let res = new Uint8Array(total_len);
    for (let buf of bufs) {
        if (buf instanceof Uint8Array)
            res.set(buf, offset);
        else
            res.set(new Uint8Array(buf), offset);
        offset += buf.byteLength
    }
    return returnBuf ? res.buffer : res;
}

export {SignMsg, EncryptAES, DecryptAES, ExportCryptoKey, GenerateECDSAKeyPair, ImportECDSAKey, ImportAESKey};
export {ImportRSAOAEP, EncryptRSAOAEP};
export {StringToArray, ArrayToString, ConcatArray};