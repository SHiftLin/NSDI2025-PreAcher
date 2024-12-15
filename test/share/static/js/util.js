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

async function VerifyMsg(key, signature, message) {
    return await crypto.subtle.verify(
        {
            name: "ECDSA",
            hash: "SHA-256"
        },
        key,
        signature,
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
    const exportedAsString = ArrayToString(exported);
    return btoa(exportedAsString);
}

async function ImportVerifyKey(hex) {
    return await crypto.subtle.importKey(
        "spki",
        HexToArray(hex),
        {
            name: "ECDSA",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        false,
        ['verify']
    );
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

async function GenerateRSAOAEPKeyPair() {
    return await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: {name: "SHA-256"},
        },
        true,
        ["encrypt", "decrypt"]
    )
}

async function ExportRSAOAEP(key, isPrivate) {
    if (isPrivate) {
        const exported = await crypto.subtle.exportKey("pkcs8", key);
        const exportedAsBase64 = btoa(ArrayToString(exported));
        return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
    } else {
        const exported = await window.crypto.subtle.exportKey("spki", key);
        const exportedAsBase64 = btoa(ArrayToString(exported));
        return `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
    }
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

async function DecryptRSAOAEP(privateKey, msg) {
    return crypto.subtle.decrypt(
        {
            name: "RSA-OAEP",
        },
        privateKey,
        msg
    )
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

var Dec2Hex = ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af", "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf", "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf", "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df", "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef", "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"]

function HexToArray(hex) {
    let len = hex.length;
    let array = new Uint8Array(len / 2);
    for (let i = 0, j = 0; i < len; i += 2, j++)
        array[j] = parseInt(hex.substr(i, 2), 16);
    return array;
}

function ArrayToHex(array) {
    if (array instanceof ArrayBuffer)
        array = new Uint8Array(array);
    let hex = '';
    for (let i = 0; i < array.length; ++i)
        hex += Dec2Hex[array[i]]
    return hex;
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

function UintToArray(x, array, offset) { // x: unsigned integer, Array: small end 
    for (let i = 0; i < 4; i++, offset++, x >>= 8)
        array[offset] = x & 0xff
}

function ArrayToUint(array) {
    let x = 0;
    if (typeof array === "string")
        for (let i = 0; i < array.length; i++)
            x = (x << 8) + str.charCodeAt(i);
    else {
        for (let i = 0; i < array.length; i++)
            x = (x << 8) + array[i];
    }
    return x;
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

export {SignMsg, VerifyMsg, EncryptAES, DecryptAES, ExportCryptoKey, ImportVerifyKey, GenerateECDSAKeyPair, ImportECDSAKey, ImportAESKey};
export {GenerateRSAOAEPKeyPair, ExportRSAOAEP, ImportRSAOAEP, EncryptRSAOAEP, DecryptRSAOAEP};
export {HexToArray, ArrayToHex, StringToArray, ArrayToString, UintToArray, ArrayToUint, ConcatArray};