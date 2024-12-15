'use strict'
import * as util from "./util.js";
import {ArrayToString, EncryptRSAOAEP, ImportRSAOAEP, StringToArray} from "./util.js";

let sodium;
const zeroNonce = new Uint8Array(16);

function getAlpha(password, r) {
    let gr = sodium.crypto_scalarmult_ristretto255_base(r);
    let h = sodium.crypto_generichash(sodium.crypto_core_ristretto255_HASHBYTES, password); //BLAKE2b
    h = sodium.crypto_core_ristretto255_from_hash(h);
    return sodium.crypto_core_ristretto255_add(h, gr);
}

function getD(password, v, beta, r, hash_len = sodium.crypto_core_ristretto255_HASHBYTES) {
    let nr = sodium.crypto_core_ristretto255_scalar_negate(r);
    let vnr = sodium.crypto_scalarmult_ristretto255(nr, v);
    let bvnr = sodium.crypto_core_ristretto255_add(beta, vnr);
    let msg = util.ConcatArray([util.StringToArray(password), v, bvnr]);
    return sodium.crypto_generichash(hash_len, msg);
}

function getD_primed(password, v, beta, r) {
    return getD(password, v, beta, r, 32);
}

async function genEnvU_primed(rwd) { // return: ArrayBuffer
    let keypair = await util.GenerateECDSAKeyPair();
    let privU = await util.ExportCryptoKey(keypair.privateKey, true);
    let pubU = await util.ExportCryptoKey(keypair.publicKey, false);
    let envU = await util.EncryptAES(util.StringToArray(privU), await util.ImportAESKey(rwd), zeroNonce);
    return [pubU, envU];
}

async function LSH(password) {
    const mapping = {
        '0': 0,
        '1': 0,
        '2': 0,
        '3': 0,
        '4': 0,
        '5': 0,
        '6': 0,
        '7': 0,
        '8': 0,
        '9': 0,
        'a': 0,
        'b': 0,
        'c': 0,
        'd': 0,
        'e': 1,
        'f': 1,
        'g': 1,
        'h': 1,
        'i': 1,
        'j': 1,
        'k': 1,
        'l': 2,
        'm': 2,
        'n': 2,
        'o': 2,
        'p': 2,
        'q': 2,
        'r': 3,
        's': 3,
        't': 3,
        'u': 3,
        'v': 3,
        'w': 3,
        'x': 3,
        'y': 3,
        'z': 3
    };
    let p = 0;
    for (let i = 0; i < password.length; i++) {
        p *= 4;
        p += mapping[password[i]];
    }
    // To hex string
    p = p.toString(16);
    return p;
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

async function Hello(user, HelloURL) {
    const p_primed = await LSH(user.password);
    let r = sodium.crypto_core_ristretto255_scalar_random(); //Do not use sodium.randombytes_buf!
    let alpha_primed = getAlpha(p_primed, r);
    alpha_primed = btoa(util.ArrayToString(alpha_primed));
    let data = {
        s: "h",
        u: user.username,
        a_p: alpha_primed
    };
    let req = new Request(HelloURL, {
        method: 'POST',
        body: JSON.stringify(data)
    });
    return {p_primed, r, req};
}

async function parseBody(response) {
    const reader = response.body.getReader();
    const body_uint8 = await reader.read();
    let str = ArrayToString(body_uint8.value);
    return JSON.parse(str);
}

async function SignHelloRespHandler(resp, u, p, p_primed, r, signupURL) {
    resp = await parseBody(resp);
    const vU = StringToArray(atob(resp["vU"]));
    const beta_primed = StringToArray(atob(resp["b_p"]));
    const c = resp["c"]; // Challenge
    let d_primed = getD_primed(p_primed, vU, beta_primed, r); // d`

    let [pubU_p, envU_p] = await genEnvU_primed(d_primed);

    const encrypted = await EncryptNonceBase64(p);

    let data = {
        s: "r",
        u: u,
        envU_p: btoa(ArrayToString(envU_p)),
        pubU_p: pubU_p,
        c: c,
        M: encrypted
    }
    return new Request(signupURL, {
        method: 'POST',
        body: JSON.stringify(data)
    });
}

async function SignHelloInterface(user, signupURL, libsodium) {
    sodium = libsodium;
    let {r, p_primed, req} = await Hello(user, signupURL);
    let resp = await fetch(req);
    req = await SignHelloRespHandler(resp, user.username, user.password,
        p_primed, r, signupURL);
    resp = await fetch(req);
    return resp;
}

async function getKey(envU, rwd) {
    let key_b64 = await util.DecryptAES(envU, await util.ImportAESKey(rwd), zeroNonce);
    let key = util.StringToArray(atob(util.ArrayToString(key_b64))).buffer;
    return await util.ImportECDSAKey(key, true);
}

async function LoginHelloRespHandler(resp, u, p, p_primed, r, signupURL) {
    resp = await parseBody(resp);
    const vU = StringToArray(atob(resp["vU"]));
    const beta_primed = StringToArray(atob(resp["beta_p"]));
    const envU_primed = StringToArray(atob(resp["envU_p"]));
    const challenge = StringToArray(atob(resp["c"]));

    const d_primed = getD_primed(p_primed, vU, beta_primed, r);
    let sku_primed = await getKey(envU_primed, d_primed);

    const sign = await util.SignMsg(sku_primed, challenge);

    const M = await EncryptNonceBase64(p);

    let data = {
        s: "r",
        u: u,
        S: btoa(ArrayToString(sign)),
        M: M
    }
    return new Request(signupURL, {
        method: 'POST',
        body: JSON.stringify(data)
    });
}

async function LoginHelloInterface(user, loginURL, libsodium) {
    sodium = libsodium;
    let {r, p_primed, req} = await Hello(user, loginURL);
    let resp = await fetch(req);
    req = await LoginHelloRespHandler(resp, user.username, user.password, p_primed, r, loginURL);
    resp = await fetch(req);
    return resp;
}

export {SignHelloInterface, LoginHelloInterface};