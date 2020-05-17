import * as base64 from "@stablelib/base64";
import * as utf8 from "@stablelib/utf8";
import { ObjectsCrypto } from "./ObjectsCrypto";
// import  from "ecurve";

import nacl from "tweetnacl";
import { Curve, getCurveByName } from "ecurve";

abstract class Key<K extends KeyType> {
    private _keyType: K;

    key: CryptoKey;

    constructor(key: CryptoKey) {
        this.key = key;
    }

    abstract getKeyType(): K;
}
export class SignKey extends Key<KeyType.Sign> {
    keyType = KeyType.Sign;

    verifyKey: VerifyKey;

    constructor(privateKey: CryptoKey, publicKey: CryptoKey) {
        super(privateKey);
        this.verifyKey = new VerifyKey(publicKey);
    }

    getKeyType(): KeyType.Sign { return KeyType.Sign };

    static generate(): SignKey;
    static generate(password: string, salt: string): Promise<SignKey>;
    static generate(password?: string, salt?: string): SignKey | Promise<SignKey> {
        if (password !== undefined && salt !== undefined) {
            let saltBytes = utf8.encode("42234223" + salt + "sign");
            return (window as any).argon2.hash({ pass: utf8.encode(password), salt: saltBytes, hashLen: 32, mem: 131072, time: 1, parallelism: 1, type: (window as any).argon2.ArgonType.Argon2id })
                .then((result: { hash: Uint8Array }) => crypto.subtle.importKey("raw", result.hash, { name: "ECDSA", namedCurve: "P-521" }, false, ["sign"])
                    .then(k => crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-512", salt: salt }, k, {})))
                .catch(() => Promise.reject("error while generating key"));
        }
        return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-521" }, false, ["sign"]).then(k => new SignKey(k.privateKey, k.publicKey));
        // return new SignKey(nacl.randomBytes(64));
    }
}
export class VerifyKey extends Key<KeyType.Verify> {
    getKeyType(): KeyType.Verify { return KeyType.Verify };
}
export class SecretKey extends Key<"secret"> {
    getKeyType() { return KeyType.Secret };

    static generate(): SecretKey;
    static generate(password: string, salt: string): Promise<SecretKey>;
    static generate(password?: string, salt?: string): SecretKey | Promise<SecretKey> {
        if (password !== undefined && salt !== undefined) {
            return (window as any).argon2.hash({ pass: utf8.encode(password), salt: utf8.encode("42234223" + salt + "secret"), hashLen: 32, mem: 131072, time: 1, parallelism: 1, type: (window as any).argon2.ArgonType.Argon2id })
                .then((result: { hash: Uint8Array }) => Promise.resolve(new SecretKey(result.hash)))
                .catch(() => Promise.reject("error while generating key"));
        }

        return new SecretKey(nacl.randomBytes(32));
    }
}

export enum KeyType { Secret = "secretKey", Sign = "signKey", Verify = "verifyKey", Private = "privateKey", Public = "publicKey" }

function getKeyPair(privateKey: Uint8Array, keyType: KeyType.Sign | KeyType.Private): Promise<CryptoKeyPair> {
    let jwk: JsonWebKey = {};
    jwk.crv = "P-256";
    jwk.ext = true;
    jwk.kty = "EC";

    let publicKey = getCurveByName("secp256r1").G.multiply(privateKey).getEncoded(false);
    jwk.x = base64.encodeURLSafe(publicKey.slice(1, 33)).substr(0,43);
    jwk.y = base64.encodeURLSafe(publicKey.slice(33)).substr(0,43);
    jwk.key_ops = [];

    let privateJWK = { ...jwk, d: base64.encodeURLSafe(privateKey).substr(0,43), key_ops: keyType == KeyType.Sign ? ["sign"] : ["deriveKey"] };

    // TODO disallow export
    return Promise.all([
        crypto.subtle.importKey("jwk", privateJWK, { name: keyType == KeyType.Sign ? "ECDSA" : "ECDH", namedCurve: "P-256" }, true, privateJWK.key_ops),
        crypto.subtle.importKey("jwk", jwk, { name: keyType == KeyType.Sign ? "ECDSA" : "ECDH", namedCurve: "P-256" }, true, [])
    ]).then(keys => ({ privateKey: keys[0], publicKey: keys[1] }));
}