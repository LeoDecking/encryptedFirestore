import * as base64 from "@stablelib/base64";
import * as utf8 from "@stablelib/utf8";
import { ObjectsCrypto } from "./ObjectsCrypto";
// import  from "ecurve";

import nacl from "tweetnacl";
import { Curve, getCurveByName } from "ecurve";

abstract class Key<K extends KeyType> {
    private _keyType?: K;

    key: CryptoKey;

    constructor(key: CryptoKey) {
        this.key = key;
    }

    abstract getKeyType(): K;

    // TODO subclass private/public key 0>move methods there (auch generate)
    // (+privateEncryption, publicEncryption)
    protected static getKeyPair(privateKey: Uint8Array, keyType: KeyType.Sign | KeyType.Private): Promise<CryptoKeyPair> {
        let jwk: JsonWebKey = {};
        jwk.crv = "P-256";
        jwk.ext = true;
        jwk.kty = "EC";

        let publicKey = getCurveByName("secp256r1").G.multiply(privateKey).getEncoded(false);
        jwk.x = base64.encodeURLSafe(publicKey.slice(1, 33)).substr(0, 43);
        jwk.y = base64.encodeURLSafe(publicKey.slice(33)).substr(0, 43);

        let privateJWK = { ...jwk, d: base64.encodeURLSafe(privateKey).substr(0, 43) };

        // TODO disallow private export
        return Promise.all([
            crypto.subtle.importKey("jwk", privateJWK, { name: keyType == KeyType.Sign ? "ECDSA" : "ECDH", namedCurve: "P-256" }, true, keyType == KeyType.Sign ? ["sign"] : ["deriveKey"]),
            crypto.subtle.importKey("jwk", jwk, { name: keyType == KeyType.Sign ? "ECDSA" : "ECDH", namedCurve: "P-256" }, true, keyType == KeyType.Sign ? ["verify"] : [])
        ]).then(keys => ({ privateKey: keys[0], publicKey: keys[1] }));
    }

    protected static getPublicKey(publicKey: string, keyType: KeyType.Sign | KeyType.Private): PromiseLike<CryptoKey> {
        let jwk: JsonWebKey = {};
        jwk.crv = "P-256";
        jwk.ext = true;
        jwk.kty = "EC";

        jwk.x = publicKey.substr(0, 43);
        jwk.y = publicKey.substr(43);

        return crypto.subtle.importKey("jwk", jwk, { name: keyType == KeyType.Sign ? "ECDSA" : "ECDH", namedCurve: "P-256" }, true, keyType == KeyType.Sign ? ["verify"] : []);
    }
}
export class SignKey extends Key<KeyType.Sign> {
    keyType = KeyType.Sign;

    verifyKey: VerifyKey;

    constructor(keyPair: CryptoKeyPair) {
        super(keyPair.privateKey);
        this.verifyKey = new VerifyKey(keyPair.publicKey);
    }

    getKeyType(): KeyType.Sign { return KeyType.Sign };

    static async generate(password?: string, salt?: string): Promise<SignKey> {
        if (password !== undefined && salt !== undefined) {
            let hashResult: { hash: Uint8Array } = await (window as any).argon2.hash({ pass: utf8.encode(password), salt: utf8.encode("42234223" + salt + "sign"), hashLen: 32, mem: 131072, time: 1, parallelism: 1, type: (window as any).argon2.ArgonType.Argon2id });
            let keyPair = await Key.getKeyPair(hashResult.hash, KeyType.Sign);
            return new SignKey(keyPair);
        }
        return new SignKey(await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]));
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