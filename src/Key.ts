import * as base64 from "@stablelib/base64";
import * as utf8 from "@stablelib/utf8";

import { getCurveByName } from "ecurve";

abstract class Key<K extends KeyType> {
    abstract keyType: K;
    abstract alorithm: string;
    abstract keyUsages: string[];

    readonly key?: CryptoKey;

    constructor(key?: CryptoKey) {
        this.key = key;
    }
}

abstract class PrivateKey<K extends KeyType, Pub extends PublicKey<KeyType>> extends Key<K> {
    readonly publicKey: Pub;
    protected readonly publicConstructor?: new (key: CryptoKey) => Pub;

    constructor(keyPair: CryptoKeyPair) {
        super(keyPair.privateKey);
        this.publicKey = new this.publicConstructor!(keyPair.publicKey);
    }

    static async import<K extends PrivateKey<KeyType, PublicKey<KeyType>>>(this: new (keyPair?: CryptoKeyPair) => K, privateKey: Uint8Array): Promise<K> {
        let jwk: JsonWebKey = {};
        jwk.crv = "P-256";
        jwk.ext = true;
        jwk.kty = "EC";

        let publicKey = getCurveByName("secp256r1").G.multiply(privateKey).getEncoded(false);
        jwk.x = base64.encodeURLSafe(publicKey.slice(1, 33)).substr(0, 43);
        jwk.y = base64.encodeURLSafe(publicKey.slice(33)).substr(0, 43);

        let privateJWK = { ...jwk, d: base64.encodeURLSafe(privateKey).substr(0, 43) };

        let dummy = new this();

        // TODO disallow private export
        return new this(await Promise.all([
            crypto.subtle.importKey("jwk", privateJWK, { name: dummy.alorithm, namedCurve: "P-256" }, true, dummy.keyUsages),
            crypto.subtle.importKey("jwk", jwk, { name: dummy.alorithm, namedCurve: "P-256" }, true, dummy.publicKey.keyUsages)
        ]).then(keys => ({ privateKey: keys[0], publicKey: keys[1] })));
    }

    static async generate<K extends PrivateKey<KeyType, PublicKey<KeyType>>>(this: new (keyPair?: CryptoKeyPair) => K, password: string, salt: string): Promise<K> {
        let dummy = new this();
        let result = await (window as any).argon2.hash({ pass: utf8.encode(password), salt: utf8.encode(salt + dummy.keyType), hashLen: 32, mem: 131072, time: 1, parallelism: 1, type: (window as any).argon2.ArgonType.Argon2id });
        return await PrivateKey.import.call(this, result.hash);
    }
}

abstract class PublicKey<K extends KeyType> extends Key<K> {
    static async import<K extends PublicKey<KeyType>>(this: new (key?: CryptoKey) => K, publicKey: string): Promise<K> {
        let jwk: JsonWebKey = {};
        jwk.crv = "P-256";
        jwk.ext = true;
        jwk.kty = "EC";

        jwk.x = publicKey.substr(0, 43);
        jwk.y = publicKey.substr(43);

        let dummy = new this();

        return new this(await crypto.subtle.importKey("jwk", jwk, { name: dummy.alorithm, namedCurve: "P-256" }, true, dummy.keyUsages));
    }

    async export(): Promise<string> {
        let jwk = await crypto.subtle.exportKey("jwk", this.key!);
        return jwk.x! + jwk.y!;
    }
}

export class SignKey extends PrivateKey<KeyType.Sign, VerifyKey> {
    readonly keyType = KeyType.Sign;
    readonly alorithm = "ECDSA";
    readonly keyUsages = ["sign"];

    protected readonly publicConstructor = VerifyKey;
}
export class VerifyKey extends PublicKey<KeyType.Verify> {
    readonly keyType = KeyType.Verify;
    readonly alorithm = "ECDSA";
    readonly keyUsages = ["verify"];
}
export class PrivateEncryptionKey extends PrivateKey<KeyType.PrivateEncryption, PublicEncryptionKey> {
    readonly keyType = KeyType.PrivateEncryption;
    readonly alorithm = "ECDH";
    readonly keyUsages = ["deriveKey"];

    protected readonly publicConstructor = PublicEncryptionKey;
}
export class PublicEncryptionKey extends PublicKey<KeyType.PublicEncryption> {
    readonly keyType = KeyType.PublicEncryption;
    readonly alorithm = "ECDH";
    readonly keyUsages = [];
}
export class SecretKey extends Key<KeyType.Secret> {
    readonly keyType = KeyType.Secret;
    readonly alorithm = "AES-GCM";
    readonly keyUsages = ["encrypt", "decrypt"];

    static async import(secretKey: Uint8Array): Promise<SecretKey> {
        let dummy = new this();
        return new this(await crypto.subtle.importKey("raws", secretKey, dummy.alorithm, true, dummy.keyUsages));
    }

    static async generate(password?: string, salt?: string): Promise<SecretKey> {
        let dummy = new this();
        let result = password
            ? await (window as any).argon2.hash({ pass: utf8.encode(password), salt: utf8.encode((salt ?? "") + dummy.keyType), hashLen: 32, mem: 131072, time: 1, parallelism: 1, type: (window as any).argon2.ArgonType.Argon2id })
            : crypto.getRandomValues(new Uint8Array(32));
        return await SecretKey.import.call(this, result.hash);
    }

    async wrap(secretKey: DHSecrectKey): Promise<string> {
        // TODO wrap
        return "";
    }

    static async unwrap(wrapped: string, secretKey: DHSecrectKey): Promise<SecretKey> {
        // TODO unwrap
        return new SecretKey();
    }

}
export class DHSecrectKey extends SecretKey {
    static async import(secretKey: Uint8Array): Promise<DHSecrectKey> {
        let dummy = new this();
        return new this(await crypto.subtle.importKey("raws", secretKey, dummy.alorithm, false, dummy.keyUsages));
    }

    static async derive(privateEncryptionKey: PrivateEncryptionKey, publicEncryptionKey: PublicEncryptionKey): Promise<DHSecrectKey> {
        // TODO derive
        return new DHSecrectKey();
    }
}

export enum KeyType { Secret = "secretKey", Sign = "signKey", Verify = "verifyKey", PrivateEncryption = "privateEncryptionKey", PublicEncryption = "publicEncryptionKey" };