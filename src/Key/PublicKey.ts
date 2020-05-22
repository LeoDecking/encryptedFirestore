import { ObjectsKeyType } from "./Keys";
import { Key } from "./Key";

export abstract class PublicKey<K extends ObjectsKeyType> extends Key<K>{

    export: PromiseLike<string>;

    constructor(key?: CryptoKey, string?: string) {
        super(key);

        if (!key) this.export = Promise.resolve("");
        else if (string) this.export = Promise.resolve(string);
        else this.export = crypto.subtle.exportKey("jwk", this.key!).then(jwk => jwk.x! + jwk.y!);
    }

    static async import<K extends PublicKey<ObjectsKeyType>>(this: new (key?: CryptoKey, string?: string) => K, publicKey: string): Promise<K> {
        let jwk: JsonWebKey = {};
        jwk.crv = "P-256";
        jwk.ext = true;
        jwk.kty = "EC";
        jwk.x = publicKey.substr(0, 43);
        jwk.y = publicKey.substr(43);
        let dummy = new this();
        return new this(await crypto.subtle.importKey("jwk", jwk, { name: dummy.alorithm, namedCurve: "P-256" }, true, dummy.keyUsages), jwk.x! + jwk.y!);
    }
}

export class VerifyKey extends PublicKey<ObjectsKeyType.Verify> {
    readonly keyType = ObjectsKeyType.Verify;
    readonly alorithm = "ECDSA";
    readonly keyUsages = ["verify"];
}

export class PublicEncryptionKey extends PublicKey<ObjectsKeyType.PublicEncryption> {
    readonly keyType = ObjectsKeyType.PublicEncryption;
    readonly alorithm = "ECDH";
    readonly keyUsages = [];
}
