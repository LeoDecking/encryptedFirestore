import * as base64 from "@stablelib/base64";
import * as utf8 from "@stablelib/utf8";
import { Crypto } from "./Crypto";
import nacl from "tweetnacl";

abstract class Key<K extends string> {
    private _keyType?: K;

    string: string;
    uint8Array: Uint8Array;

    constructor(key: string | Uint8Array) {
        this.string = typeof key == "string" ? key : base64.encode(key);
        this.uint8Array = typeof key == "string" ? base64.decode(key) : key;
    }
    abstract getKeyType(): KeyType;

    encrypt(secretKey: SecretKey): string {
        // console.log("encrypt", this, secretKey, "=>", Crypto.encrypt(this.string, secretKey));
        return Crypto.encrypt(this.string, secretKey);
    }

    static decrypt<K>(this: new (key: string | Uint8Array) => K, encryptedKey: string, secretKey: SecretKey): K {
        // console.log("decrypt", encryptedKey, secretKey, "=>", Crypto.decrypt(encryptedKey, secretKey), new this(Crypto.decrypt(encryptedKey, secretKey)));
        return new this(Crypto.decrypt(encryptedKey, secretKey));
    }
}
// TODO different sign/secret salt
export class SignKey extends Key<"sign"> {
    verifyKey: VerifyKey;

    constructor(key: string | Uint8Array) {
        super(key);
        this.verifyKey = new VerifyKey(nacl.sign.keyPair.fromSecretKey(this.uint8Array).publicKey);
    }

    getKeyType() { return KeyType.Sign };

    static generate(): SignKey;
    static generate(password: string, salt: string): Promise<SignKey>;
    static generate(password?: string, salt?: string): SignKey | Promise<SignKey> {
        if (password !== undefined && salt !== undefined) {
            return (window as any).argon2.hash({ pass: utf8.encode(password), salt: utf8.encode("42234223" + salt + "sign"), hashLen: 32, mem: 131072, time: 1, parallelism: 1, type: (window as any).argon2.ArgonType.Argon2id })
                .then((result: { hash: Uint8Array }) => Promise.resolve(new SignKey(nacl.sign.keyPair.fromSeed(result.hash).secretKey)))
                .catch(() => Promise.reject("error while generating key"));
        }

        return new SignKey(nacl.randomBytes(64));
    }
}
export class VerifyKey extends Key<"verify"> {
    getKeyType() { return KeyType.Verify };
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

export enum KeyType { Secret = "secretKey", Sign = "signKey", Verify = "verifyKey" }