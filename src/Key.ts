import * as base64 from "@stablelib/base64";
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
    encrypt(secretKey: SecretKey): string {
        // console.log("encrypt", this, secretKey, "=>", Crypto.encrypt(this.string, secretKey));
        return Crypto.encrypt(this.string, secretKey);
    }

    static decrypt<K>(this: new (key: string | Uint8Array) => K, encryptedKey: string, secretKey: SecretKey): K {
        // console.log("decrypt", encryptedKey, secretKey, "=>", Crypto.decrypt(encryptedKey, secretKey), new this(Crypto.decrypt(encryptedKey, secretKey)));
        return new this(Crypto.decrypt(encryptedKey, secretKey));
    }
}

export class SignKey extends Key<"sign"> {
    verifyKey: VerifyKey;

    constructor(key: string | Uint8Array) {
        super(key);
        this.verifyKey = new VerifyKey(nacl.sign.keyPair.fromSecretKey(this.uint8Array).publicKey);
    }

    static generate(): SignKey {
        return new SignKey(nacl.randomBytes(64));
    }
}
export class VerifyKey extends Key<"verify"> { }
export class SecretKey extends Key<"secret"> {
    static generate(): SignKey {
        return new SignKey(nacl.randomBytes(32));
    }
}