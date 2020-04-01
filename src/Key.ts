import * as base64 from "@stablelib/base64";
import { Crypto } from "./Crypto";

class Key<K extends string> {
    private _keyType?: K;

    string: string;
    uint8Array: Uint8Array;

    // TODO warum so viele neue keys?
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

export class SignKey extends Key<"sign"> { }
export class VerifyKey extends Key<"verify"> { }
export class SecretKey extends Key<"secret"> { }