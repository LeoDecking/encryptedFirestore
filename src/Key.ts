import { DatabaseObjectType } from "./DatabaseObjectType";
import * as base64 from "@stablelib/base64";

class Key<K extends string, T extends DatabaseObjectType> {
    private _keyType?: K;
    private _objectType?: T;

    string: string;
    uint8Array: Uint8Array;

    constructor(_t: new (parent: T["parent"]) => T, key: string | Uint8Array) {
        this.string = typeof key == "string" ? key : base64.encode(key);
        this.uint8Array = typeof key == "string" ? base64.decode(key) : key;
    }
}

export class SignKey<T extends DatabaseObjectType> extends Key<"sign", T> { }
export class VerifyKey<T extends DatabaseObjectType> extends Key<"verify", T> { }
export class SecretKey<T extends DatabaseObjectType> extends Key<"secret", T> { }