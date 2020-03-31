import nacl from "tweetnacl";

import * as utf8 from "@stablelib/utf8";
import * as base64 from "@stablelib/base64";
import { SignKey, VerifyKey, SecretKey } from "./Key";

export class Crypto {


    public static sign(object: any, signKey: SignKey): string {
        return base64.encode(nacl.sign.detached(utf8.encode(JSON.stringify(object)), signKey.uint8Array));
    }

    public static verify(object: any, signature: string, verifyKey: VerifyKey): boolean {
        try {
            return nacl.sign.detached.verify(utf8.encode(JSON.stringify(object)), base64.decode(object.signature), verifyKey.uint8Array);
        } catch {
            return false;
        }
    }

    public static encrypt(object: any, secretKey: SecretKey): string {
        try {
            let nonce: Uint8Array = nacl.randomBytes(24);
            return base64.encode(nonce) + base64.encode(nacl.secretbox(utf8.encode(JSON.stringify(object)), nonce, secretKey.uint8Array));
        } catch { return ""; }
    }

    public static decrypt(encryptedObject: string, secretKey: SecretKey): any {
        try {
            let uint8array = nacl.secretbox.open(base64.decode(encryptedObject.substr(32)), base64.decode(encryptedObject.substr(0, 32)), secretKey.uint8Array);
            if (!uint8array) return undefined;
            else return JSON.parse(utf8.decode(uint8array));
        } catch { return undefined; }
    }

    public static hash(object: any): string {
        return base64.encode(nacl.hash(utf8.encode(JSON.stringify(object))));
    }

}