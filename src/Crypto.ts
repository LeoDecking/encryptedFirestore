import nacl from "tweetnacl";

import * as utf8 from "@stablelib/utf8";
import * as base64 from "@stablelib/base64";
import { SignKey, VerifyKey, SecretKey } from "./Key";

// TODO https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto

export class Crypto {


    static sign(object: any, signKey: SignKey): string {
        console.log("sign", Crypto.sortObject(object), signKey, base64.encode(nacl.sign.detached(utf8.encode(JSON.stringify(Crypto.sortObject(object))), signKey.uint8Array)))
        return base64.encode(nacl.sign.detached(utf8.encode(JSON.stringify(Crypto.sortObject(object))), signKey.uint8Array));
    }

    static verify(object: any, signature: string, verifyKey: VerifyKey): boolean {
        try {
            // console.log("verify", Crypto.sortObject(object), signature, verifyKey, nacl.sign.detached.verify(utf8.encode(JSON.stringify(Crypto.sortObject(object))), base64.decode(signature), verifyKey.uint8Array));
            return nacl.sign.detached.verify(utf8.encode(JSON.stringify(Crypto.sortObject(object))), base64.decode(signature), verifyKey.uint8Array);
        } catch {
            return false;
        }
    }

    static encrypt(object: any, secretKey: SecretKey): string {
        try {
            let nonce: Uint8Array = nacl.randomBytes(24);
            return base64.encode(nonce) + base64.encode(nacl.secretbox(utf8.encode(JSON.stringify(Crypto.sortObject(object))), nonce, secretKey.uint8Array));
        } catch { return ""; }
    }

    static decrypt(encryptedObject: string, secretKey: SecretKey): any {
        try {
            let uint8array = nacl.secretbox.open(base64.decode(encryptedObject.substr(32)), base64.decode(encryptedObject.substr(0, 32)), secretKey.uint8Array);
            if (!uint8array) return undefined; // TODO error
            else return Crypto.sortObject(JSON.parse(utf8.decode(uint8array)));
        } catch { throw new Error("error while decrypting"); }
    }

    static hash(object: any): string {
        return base64.encode(nacl.hash(utf8.encode(JSON.stringify(Crypto.sortObject(object)))));
    }

    static sortObject(object: any, parseDate: boolean = false): any {
        if (object == null || object == undefined) return null;
        if (object instanceof Date) return object;

        if (Array.isArray(object)) {
            let newObject = [];
            for (let i = 0; i < object.length; i++) newObject[i] = Crypto.sortObject(object[i], parseDate);
            return newObject;
        }
        if (typeof object == "object") {
            let newObject: { [key: string]: any } = {};
            Object.keys(object).sort().forEach(k => newObject[k] = Crypto.sortObject(object[k], parseDate));
            return newObject;
        }
        if (parseDate && typeof object == "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(object)) return new Date(object);

        return object;
    }

}