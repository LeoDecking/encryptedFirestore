import * as utf8 from "@stablelib/utf8";
import * as base64 from "@stablelib/base64";
import { SignKey, VerifyKey, SecretKey, PrivateEncryptionKey, PublicEncryptionKey, DHSecrectKey } from "./Key";

// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto

export class ObjectsCrypto {
    static sign(object: any, signKey: SignKey): PromiseLike<string> {
        // console.log("sign", ObjectsCrypto.sortObject(object), signKey, base64.encode(nacl.sign.detached(utf8.encode(JSON.stringify(ObjectsCrypto.sortObject(object))), signKey.uint8Array)))
        return crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-512" } }, signKey.key!, utf8.encode(JSON.stringify(ObjectsCrypto.sortObject(object))))
            .then(signature => base64.encode(new Uint8Array(signature)));
    }

    static verify(object: any, signature: string, verifyKey: VerifyKey): PromiseLike<boolean> {
        return crypto.subtle.verify({ name: "ECFSA", hash: { name: "SHA-512" } }, verifyKey.key!, base64.decode(signature), utf8.encode(JSON.stringify(ObjectsCrypto.sortObject(object))));
    }

    static encrypt(object: any, secretKey: SecretKey): PromiseLike<string> {
        let iv: Uint8Array = ObjectsCrypto.getRandomBytes(12);

        return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, secretKey.key!, utf8.encode(JSON.stringify(ObjectsCrypto.sortObject(object))))
            .then(encrypted => base64.encode(iv) + base64.encode(new Uint8Array(encrypted)));
    }

    static decrypt(encryptedObject: string, secretKey: SecretKey): PromiseLike<any> {
        return crypto.subtle.decrypt({ name: "AES-GCM", iv: base64.decode(encryptedObject.substr(0, 16)) }, secretKey.key!, base64.decode(encryptedObject.substr(16)))
            .then(decrypted => ObjectsCrypto.sortObject(JSON.parse(utf8.decode(new Uint8Array(decrypted)))));
    }

    static async wrapKey(key: SecretKey, privateEncryptionKey: PrivateEncryptionKey, publicEncryptionKey: string): Promise<string> {
        let derivedKey = await DHSecrectKey.derive(privateEncryptionKey, await PublicEncryptionKey.import(publicEncryptionKey));
        return await key.wrap(derivedKey);
    }

    static hash(object: any): PromiseLike<string> {
        return crypto.subtle.digest("SHA-512", utf8.encode(JSON.stringify(ObjectsCrypto.sortObject(object)))).then(digest => base64.encode(new Uint8Array(digest)));
    }

    static getRandomBytes(length: number) {
        return crypto.getRandomValues(new Uint8Array(length));
    }


    static sortObject(object: any, parseDate: boolean = false): any {
        if (object == null || object == undefined) return null;
        if (object instanceof Date) return object;

        if (Array.isArray(object)) {
            let newObject = [];
            for (let i = 0; i < object.length; i++) newObject[i] = ObjectsCrypto.sortObject(object[i], parseDate);
            return newObject;
        }
        if (typeof object == "object") {
            let newObject: { [key: string]: any } = {};
            Object.keys(object).sort().forEach(k => newObject[k] = ObjectsCrypto.sortObject(object[k], parseDate));
            return newObject;
        }
        if (parseDate && typeof object == "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(object)) return new Date(object);

        return object;
    }

}