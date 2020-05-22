import {  ObjectsKeyType, PrivateEncryptionKey, PublicEncryptionKey } from "./Keys";
import * as utf8 from "@stablelib/utf8";
import * as base64 from "@stablelib/base64";

// SecretKeys können exportiert werden, deswegen wird jedes Mal ein neuer generiert
export class SecretKey {
    readonly keyType = ObjectsKeyType.Secret;
    readonly alorithm = "AES-GCM";
    readonly keyUsages = ["encrypt", "decrypt"];


    readonly key?: CryptoKey;

    constructor(key?: CryptoKey) {
        this.key=key;
    }

    static async import(secretKey: Uint8Array): Promise<SecretKey> {
        let dummy = new this();
        return new this(await crypto.subtle.importKey("raw", secretKey, dummy.alorithm, true, dummy.keyUsages));
    }

    static async generate(password?: string, salt?: string): Promise<SecretKey> {
        let dummy = new this();
        let result = password
            ? await (window as any).argon2.hash({ pass: utf8.encode(password), salt: utf8.encode((salt ?? "") + dummy.keyType), hashLen: 32, mem: 131072, time: 1, parallelism: 1, type: (window as any).argon2.ArgonType.Argon2id })
            : crypto.getRandomValues(new Uint8Array(32));
        return await SecretKey.import.call(this, result.hash);
    }

    async export(): Promise<string> {
        return base64.encode(new Uint8Array(await crypto.subtle.exportKey("raw", this.key!)));
    }
}
