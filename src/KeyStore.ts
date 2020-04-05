import { VerifyKey, SignKey, SecretKey } from "./Key";
import { DatabaseObjectType } from "./DatabaseObjectType";
import { App } from "./App";
import { Crypto } from "./Crypto";

export class KeyStore {
    // keys are still encrypeted with storageKeySecret/storageKeySign
    private keys: { [path: string]: { signKey?: string, secretKey?: string } };

    private getStorageKeySecret: () => Promise<SecretKey>;
    private getStorageKeySign: () => Promise<SecretKey>;

    constructor(json: string, getStorageKeySecret: () => Promise<SecretKey>, getStorageKeySign: () => Promise<SecretKey>) {
        this.keys = JSON.parse(json);
        this.getStorageKeySecret = getStorageKeySecret;
        this.getStorageKeySign = getStorageKeySign;
    }

    // TODO catches

    export(): string {
        return JSON.stringify(this.keys);
    }

    // TODO auch für signkeys??
    // TODO Achtung: Owner kann secretKey ändern und falschen Key rausgeben, kann dann nicht mehr von oben kontrolliert werden :(
    // Es können nur Objekte direkt gesehen werden, die parent (n-ten Grades) vom object sind
    // 1. SecretKey im KeyStore gespeichert
    // 2. SecretKey verlinkt, der im KeyStore gespeichert ist
    // 3. SecrentKey vom nächstbesten Parent verlinkt (nur der "niedrigste" Parent, der verlinkt ist, wird betrachtet), auf den 1. oder 2. oder 3. zutrifft
    private async getSecretKey(object: DatabaseObjectType, storageKeySecretPromise: Promise<SecretKey> = this.getStorageKeySecret()): Promise<SecretKey> {
        console.log("getSecretKey", object.path);
        // TODO catch
        try {

            let storageKeySecret = await storageKeySecretPromise;

            if (this.keys[object.path]?.secretKey) { console.log(1, SecretKey.decrypt(this.keys[object.path].secretKey!, storageKeySecret)); return SecretKey.decrypt(this.keys[object.path]?.secretKey!, storageKeySecret); }
            else {
                let path = Object.keys(object.encryptedSecretKey).find(p => this.keys[p]?.secretKey);
                if (path) { console.log(2); return Crypto.decrypt(object.encryptedSecretKey[path], SecretKey.decrypt(this.keys[path].secretKey!, storageKeySecret)); }
                else {
                    let current: DatabaseObjectType = object;
                    // TODO nochmal drüber nachdenken
                    while (!App.isApp(current.owner)) {
                        current = current.owner;
                        if (object.encryptedSecretKey[current.path]) {
                            console.log("owner", current);
                            return Crypto.decrypt(object.encryptedSecretKey[current.path], await this.getSecretKey(current, storageKeySecretPromise));
                        }
                    }
                }
                throw new Error("no secretkey");
            }
        } catch (error) {
            console.log(error);
            throw new Error(error);
        }
    }

    encrypt(object: DatabaseObjectType, property: any): Promise<string> {
        return this.getSecretKey(object).then(key => Crypto.encrypt(property, key));
    }

    decrypt(object: DatabaseObjectType, property: string): Promise<any> {
        return this.getSecretKey(object).then(key => Crypto.decrypt(property, key));
    }

    sign<T extends DatabaseObjectType>(owner: DatabaseObjectType | App, object: T): Promise<T & { signature: string }> {
        if (!this.keys[owner.path]?.signKey) return Promise.reject("no signkey");
        return this.getStorageKeySign().then(storageKeySign => ({ ...object, signature: Crypto.sign(object, SignKey.decrypt(this.keys[owner.path].signKey!, storageKeySign)) }));
    }

    verify<T extends DatabaseObjectType>(owner: DatabaseObjectType | App, object: T & { signature: string }): T {
        if (!object) throw new Error("undefined object");
        if (!owner.verifyKey) throw new Error("no verifykey");
        let o = { ...object };
        delete o.signature;
        if (Crypto.verify(o, object.signature, owner.verifyKey!))
            return o;
        else
            throw new Error("wrong signature");
    }
}