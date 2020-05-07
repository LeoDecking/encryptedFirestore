import { VerifyKey, SignKey, SecretKey, KeyType } from "./Key";
import { DatabaseObjectType } from "./DatabaseObjectType";
import { App } from "./App";
import { Crypto } from "./Crypto";

// TODO has key
export class KeyStore {
    private keys: { [path: string]: { secretKey?: { key: string, persistent: boolean, prompt: boolean }, signKey?: { key: string, persistent: boolean, prompt: boolean } } };

    private passwordHash: string;

    private getStoragePassword: (passwordHash: string) => Promise<string>;

    loadStorageKey: Promise<SecretKey>;

    // TODO no persistentKey set?
    // TODO check storageKey
    // TODO public password hashes safe? -> encrypted path + version? / argon2 hash

    constructor(json: string, storagePassword: string, getStoragePassword: (passwordHash: string) => Promise<string>) {
        this.keys = JSON.parse(json);
        this.passwordHash = Crypto.hash(storagePassword);
        this.getStoragePassword = getStoragePassword;

        this.loadStorageKey = SecretKey.generate(storagePassword, "withoutPrompt");
    }

    export(): string {
        let persistentKeys: KeyStore["keys"] = {};
        Object.entries(this.keys).forEach(k => {
            if (k[1].secretKey?.persistent || k[1].signKey?.persistent) {
                persistentKeys[k[0]] = {};
                if (k[1].secretKey?.persistent) persistentKeys[k[0]].secretKey = k[1].secretKey;
                if (k[1].signKey?.persistent) persistentKeys[k[0]].signKey = k[1].signKey;
            };
        });
        return JSON.stringify(persistentKeys);
    }

    // returns passwordHash
    async setStoragePassword(oldPassword: string, newPassword: string): Promise<string> {
        if (Crypto.hash(oldPassword) != this.passwordHash) throw new Error("wrong password");

        let oldKeyContainer = new KeyContainer(oldPassword);
        let newStorageKey = await SecretKey.generate(newPassword, "withoutPrompt");
        let newStoragePromptKey = await SecretKey.generate(newPassword, "prompt");

        await Promise.all(Object.keys(this.keys).map(async k => {
            let keys = this.keys[k]
            if (keys.secretKey) keys.secretKey.key = SecretKey.decrypt(keys.secretKey.key, await this.getStorageKey(keys.secretKey.prompt, oldKeyContainer)).encrypt(keys.secretKey.prompt ? newStoragePromptKey : newStorageKey);
            if (keys.signKey) keys.signKey.key = SecretKey.decrypt(keys.signKey.key, await this.getStorageKey(keys.signKey.prompt, oldKeyContainer)).encrypt(keys.signKey.prompt ? newStoragePromptKey : newStorageKey);
        }));

        this.loadStorageKey = Promise.resolve(newStorageKey);
        return this.passwordHash = Crypto.hash(newPassword);
    }

    private async getStorageKey(prompt: boolean, keyContainer: KeyContainer): Promise<SecretKey> {
        if (prompt) {
            if (keyContainer.storagePromptKey) return keyContainer.storagePromptKey;

            if (!keyContainer.storagePassword) keyContainer.storagePassword = this.getStoragePassword(this.passwordHash).catch(() => Promise.resolve());
            // TODO retry if wrong password
            let storagePassword = await keyContainer.storagePassword;
            // TODO there will be many error messages
            if (!storagePassword) throw new Error("password not entered");

            keyContainer.storagePromptKey = await SecretKey.generate(storagePassword, "prompt");
            delete keyContainer.storagePassword;

            return keyContainer.storagePromptKey;
        } else {
            return await this.loadStorageKey;
        }
    }

    getKeyPaths(): string[] {
        return Object.keys(this.keys);
    }

    // TODO canSign/canRead
    // TODO test
    async setPassword(path: string, password: string, secretKeyOptions: StorageOptions = { store: "none" }, signKeyOptions: StorageOptions = { store: "none" }, keyContainer: KeyContainer = new KeyContainer()): Promise<KeyContainer> {
        await Promise.all([
            secretKeyOptions.store == "none" ? Promise.resolve() : SecretKey.generate(password, path).then(async secretKey => this.setKey(secretKey, path, secretKeyOptions, keyContainer)),
            signKeyOptions.store == "none" ? Promise.resolve() : SignKey.generate(password, path).then(async signKey => this.setKey(signKey, path, signKeyOptions, keyContainer))
        ] as Promise<KeyContainer | void>[]);
        return keyContainer;
    }

    // TODO überprüfen, ob richtig?
    async setKey(key: SecretKey | SignKey, path: string, storageOptions: StorageOptions = { store: "once" }, keyContainer: KeyContainer = new KeyContainer()): Promise<KeyContainer> {
        if (storageOptions.store == "once") {
            if (!keyContainer.keys[path]) keyContainer.keys[path] = {};
            (keyContainer.keys[path] as { [type: string]: SecretKey | SignKey })[key.getKeyType()] = key;
        }
        else {
            if (!this.keys[path]) this.keys[path] = {};
            this.keys[path][key.getKeyType() as KeyType.Secret | KeyType.Sign] = {
                key: key.encrypt(await this.getStorageKey(storageOptions.storageKeyPrompt == "always", keyContainer)),
                persistent: storageOptions.store == "persistent",
                prompt: storageOptions.storageKeyPrompt == "always"
            };
        }
        return keyContainer;
    }

    async deletePassword(path: string) {
        delete this.keys[path];
    }
    async deleteKey(type: KeyType.Secret | KeyType.Sign, path: string) {
        delete this.keys[path][type == KeyType.Secret ? "secretKey" : "signKey"];
    }

    private async decryptSecretKey(key: { key: string, persistent: boolean, prompt: boolean }, keyContainer: KeyContainer): Promise<SecretKey> {
        return SecretKey.decrypt(key.key, await this.getStorageKey(key.prompt, keyContainer));
    }
    private async decryptSignKey(key: { key: string, persistent: boolean, prompt: boolean }, keyContainer: KeyContainer): Promise<SignKey> {
        return SignKey.decrypt(key.key, await this.getStorageKey(key.prompt, keyContainer));
    }

    // TODO auch für signkeys??
    // TODO Achtung: Owner kann secretKey ändern und falschen Key rausgeben, kann dann nicht mehr von oben kontrolliert werden :(
    // Es können nur Objekte direkt gesehen werden, die parent (n-ten Grades) vom object sind
    // 1. SecretKey im KeyStore gespeichert
    // 2. SecretKey verlinkt, der im KeyStore gespeichert ist
    // 3. SecrentKey vom nächstbesten Parent verlinkt (nur der "niedrigste" Parent, der verlinkt ist, wird betrachtet), auf den 1. oder 2. oder 3. zutrifft
    private async getSecretKey(object: DatabaseObjectType, keyContainer: KeyContainer): Promise<SecretKey> {
        // console.log("getSecretKey", object.path);
        // TODO catch
        try {
            if (this.keys[object.path]?.secretKey) {
                // console.log(1, SecretKey.decrypt(this.keys[object.path].secretKey!, storageKeySecret));
                return await this.decryptSecretKey(this.keys[object.path].secretKey!, keyContainer);
            }
            else {
                let path = Object.keys(object.encryptedSecretKey).find(p => this.keys[p]?.secretKey);
                if (path) {
                    // console.log(2);
                    return SecretKey.decrypt(object.encryptedSecretKey[path], await this.decryptSecretKey(this.keys[path].secretKey!, keyContainer));
                }
                else {
                    let current: DatabaseObjectType = object;
                    // TODO nochmal drüber nachdenken
                    while (!App.isApp(current.owner)) {
                        current = current.owner;
                        if (object.encryptedSecretKey[current.path]) {
                            console.log("owner", current);
                            return SecretKey.decrypt(object.encryptedSecretKey[current.path], await this.getSecretKey(current, keyContainer));
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

    encrypt(object: DatabaseObjectType, property: any, keyContainer: KeyContainer = new KeyContainer()): Promise<string> {
        return this.getSecretKey(object, keyContainer).then(key => Crypto.encrypt(property, key));
    }

    decrypt(object: DatabaseObjectType, property: string, keyContainer: KeyContainer = new KeyContainer()): Promise<any> {
        return this.getSecretKey(object, keyContainer).then(key => Crypto.decrypt(property, key));
    }

    // TODO getSignKey
    sign<T extends DatabaseObjectType>(owner: DatabaseObjectType | App, object: T, keyContainer: KeyContainer = new KeyContainer()): Promise<T & { signature: string }> {
        if (!this.keys[owner.path]?.signKey) return Promise.reject("no signkey");
        return this.decryptSignKey(this.keys[owner.path].signKey!, keyContainer).then(signKey => ({ ...Crypto.sortObject(object), signature: Crypto.sign(object, signKey) }));
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
// TODO Achtung: man kann keyStore.encrypt ein keyContainerObjekt übergeben, welches dann befüllt wird😬
// TODO include in getSecretKey
export class KeyContainer {
    storagePromptKey?: SecretKey;
    storagePassword?: Promise<string | void>;

    keys: { [path: string]: { secretKey?: SecretKey, signKey?: SignKey } } = {};

    constructor(storagePassword?: string) {
        if (storagePassword) this.storagePassword = Promise.resolve(storagePassword);
    }
}

export interface StorageOptions {
    store: "none" | "once" | "session" | "persistent";
    storageKeyPrompt?: "once" | "always";
}