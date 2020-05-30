import { DatabaseObjectType, GetOwner } from "./DatabaseObjectType";
import { App } from "./App";
import { SecretKey, ObjectsCrypto, SignKey, PrivateEncryptionKey } from "objects-crypto";

type Keys = { [path: string]: { privateEncryptionKey?: { encryptedKey: string, persistent: boolean, prompt: boolean, key?: PrivateEncryptionKey }, signKey?: { encryptedKey: string, persistent: boolean, prompt: boolean, key?: SignKey } } };

// TODO has key
export class KeyStore {
    private loadKeys: Promise<Keys>;

    private passwordCheck: Promise<string>;

    private getStoragePassword: (passwordCheck: string) => Promise<string>;

    // TODO no persistentKey set?
    // TODO check storageKey

    constructor(json: string, storagePassword: string, getStoragePassword: (passwordCheck: string) => Promise<string>) {
        this.getStoragePassword = getStoragePassword;

        let generateStorageKey = SecretKey.generate(storagePassword, "withoutPrompt");
        this.passwordCheck = generateStorageKey.then(k => ObjectsCrypto.encrypt(true, k));

        this.loadKeys = generateStorageKey.then(async storageKey => {
            let keys: Keys = JSON.parse(json);
            let values = Object.values(keys);

            await Promise.all([
                ...values.filter(p => p.privateEncryptionKey && !p.privateEncryptionKey.prompt).map(async k => k.privateEncryptionKey!.key = await PrivateEncryptionKey.import(await ObjectsCrypto.decrypt(k.privateEncryptionKey!.encryptedKey, storageKey))),
                ...values.filter(p => p.signKey && !p.signKey.prompt).map(async k => k.signKey!.key = await SignKey.import(await ObjectsCrypto.decrypt(k.signKey!.encryptedKey, storageKey)))
            ] as Promise<PrivateEncryptionKey | SignKey>[]);

            return keys;
        });
    }

    async export(): Promise<string> {
        let persistentKeys: Keys = {};
        Object.entries(await this.loadKeys).forEach(k => {
            if (k[1].privateEncryptionKey?.persistent || k[1].signKey?.persistent) {
                persistentKeys[k[0]] = {};
                if (k[1].privateEncryptionKey?.persistent) persistentKeys[k[0]].privateEncryptionKey = { ...k[1].privateEncryptionKey, key: undefined };
                if (k[1].signKey?.persistent) persistentKeys[k[0]].signKey = { ...k[1].signKey, key: undefined };
            };
        });
        return JSON.stringify(persistentKeys);
    }

    async setStoragePassword(oldPassword: string, newPassword: string): Promise<void> {

        let oldStorageKey = await SecretKey.generate(oldPassword, "withoutPrompt");
        if (!await ObjectsCrypto.decrypt(await this.passwordCheck, oldStorageKey).then(null, () => false)) throw new Error("wrong password");

        let [oldStoragePromptKey, newStorageKey, newStoragePromptKey] = await Promise.all([SecretKey.generate(oldPassword, "prompt"), SecretKey.generate(newPassword, "withoutPrompt"), SecretKey.generate(newPassword, "prompt")]);

        let values = Object.values(await this.loadKeys);

        await Promise.all([
            ...values.filter(p => p.privateEncryptionKey).map(async k => k.privateEncryptionKey!.encryptedKey = await ObjectsCrypto.encrypt(
                await ObjectsCrypto.decrypt(k.privateEncryptionKey!.encryptedKey, k.privateEncryptionKey!.prompt ? oldStoragePromptKey : oldStorageKey),
                k.privateEncryptionKey!.prompt ? newStoragePromptKey : newStorageKey)),
            ...values.filter(p => p.signKey).map(async k => k.signKey!.encryptedKey = await ObjectsCrypto.encrypt(
                await ObjectsCrypto.decrypt(k.signKey!.encryptedKey, k.signKey!.prompt ? oldStoragePromptKey : oldStorageKey),
                k.signKey!.prompt ? newStoragePromptKey : newStorageKey)),
        ] as Promise<string>[]);

        this.passwordCheck = Promise.resolve().then(() => ObjectsCrypto.encrypt(true, newStorageKey));
    }

    decryptPromptKeys(keys: Keys, storagePassword?: string): [KeyContainer["promptPrivateEncryptionKeys"], KeyContainer["promptSignKeys"]] {
        let storagePromptKey = (storagePassword ? Promise.resolve(storagePassword) : this.passwordCheck.then(c => this.getStoragePassword(c))).then(password => SecretKey.generate(password, "prompt"));

        return [
            storagePromptKey.then(storageKey =>
                Promise.all(Object.entries(keys).filter(k => k[1].privateEncryptionKey?.prompt).map(async k => [k[0], await PrivateEncryptionKey.import(await ObjectsCrypto.decrypt(k[1].privateEncryptionKey!.encryptedKey, storageKey))] as [string, PrivateEncryptionKey])))
                .then(keys => keys.reduce((o, k) => { o[k[0]] = k[1]; return o; }, {} as { [path: string]: PrivateEncryptionKey })),
            storagePromptKey.then(storageKey =>
                Promise.all(Object.entries(keys).filter(k => k[1].signKey?.prompt).map(async k => [k[0], await SignKey.import(await ObjectsCrypto.decrypt(k[1].signKey!.encryptedKey, storageKey))] as [string, SignKey])))
                .then(keys => keys.reduce((o, k) => { o[k[0]] = k[1]; return o; }, {} as { [path: string]: SignKey }))
        ]
    }

    private async getStorageKey(prompt: boolean, keyContainer: KeyContainer): Promise<SecretKey> {
        if (prompt) {
            if (keyContainer.storagePromptKey) return keyContainer.storagePromptKey;

            if (!keyContainer.storagePassword) keyContainer.storagePassword = this.getStoragePassword(this.passwordHash).catch(() => Promise.resolve());
            // TODO retry if wrong password
            let storagePassword = await keyContainer.storagePassword;
            // TODO there will be many error messages
            if (!storagePassword) throw new Error("password not entered");

            // TODO probably generated multiple times;
            keyContainer.storagePromptKey = await SecretKey.generate(storagePassword, "prompt");
            delete keyContainer.storagePassword;

            return keyContainer.storagePromptKey;
        } else {
            return await this.generateStorageKey;
        }
    }

    getKeyPaths(): string[] {
        return Object.keys(this.loadKeys);
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
            if (!this.loadKeys[path]) this.loadKeys[path] = {};
            this.loadKeys[path][key.getKeyType() as KeyType.Secret | KeyType.Sign] = {
                key: key.encrypt(await this.getStorageKey(storageOptions.storageKeyPrompt == "always", keyContainer)),
                persistent: storageOptions.store == "persistent",
                prompt: storageOptions.storageKeyPrompt == "always"
            };
        }
        return keyContainer;
    }

    async deletePassword(path: string) {
        delete this.loadKeys[path];
    }
    async deleteKey(type: KeyType.Secret | KeyType.Sign, path: string) {
        delete this.loadKeys[path][type == KeyType.Secret ? "secretKey" : "signKey"];
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
    // 3. SecretKey vom nächstbesten Parent verlinkt (nur der "niedrigste" Parent, der verlinkt ist, wird betrachtet), auf den 1. oder 2. oder 3. zutrifft
    private async getSecretKey(object: DatabaseObjectType, keyContainer: KeyContainer): Promise<SecretKey> {
        // console.log("getSecretKey", object.path);
        // TODO catch
        try {
            if (keyContainer.keys[object.path]?.secretKey) {
                return keyContainer.keys[object.path].secretKey!;
            }
            else if (this.loadKeys[object.path]?.secretKey) {
                // console.log(1, SecretKey.decrypt(this.keys[object.path].secretKey!, storageKeySecret));
                return await this.decryptSecretKey(this.loadKeys[object.path].secretKey!, keyContainer);
            } else {
                let path = Object.keys(object.encryptedSecretKey).find(p => keyContainer.keys[p]?.secretKey || this.loadKeys[p]?.secretKey);
                if (path) {
                    // console.log(2);
                    return SecretKey.decrypt(object.encryptedSecretKey[path], keyContainer.keys[path]?.secretKey ? keyContainer.keys[path].secretKey! : await this.decryptSecretKey(this.loadKeys[path].secretKey!, keyContainer));
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
        return this.getSecretKey(object, keyContainer).then(key => ObjectsCrypto.encrypt(property, key));
    }

    decrypt(object: DatabaseObjectType, property: string, keyContainer: KeyContainer = new KeyContainer()): Promise<any> {
        return this.getSecretKey(object, keyContainer).then(key => ObjectsCrypto.decrypt(property, key));
    }

    // TODO getSignKey
    sign<T extends DatabaseObjectType>(owner: GetOwner<T>, object: T, keyContainer: KeyContainer = new KeyContainer()): Promise<T> {
        if (!this.loadKeys[owner.path]?.signKey && !keyContainer.keys[owner.path]?.signKey) return Promise.reject("no signkey");
        let o = { ...object };
        delete o.signature;
        return (keyContainer.keys[owner.path]?.signKey ? Promise.resolve(keyContainer.keys[owner.path].signKey!) : this.decryptSignKey(this.loadKeys[owner.path].signKey!, keyContainer)).then(signKey => ({ ...ObjectsCrypto.sortObject(object), signature: ObjectsCrypto.sign(o, signKey) }));
    }

    verify<T extends DatabaseObjectType>(owner: GetOwner<T>, object: T): T {
        if (!object) throw new Error("undefined object");
        if (!object.signature) throw new Error("no signature");
        if (!owner.verifyKey) throw new Error("no verifykey");

        let o = { ...object };
        delete o.signature;
        if (ObjectsCrypto.verify(o, object.signature, owner.verifyKey!))
            return object;
        else
            throw new Error("wrong signature");
    }
}
// TODO Achtung: man kann keyStore.encrypt ein keyContainerObjekt übergeben, welches dann befüllt wird😬
// TODO include in getSecretKey
export class KeyContainer {
    keyStore: KeyStore;

    // copy of keyStores key with decryptedPromptKeys
    private keys: Keys = {};
    private promptPrivateEncryptionKeys?: Promise<{ [path: string]: PrivateEncryptionKey }>;
    private promptSignKeys?: Promise<{ [path: string]: SignKey }>;

    constructor(keyStore: KeyStore, storagePassword?: string) {
        this.keyStore = keyStore;

        if (storagePassword) [this.promptPrivateEncryptionKeys, this.promptSignKeys] = this.keyStore.decryptPromptKeys(this.keys, storagePassword);
    }

    getPrivateEncryptionKeys(): string[] {
        return Object.entries(this.keys).filter(k => k[1].privateEncryptionKey).map(k => k[0]);
    }
    getSignKeys(): string[] {
        return Object.entries(this.keys).filter(k => k[1].signKey).map(k => k[0]);
    }

    async getPrivateEncryptionKey(path: string): Promise<PrivateEncryptionKey> {
        let keys = this.keys[path];
        if (!keys?.privateEncryptionKey) throw new Error("key not found");

        if (!keys.privateEncryptionKey.prompt) return keys.privateEncryptionKey.key!;
        else {
            if (!this.promptPrivateEncryptionKeys) [this.promptPrivateEncryptionKeys, this.promptSignKeys] = this.keyStore.decryptPromptKeys(this.keys);

            return this.promptPrivateEncryptionKeys!.then(k => k[path]);
        }
    }

    async getSignKey(path: string): Promise<SignKey> {
        let keys = this.keys[path];
        if (!keys?.signKey) throw new Error("key not found");

        if (!keys.signKey.prompt) return keys.signKey.key!;
        else {
            if (!this.promptSignKeys) [this.promptPrivateEncryptionKeys, this.promptSignKeys] = this.keyStore.decryptPromptKeys(this.keys);

            return this.promptSignKeys!.then(k => k[path]);
        }
    }
}

export interface StorageOptions {
    store: "none" | "once" | "session" | "persistent";
    storageKeyPrompt?: "once" | "always";
}