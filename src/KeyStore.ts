import { DatabaseObjectType, GetOwner } from "./DatabaseObjectType";
import { App } from "./App";
import { SecretKey, ObjectsCrypto, SignKey, PrivateEncryptionKey, ObjectsKeyType } from "objects-crypto";

type Keys = { [path: string]: { privateEncryptionKey?: { encryptedKey: string, persistent: boolean, prompt: boolean, key?: Promise<PrivateEncryptionKey> }, signKey?: { encryptedKey: string, persistent: boolean, prompt: boolean, key?: Promise<SignKey> } } };

// TODO has key
export class KeyStore {
    private keys: Keys;
    private passwordCheck: string;
    private getStoragePassword: (passwordCheck: string) => Promise<string>;

    // TODO no persistentKey set?
    // TODO check storageKey

    constructor(json: string, getStoragePassword: (passwordCheck: string) => Promise<string>, out?: { keyContainer?: KeyContainer }) {
        let stored = JSON.parse(json);

        this.keys = stored.keys;
        this.passwordCheck = stored.passwordCheck;
        this.getStoragePassword = getStoragePassword;

        let storagePasswordPromise = this.getStoragePassword(this.passwordCheck);

        let generateStorageKey = storagePasswordPromise.then(storagePassword => SecretKey.generate(storagePassword, "withoutPrompt"));

        Object.values(this.keys).forEach(k => {
            if (k.privateEncryptionKey) (k.privateEncryptionKey!.prompt) ? Promise.reject() : k.privateEncryptionKey.key = generateStorageKey.then(async storageKey => await PrivateEncryptionKey.import(await ObjectsCrypto.decrypt(k.privateEncryptionKey!.encryptedKey, storageKey)));
            if (k.signKey) (k.signKey!.prompt) ? Promise.reject() : k.signKey.key = generateStorageKey.then(async storageKey => await SignKey.import(await ObjectsCrypto.decrypt(k.signKey!.encryptedKey, storageKey)));
        });
        if (out) out.keyContainer = this.createKeyContainer(storagePasswordPromise);
    }

    async export(): Promise<string> {
        let persistentKeys: Keys = {};
        Object.entries(this.keys).forEach(k => {
            if (k[1].privateEncryptionKey?.persistent || k[1].signKey?.persistent) {
                persistentKeys[k[0]] = {};
                if (k[1].privateEncryptionKey?.persistent) persistentKeys[k[0]].privateEncryptionKey = { ...k[1].privateEncryptionKey, key: undefined };
                if (k[1].signKey?.persistent) persistentKeys[k[0]].signKey = { ...k[1].signKey, key: undefined };
            };
        });
        return JSON.stringify({ keys: persistentKeys, passwordCheck: this.passwordCheck });
    }

    async setStoragePassword(oldPassword: string, newPassword: string): Promise<void> {
        let oldStorageKey = await SecretKey.generate(oldPassword, "withoutPrompt");
        if (!await ObjectsCrypto.decrypt(this.passwordCheck, oldStorageKey).then(null, () => false)) throw new Error("wrong password");

        let [oldStoragePromptKey, newStorageKey, newStoragePromptKey] = await Promise.all([SecretKey.generate(oldPassword, "prompt"), SecretKey.generate(newPassword, "withoutPrompt"), SecretKey.generate(newPassword, "prompt")]);

        let values = Object.values(await this.keys);

        await Promise.all([
            ...values.map(keys => Object.values(keys)).reduce((a, b) => [...a, ...b], []).map(async k => {
                if (!k) return;
                k.encryptedKey = await ObjectsCrypto.encrypt(await ObjectsCrypto.decrypt(k.encryptedKey, k.prompt ? oldStoragePromptKey : oldStorageKey), k.prompt ? newStoragePromptKey : newStorageKey);
            }),
            ObjectsCrypto.encrypt(true, newStorageKey).then(c => this.passwordCheck = c) as Promise<void>
        ]);
    }

    createKeyContainer(storagePasswordPromise?: Promise<string>) {
        let requestPromptKeys: () => void = () => { };
        let generateStorageKey: Promise<SecretKey> = storagePasswordPromise
            ? storagePasswordPromise.then(storagePassword => SecretKey.generate(storagePassword, "prompt"))
            : new Promise(resolve => requestPromptKeys = () => this.getStoragePassword(this.passwordCheck).then(storagePassword => SecretKey.generate(storagePassword, "prompt")).then(storageKey => resolve(storageKey)));

        let keys: KeyContainer["keys"] = {};

        Object.entries(this.keys).forEach(k => {
            keys[k[0]] = {};
            if (k[1].privateEncryptionKey) {
                keys[k[0]].privateEncryptionKey = {
                    key: (k[1].privateEncryptionKey.prompt)
                        ? generateStorageKey.then(async storageKey => await PrivateEncryptionKey.import(await ObjectsCrypto.decrypt(k[1].privateEncryptionKey!.encryptedKey, storageKey)))
                        : k[1].privateEncryptionKey.key!,
                    prompt: k[1].privateEncryptionKey.prompt
                };
            }
            if (k[1].signKey) {
                keys[k[0]].signKey = {
                    key: (k[1].signKey.prompt)
                        ? generateStorageKey.then(async storageKey => await SignKey.import(await ObjectsCrypto.decrypt(k[1].signKey!.encryptedKey, storageKey)))
                        : k[1].signKey.key!,
                    prompt: k[1].signKey.prompt
                };
            }
        });

        return new KeyContainer(keys, requestPromptKeys!);
    }


    // TODO
    getKeyPaths(keyType: ObjectsKeyType.PrivateEncryption | ObjectsKeyType.Sign): string[] {
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
    // 3. SecretKey vom nächstbesten Parent verlinkt (nur der "niedrigste" Parent, der verlinkt ist, wird betrachtet), auf den 1. oder 2. oder 3. zutrifft
    private async getSecretKey(object: DatabaseObjectType, keyContainer: KeyContainer): Promise<SecretKey> {
        // console.log("getSecretKey", object.path);
        // TODO catch
        try {
            if (keyContainer.keys[object.path]?.secretKey) {
                return keyContainer.keys[object.path].secretKey!;
            }
            else if (this.keys[object.path]?.secretKey) {
                // console.log(1, SecretKey.decrypt(this.keys[object.path].secretKey!, storageKeySecret));
                return await this.decryptSecretKey(this.keys[object.path].secretKey!, keyContainer);
            } else {
                let path = Object.keys(object.encryptedSecretKey).find(p => keyContainer.keys[p]?.secretKey || this.keys[p]?.secretKey);
                if (path) {
                    // console.log(2);
                    return SecretKey.decrypt(object.encryptedSecretKey[path], keyContainer.keys[path]?.secretKey ? keyContainer.keys[path].secretKey! : await this.decryptSecretKey(this.keys[path].secretKey!, keyContainer));
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
        if (!this.keys[owner.path]?.signKey && !keyContainer.keys[owner.path]?.signKey) return Promise.reject("no signkey");
        let o = { ...object };
        delete o.signature;
        return (keyContainer.keys[owner.path]?.signKey ? Promise.resolve(keyContainer.keys[owner.path].signKey!) : this.decryptSignKey(this.keys[owner.path].signKey!, keyContainer)).then(signKey => ({ ...ObjectsCrypto.sortObject(object), signature: ObjectsCrypto.sign(o, signKey) }));
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

export class KeyContainer {
    // copy of keystore's keys, promptKeys with new promise, plus additional once-keys
    private keys: { [path: string]: { privateEncryptionKey?: { key: Promise<PrivateEncryptionKey>, prompt: boolean }, signKey?: { key: Promise<SignKey>, prompt: boolean } } };
    requestPromptKeys: () => void;

    constructor(keys: KeyContainer["keys"], requestPromptKeys: () => void) {
        this.keys = keys;
        this.requestPromptKeys = () => { requestPromptKeys(); this.requestPromptKeys = () => { } };
    }

    // TODO set return type according to keyType
    async getKey(path: string, keyType: ObjectsKeyType.PrivateEncryption | ObjectsKeyType.Sign): Promise<PrivateEncryptionKey | SignKey> {
        let keys = this.keys[path];
        if (!keys?.[keyType]) throw new Error("key not found");

        if (keys[keyType]!.prompt) this.requestPromptKeys();
        return keys[keyType]!.key;
    }
    // TODO setKey
}

export interface StorageOptions {
    store: "none" | "once" | "session" | "persistent";
    storageKeyPrompt?: "once" | "always";
}