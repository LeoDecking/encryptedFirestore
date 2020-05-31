import { DatabaseObjectType, GetOwner } from "./DatabaseObjectType";
import { App } from "./App";
import { SecretKey, ObjectsCrypto, SignKey, PrivateEncryptionKey, ObjectsKeyType } from "objects-crypto";

export class KeyStore {
    private keys: { [path: string]: { privateEncryptionKey?: { encryptedKey?: string, persistent: boolean, prompt: boolean, key?: Promise<PrivateEncryptionKey> }, signKey?: { encryptedKey?: string, persistent: boolean, prompt: boolean, key?: Promise<SignKey> } } };;
    private passwordCheck: string;
    private getStoragePassword: (passwordCheck: string) => Promise<string>;

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
        let persistentKeys: KeyStore["keys"] = {};
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

    getKeyPaths(keyType: ObjectsKeyType.PrivateEncryption | ObjectsKeyType.Sign, keyContainer?: KeyContainer): string[] {
        return keyContainer ? keyContainer.getKeyPaths(keyType) : Object.entries(this.keys).filter(k => k[1][keyType]).map(k => k[0]);;
    }

    // TODO hasKey

    // TODO getKey

    // TODO canSign/canRead
    // TODO minimize / beautify
    async setPassword(path: string, password: string, privateEncryptionKeyOptions: StorageOptions = { store: "none" }, signKeyOptions: StorageOptions = { store: "none" }, keyContainer: KeyContainer = this.createKeyContainer()): Promise<KeyContainer> {
        let storagePasswordPromise: Promise<string> | null = ((privateEncryptionKeyOptions.storageKeyPrompt || privateEncryptionKeyOptions.store == "persistent")
            || (signKeyOptions.storageKeyPrompt || signKeyOptions.store == "persistent")) ? this.getStoragePassword(this.passwordCheck) : null;
        let storageKeyPromise: Promise<SecretKey> | null = (privateEncryptionKeyOptions.storageKeyPrompt && signKeyOptions.storageKeyPrompt) ? null : storagePasswordPromise!.then(storagePassword => SecretKey.generate(storagePassword, "withoutPrompt"));
        let storageKeyPromptPromise: Promise<SecretKey> | null = (!privateEncryptionKeyOptions.storageKeyPrompt && !signKeyOptions.storageKeyPrompt) ? null : storagePasswordPromise!.then(storagePassword => SecretKey.generate(storagePassword, "prompt"));

        await Promise.all([
            privateEncryptionKeyOptions.store == "none" ? undefined : PrivateEncryptionKey.generateBits(password, path + ObjectsKeyType.PrivateEncryption).then(bits => Promise.all([
                PrivateEncryptionKey.import(bits),
                privateEncryptionKeyOptions.storageKeyPrompt || privateEncryptionKeyOptions.store == "persistent" ? (privateEncryptionKeyOptions.storageKeyPrompt ? storageKeyPromptPromise : storageKeyPromise)?.then(secretKey => ObjectsCrypto.encrypt(bits, secretKey)) : undefined
            ] as [Promise<PrivateEncryptionKey>, Promise<string> | undefined])).then(p => this.setKey(path, p[0], p[1], privateEncryptionKeyOptions, keyContainer)),

            signKeyOptions.store == "none" ? undefined : SignKey.generateBits(password, path + ObjectsKeyType.Sign).then(bits => Promise.all([
                SignKey.import(bits),
                signKeyOptions.storageKeyPrompt || signKeyOptions.store == "persistent" ? (signKeyOptions.storageKeyPrompt ? storageKeyPromptPromise : storageKeyPromise)?.then(secretKey => ObjectsCrypto.encrypt(bits, secretKey)) : undefined
            ] as [Promise<SignKey>, Promise<string> | undefined])).then(p => this.setKey(path, p[0], p[1], signKeyOptions, keyContainer))
        ] as Promise<KeyContainer>[]);
        return keyContainer;
    }

    // TODO überprüfen, ob richtig?
    async setKey(path: string, key: PrivateEncryptionKey | SignKey, encryptedKey?: string, storageOptions: StorageOptions = { store: "once" }, keyContainer: KeyContainer = this.createKeyContainer()): Promise<KeyContainer> {
        if (storageOptions.store == "once") {
            keyContainer.setKey(path, key);
        }
        else if (storageOptions.store != "none") {
            let keys = this.keys[path];
            if (!keys) keys = (this.keys[path] = {});

            keys[key.keyType] = {
                key: (keys[key.keyType]?.prompt ? Promise.reject() : Promise.resolve(key)) as Promise<SignKey> & Promise<PrivateEncryptionKey>,
                persistent: storageOptions.store == "persistent",
                prompt: storageOptions.storageKeyPrompt == "always"
            };
            if (keys[key.keyType]!.persistent || keys[key.keyType]!.prompt) keys[key.keyType]!.encryptedKey = encryptedKey;

        }
        return keyContainer;
    }

    async deletePassword(path: string, keyContainer?: KeyContainer) {
        delete this.keys[path];
        if (keyContainer) {
            keyContainer.deleteKey(path, ObjectsKeyType.PrivateEncryption);
            keyContainer.deleteKey(path, ObjectsKeyType.Sign);
        }
    }
    async deleteKey(path: string, keyType: ObjectsKeyType.PrivateEncryption | ObjectsKeyType.Sign, keyContainer?: KeyContainer) {
        if (this.keys[path]) {
            delete this.keys[path][keyType];
            if (Object.keys(this.keys[path]).length == 0) delete this.keys[path];
        }
        if (keyContainer) keyContainer.deleteKey(path, keyType);
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

    getKeyPaths(keyType: ObjectsKeyType.PrivateEncryption | ObjectsKeyType.Sign): string[] {
        return Object.entries(this.keys).filter(k => k[1][keyType]).map(k => k[0]);
    }

    // TODO set return type according to keyType
    async getKey(path: string, keyType: ObjectsKeyType.PrivateEncryption | ObjectsKeyType.Sign): Promise<PrivateEncryptionKey | SignKey> {
        let keys = this.keys[path];
        if (!keys?.[keyType]) throw new Error("key not found");

        if (keys[keyType]!.prompt) this.requestPromptKeys();
        return keys[keyType]!.key;
    }

    setKey(path: string, key: PrivateEncryptionKey | SignKey) {
        let keys = this.keys[path];
        if (!keys) keys = (this.keys[path] = {});

        keys[key.keyType] = { key: Promise.resolve(key) as Promise<SignKey & PrivateEncryptionKey>, prompt: false };
    }

    deleteKey(path: string, keyType: ObjectsKeyType.PrivateEncryption | ObjectsKeyType.Sign) {
        if (!this.keys[path]?.[keyType]) return;
        if (Object.keys(this.keys[path]).length > 1) delete this.keys[path][keyType];
        else delete this.keys[path];
    }
}

export interface StorageOptions {
    store: "none" | "once" | "session" | "persistent";
    storageKeyPrompt?: "once" | "always";
}