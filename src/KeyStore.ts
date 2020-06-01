import { DatabaseObjectType, GetOwner } from "./DatabaseObjectType";
import { App } from "./App";
import { SecretKey, ObjectsCrypto, SignKey, PrivateEncryptionKey, ObjectsKeyType } from "objects-crypto";


// TODO device signKey/secretKey
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
            if (k.privateEncryptionKey) (k.privateEncryptionKey!.prompt) ? Promise.reject() : k.privateEncryptionKey.key = generateStorageKey.then(async storageKey => await PrivateEncryptionKey.import(await ObjectsCrypto.decrypt(k.privateEncryptionKey!.encryptedKey!, storageKey)));
            if (k.signKey) (k.signKey!.prompt) ? Promise.reject() : k.signKey.key = generateStorageKey.then(async storageKey => await SignKey.import(await ObjectsCrypto.decrypt(k.signKey!.encryptedKey!, storageKey)));
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

    hasKey(path: string, keyType: ObjectsKeyType.PrivateEncryption | ObjectsKeyType.Sign, keyContainer?: KeyContainer): boolean {
        return keyContainer ? keyContainer.hasKey(path, keyType) : !!this.keys[path]?.[keyType];
    }

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

    // TODO set return type according to keyType
    async setKey(path: string, key: PrivateEncryptionKey | SignKey, encryptedKey?: string, storageOptions: StorageOptions = { store: "once" }, keyContainer: KeyContainer = this.createKeyContainer()): Promise<KeyContainer> {
        keyContainer.setKey(path, key);

        if (storageOptions.store != "none" && storageOptions.store != "once") {
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

    async getKey(path: string, keyType: ObjectsKeyType.PrivateEncryption | ObjectsKeyType.Sign, keyContainer?: KeyContainer): Promise<PrivateEncryptionKey | SignKey> {
        if (keyContainer) {
            return keyContainer.getKey(path, keyType);
        } else {
            let keys = this.keys[path];
            if (!keys?.[keyType]) throw new Error("key not found");
            return keys[keyType]!.key!;
        }
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

    hasKey(path: string, keyType: ObjectsKeyType.PrivateEncryption | ObjectsKeyType.Sign): boolean {
        return !!this.keys[path]?.[keyType];
    }

    setKey(path: string, key: PrivateEncryptionKey | SignKey) {
        let keys = this.keys[path];
        if (!keys) keys = (this.keys[path] = {});

        keys[key.keyType] = { key: Promise.resolve(key) as Promise<SignKey & PrivateEncryptionKey>, prompt: false };
    }

    // TODO set return type according to keyType
    async getKey(path: string, keyType: ObjectsKeyType.PrivateEncryption | ObjectsKeyType.Sign): Promise<PrivateEncryptionKey | SignKey> {
        let keys = this.keys[path];
        if (!keys?.[keyType]) throw new Error("key not found");

        if (keys[keyType]!.prompt) this.requestPromptKeys();
        return keys[keyType]!.key;
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