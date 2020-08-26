import { SecretKey, ObjectsCrypto, SignKey, PrivateEncryptionKey, ObjectsKeyType } from "objects-crypto";


// TODO device signKey/secretKey
export class KeyStore {
    private keys: { [path: string]: { privateEncryptionKey?: { encryptedKey?: string, persistent: boolean, prompt: boolean, key: Promise<PrivateEncryptionKey> | null }, signKey?: { encryptedKey?: string, persistent: boolean, prompt: boolean, key: Promise<SignKey> | null } } };;
    private passwordCheck?: string;
    private getStoragePassword: () => Promise<string>;


    // TODO generated key als parameter -> biometrisch...
    // TODO wrong password
    constructor(json: string, getStoragePassword: (checkPassword: (p: string) => Promise<boolean>) => Promise<string>, out?: { keyContainer?: KeyContainer }) {
        let stored = JSON.parse(json ?? "{}");

        this.keys = stored.keys ?? {};
        this.passwordCheck = stored.passwordCheck;

        // TODO test, move checkPassword here - otherwise create method to call getStoragePassword
        this.getStoragePassword = () => this.passwordCheck ? getStoragePassword(this.checkPassword) : Promise.resolve("");

        if (Object.keys(this.keys).length || out) {
            // if (!this.passwordCheck) throw new Error("no passwordCheck");

            let storagePasswordPromise = this.getStoragePassword();

            if (Object.keys(this.keys).length) {
                let generateStorageKey = storagePasswordPromise.then(storagePassword => SecretKey.generate(storagePassword, "withoutPrompt"));

                Object.values(this.keys).forEach(k => {
                    if (k.privateEncryptionKey) k.privateEncryptionKey.key = (k.privateEncryptionKey!.prompt) ? null : generateStorageKey.then(async storageKey => await PrivateEncryptionKey.import(await ObjectsCrypto.decrypt(k.privateEncryptionKey!.encryptedKey!, storageKey)));
                    if (k.signKey) k.signKey.key = (k.signKey!.prompt) ? null : generateStorageKey.then(async storageKey => await SignKey.import(await ObjectsCrypto.decrypt(k.signKey!.encryptedKey!, storageKey)));
                });
            }
            if (out) out.keyContainer = this.createKeyContainer(storagePasswordPromise);
        }

        // await sign before export
        if (!this.hasKey("device", ObjectsKeyType.Sign)) {
            let encryptionBits = ObjectsCrypto.getRandomBytes(32);
            let signBits = ObjectsCrypto.getRandomBytes(32);

            let storageKey = SecretKey.generate("", "withoutPrompt");
            let encryptedEncryption = storageKey.then(s => ObjectsCrypto.encrypt(Array.from(encryptionBits), s)).then(e => this.keys["device"].privateEncryptionKey!.encryptedKey = e);
            let encryptedSign = storageKey.then(s => ObjectsCrypto.encrypt(Array.from(signBits), s)).then(e => this.keys["device"].signKey!.encryptedKey = e);

            this.keys["device"] = {
                privateEncryptionKey: {
                    persistent: true,
                    prompt: false,
                    key: PrivateEncryptionKey.import(encryptionBits)
                },
                signKey: {
                    persistent: true,
                    prompt: false,
                    key: encryptedEncryption.then(() => encryptedSign).then(() => SignKey.import(signBits))
                }
            };
        }
    }

    private async checkPassword(password: string): Promise<boolean> {
        return !this.passwordCheck || !await ObjectsCrypto.decrypt(this.passwordCheck, await SecretKey.generate(password, "withoutPrompt")).then(null, () => false);
    }

    async export(noKeys: boolean = false): Promise<string> {
        let persistentKeys: KeyStore["keys"] = {};

        await this.keys["device"].signKey?.key; // key is set after encryptedKey

        Object.entries(this.keys).filter(k => noKeys ? k[0] == "device" : k[1].privateEncryptionKey?.persistent || k[1].signKey?.persistent).forEach(k => {
            persistentKeys[k[0]] = {};
            if (k[1].privateEncryptionKey?.persistent) persistentKeys[k[0]].privateEncryptionKey = { ...k[1].privateEncryptionKey, key: null };
            if (k[1].signKey?.persistent) persistentKeys[k[0]].signKey = { ...k[1].signKey, key: null };
        });

        return JSON.stringify({ passwordCheck: this.passwordCheck, keys: persistentKeys });
    }

    async setStoragePassword(oldPassword: string, newPassword: string): Promise<void> {
        let oldStorageKey = this.passwordCheck ? await SecretKey.generate(oldPassword, "withoutPrompt") : null;
        if (this.passwordCheck && !await ObjectsCrypto.decrypt(this.passwordCheck, oldStorageKey!).then(null, () => false)) throw new Error("wrong password");

        let [oldStoragePromptKey, newStorageKey, newStoragePromptKey] = await Promise.all([this.passwordCheck ? SecretKey.generate(oldPassword, "prompt") : null, SecretKey.generate(newPassword, "withoutPrompt"), SecretKey.generate(newPassword, "prompt")]);


        await Promise.all([
            ...(this.passwordCheck ? Object.values(this.keys).map(keys => Object.values(keys)).reduce((a, b) => [...a, ...b], []).map(async k => {
                if (!k?.encryptedKey) return;
                k.encryptedKey = await ObjectsCrypto.encrypt(await ObjectsCrypto.decrypt(k.encryptedKey, k.prompt ? oldStoragePromptKey! : oldStorageKey!), k.prompt ? newStoragePromptKey : newStorageKey);
            }) : []),
            ObjectsCrypto.encrypt(true, newStorageKey).then(c => this.passwordCheck = c) as Promise<void>
        ]);
    }

    createKeyContainer(storagePasswordPromise?: Promise<string>) {
        // if (!this.passwordCheck) throw new Error("no passwordCheck");

        // TODO wrong password
        let requestPromptKeys: () => void = () => { };
        let generateStorageKey: Promise<SecretKey> = storagePasswordPromise
            ? storagePasswordPromise.then(storagePassword => SecretKey.generate(storagePassword, "prompt"))
            : new Promise(resolve => requestPromptKeys = () => this.getStoragePassword().then(storagePassword => SecretKey.generate(storagePassword, "prompt")).then(storageKey => resolve(storageKey)));

        let keys: KeyContainer["keys"] = {};

        Object.entries(this.keys).forEach(k => {
            keys[k[0]] = {};
            if (k[1].privateEncryptionKey) {
                keys[k[0]].privateEncryptionKey = {
                    key: (k[1].privateEncryptionKey.prompt)
                        ? generateStorageKey.then(async storageKey => await PrivateEncryptionKey.import(await ObjectsCrypto.decrypt(k[1].privateEncryptionKey!.encryptedKey!, storageKey)))
                        : k[1].privateEncryptionKey.key!,
                    prompt: k[1].privateEncryptionKey.prompt
                };
            }
            if (k[1].signKey) {
                keys[k[0]].signKey = {
                    key: (k[1].signKey.prompt)
                        ? generateStorageKey.then(async storageKey => await SignKey.import(await ObjectsCrypto.decrypt(k[1].signKey!.encryptedKey!, storageKey)))
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

    async setPassword(path: string, password: string, privateEncryptionKeyOptions: StorageOptions = { store: "none" }, signKeyOptions: StorageOptions = { store: "none" }, keyContainer: KeyContainer = this.createKeyContainer()): Promise<KeyContainer> {
        if (privateEncryptionKeyOptions.store == "none" && signKeyOptions.store == "none") return keyContainer;


        let pPromptKey = (privateEncryptionKeyOptions.prompt ?? false) && (privateEncryptionKeyOptions.store == "persistent" || privateEncryptionKeyOptions.store == "session");
        let sPromptKey = (signKeyOptions.prompt ?? false) && (signKeyOptions.store == "persistent" || signKeyOptions.store == "session");
        let promptKey = pPromptKey || sPromptKey;

        let pWithoutPromptKey = !pPromptKey && (privateEncryptionKeyOptions.store == "persistent" || privateEncryptionKeyOptions.store == "session");
        let sWithoutPromptKey = !sPromptKey && (signKeyOptions.store == "persistent" || signKeyOptions.store == "session");
        let withoutPromptKey = pWithoutPromptKey || sWithoutPromptKey;

        // if ((promptKey || withoutPromptKey) && !this.passwordCheck) throw new Error("no passwordCheck");

        let storagePasswordPromise: Promise<string> | null = (promptKey || withoutPromptKey) ? this.getStoragePassword() : null;
        // TODO wrong password

        let storageKeyPromptPromise: Promise<SecretKey> | null = !promptKey ? null : storagePasswordPromise!.then(storagePassword => SecretKey.generate(storagePassword, "prompt"));
        let storageKeyPromise: Promise<SecretKey> | null = !withoutPromptKey ? null : storagePasswordPromise!.then(storagePassword => SecretKey.generate(storagePassword, "withoutPrompt"));

        await Promise.all([
            privateEncryptionKeyOptions.store == "none" ? undefined : PrivateEncryptionKey.generateBits(password, path + ObjectsKeyType.PrivateEncryption).then(bits => Promise.all([
                PrivateEncryptionKey.import(bits),
                (pPromptKey ? storageKeyPromptPromise : pWithoutPromptKey ? storageKeyPromise : null)?.then(secretKey => ObjectsCrypto.encrypt(Array.from(bits), secretKey))
            ] as [Promise<PrivateEncryptionKey>, Promise<string> | undefined])).then(p => this.setKey(path, p[0], p[1], privateEncryptionKeyOptions, keyContainer)),

            signKeyOptions.store == "none" ? undefined : SignKey.generateBits(password, path + ObjectsKeyType.Sign).then(bits => Promise.all([
                SignKey.import(bits),
                (sPromptKey ? storageKeyPromptPromise : sWithoutPromptKey ? storageKeyPromise : null)?.then(secretKey => ObjectsCrypto.encrypt(Array.from(bits), secretKey))
            ] as [Promise<SignKey>, Promise<string> | undefined])).then(p => this.setKey(path, p[0], p[1], signKeyOptions, keyContainer))
        ] as Promise<KeyContainer>[]);
        return keyContainer;
    }

    setKey(path: string, key: PrivateEncryptionKey | SignKey, encryptedKey?: string, storageOptions: StorageOptions = { store: "once" }, keyContainer: KeyContainer = this.createKeyContainer()): KeyContainer {
        keyContainer.setKey(path, key);

        if (storageOptions.store != "none" && storageOptions.store != "once") {
            let keys = this.keys[path];
            if (!keys) keys = (this.keys[path] = {});

            keys[key.keyType] = {
                key: (storageOptions.prompt ? null : Promise.resolve(key)) as Promise<SignKey> & Promise<PrivateEncryptionKey>,
                persistent: storageOptions.store == "persistent",
                prompt: storageOptions.prompt ?? false
            };
            if (keys[key.keyType]!.persistent || keys[key.keyType]!.prompt) keys[key.keyType]!.encryptedKey = encryptedKey;

        }
        return keyContainer;
    }

    // TODO return type
    async getKey(path: string, keyType: ObjectsKeyType.PrivateEncryption | ObjectsKeyType.Sign, keyContainer?: KeyContainer): Promise<PrivateEncryptionKey | SignKey> {
        if (!keyContainer && this.keys[path]?.[keyType]?.prompt) keyContainer = this.createKeyContainer();
        if (keyContainer) {
            return keyContainer.getKey(path, keyType);
        } else {
            let keys = this.keys[path];
            if (!keys?.[keyType]) throw new Error("key not found");
            return keys[keyType]!.key!;
        }
    }

    // TODO storagePassword needed?
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
    prompt?: boolean;
}