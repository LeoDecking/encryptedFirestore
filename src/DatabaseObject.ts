import { AutoId } from "./AutoId";
import { DatabaseObjectType, DatabaseChildObjectType, DatabaseAncestorObjectType } from "./DatabaseObjectType";
import { App } from "./App";
import { KeyContainer } from "./KeyStore";
import { PublicEncryptionKey, VerifyKey, ObjectsCrypto, PrivateEncryptionKey, SignKey, SecretKey, ObjectsKeyType } from "objects-crypto";
import { Key } from "objects-crypto/dist/Key/Key";
// import { app } from "firebase";


type DocumentData = {
    [key: string]: any,
    encryptedProperties?:
    {
        publicKey: string,
        encrypted: string,
        encryptedPrivateKey: { [path: string]: [string, string] } //[publicKey, encryptedPrivateKey]
        ownerEncryptedPrivateKey: { [path: string]: [string, string] } //[publicKey, encryptedPrivateKey]
    },
    signature?: {
        signature: string,
        ownerPath: string,
        verifyKey: string
    }
};

// TODO after download / before upload
// Every property must be default initialized!
export abstract class DatabaseObject<Tstring extends string, T extends DatabaseObjectType, P extends DatabaseObjectType | App, O extends DatabaseAncestorObjectType<T> = P> {
    abstract readonly databaseOptions: {
        type: Tstring,
        collection: string,

        ownerType: O extends App ? "app" : Extract<O, DatabaseObjectType>["databaseOptions"]["type"],
        ownerMayRead: boolean, // --> should the secretKey be encrypted for owner?
        ownerMayWrite: boolean, // --> is the owner allowed to sign children of this object?

        // TODO weiter implementieren / löschen
        hasPassword: boolean, // --> should a password for encryption be generated?
        passwordCanSign: boolean,

        encryptedProperties?: string[]

    };
    private readonly ignoreProperties = ["databaseOptions", "ignoreProperties", "id", "app", "parent", "verifyKey", "publicKey", "children"];

    readonly app: App;
    readonly parent: P;
    get owner(): O {
        for (let o: DatabaseObjectType | App = this.parent; !App.isApp(o); o = o.parent) {
            if (o.databaseOptions.type == this.databaseOptions.ownerType) return o as O;
        }
        return this.app as O;
    }

    readonly id: string;
    get path(): string { return this.parent.path + "/" + this.databaseOptions.collection + "/" + this.id; }
    version: number = 0;

    children?: { [type: string]: { [id: string]: DatabaseChildObjectType<T> } };

    publicKey?: PublicEncryptionKey;
    verifyKey?: VerifyKey;
    publicKeys?: { [path: string]: PublicEncryptionKey }; // keys, for which the secretKey will be encrypted - without allowed parents, they're added automatically


    constructor(parent: P, id: string = AutoId.newId()) {
        this.id = id;
        this.parent = parent;
        this.app = App.isApp(parent) ? parent : (parent as DatabaseObjectType).app;
    }

    newChild<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id?: string): C {
        return new child(this, id);
    }

    async hash(): Promise<string> {
        let object: any = {};
        Object.keys(this).map(async k => {
            if (this.ignoreProperties.indexOf(k) == -1)
                object[k] = (this as { [key: string]: any })[k];
        });
        return await ObjectsCrypto.hash(object);
    }

    // TODO id from path
    static async fromDocumentData<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], documentData: DocumentData, id: string = AutoId.newId(), opaque: boolean = false, keyContainer?: KeyContainer): Promise<T> {
        if (!documentData.signature) throw new Error("no signature");

        let object = new this(parent, id);
        if (documentData.path != object.path) throw new Error("wrong path: " + object.path);


        let owner: DatabaseObjectType | App;
        for (let o: DatabaseObjectType = object; !owner! && !App.isApp(o); o = o.owner as DatabaseObjectType) {
            if (o.owner.path == documentData.signature.ownerPath) {
                if (o.owner.verifyKey && await o.owner.verifyKey?.export == documentData.signature.verifyKey) owner = o.owner;
                else throw new Error("wrong verifyKey");
            } else if (!o.databaseOptions.ownerMayWrite) break;
        }
        if (!owner!) throw new Error("wrong signature's owner");

        let verifyObject = { ...documentData };
        delete verifyObject.signature;

        if (!await ObjectsCrypto.verify(verifyObject, documentData.signature.signature, owner!.verifyKey!)) throw new Error("wrong signature");



        Object.keys(object).filter(k => object.ignoreProperties.indexOf(k) == -1 && (!object.databaseOptions.encryptedProperties || object.databaseOptions.encryptedProperties.indexOf(k) == -1)).forEach(k =>
            (object as { [key: string]: any })[k] = ObjectsCrypto.sortObject(documentData[k], true)
        );

        if (!opaque && object.databaseOptions.encryptedProperties?.length && documentData.encryptedProperties) {
            if (!keyContainer) keyContainer = (App.isApp(parent) ? parent : (parent as DatabaseObjectType).app).keyStore.createKeyContainer();

            let publicEncryptionKey = await PublicEncryptionKey.import(documentData.encryptedProperties.publicKey);


            let secretKey: SecretKey;

            let publicKeys = { ...documentData.encryptedProperties.ownerEncryptedPrivateKey, ...documentData.encryptedProperties.encryptedPrivateKey };
            let encryptionKeyPaths = Object.keys(publicKeys).filter(k => object.app.keyStore.hasKey(k, ObjectsKeyType.PrivateEncryption, keyContainer));
            for (let i = 0; i < encryptionKeyPaths.length; i++) {
                let privateEncryptionKey = await object.app.keyStore.getKey(encryptionKeyPaths[i], ObjectsKeyType.PrivateEncryption, keyContainer) as PrivateEncryptionKey;

                if (await privateEncryptionKey.publicKey.export == publicKeys[encryptionKeyPaths[i]][0]) {
                    secretKey = await SecretKey.import(await ObjectsCrypto.decrypt(publicKeys[encryptionKeyPaths[i]][1], await SecretKey.derive(privateEncryptionKey, publicEncryptionKey)));
                    break;
                } else
                    console.log("wrong publicEncryptionKey:", publicKeys[encryptionKeyPaths[i]][0])
            }

            if (!secretKey!) throw new Error("no privateEncryptionKey");
            let encryptedProperties: { [key: string]: any } = await ObjectsCrypto.sortObject(await ObjectsCrypto.decrypt(documentData.encryptedProperties.encrypted, secretKey!), true);

            Object.keys(object).filter(k => object.ignoreProperties.indexOf(k) == -1 && object.databaseOptions.encryptedProperties?.indexOf(k) != -1).forEach(k =>
                (object as { [key: string]: any })[k] = ObjectsCrypto.sortObject(encryptedProperties[k], true)
            );

        }

        if (documentData.verifyKey) object.verifyKey = await VerifyKey.import(documentData.verifyKey);
        if (documentData.publicKey) object.publicKey = await PublicEncryptionKey.import(documentData.publicKey);
        if (Object.keys(documentData.encryptedProperties?.encryptedPrivateKey ?? {}).length) {
            object.publicKeys = {};
            await Promise.all(Object.entries(documentData.encryptedProperties!.encryptedPrivateKey).map(async k => object.publicKeys![k[0]] = await PublicEncryptionKey.import(k[1][0])));
        }

        return object as T;
    }

    async childFromDocumentData<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, documentData: DocumentData, id: string = AutoId.newId(), opaque: boolean = false, keyContainer?: KeyContainer): Promise<C> {
        return await DatabaseObject.fromDocumentData.call(child, parent, documentData, id, opaque, keyContainer);
    }

    async updateFromDocumentData(constructor: new (parent: P, id?: string) => T, documentData: DocumentData, opaque: boolean = false, keyContainer?: KeyContainer): Promise<this> {
        let updated = await DatabaseObject.fromDocumentData.call(constructor, this.parent, documentData, this.id, opaque, keyContainer);
        Object.keys(this).forEach(k => (this as { [key: string]: any })[k] = updated[k]);
        return this;
    }

    // TODO test
    clone(): this {
        return new (this.constructor as new (parent: P, id?: string) => this)(this.parent, this.id).cloneFrom(this);
    }

    cloneFrom(object: this): this {
        Object.keys(this).forEach(k => (this as { [key: string]: any })[k] = (this.ignoreProperties.indexOf(k) == -1) ? ObjectsCrypto.sortObject((object as { [key: string]: any })[k]) : (object as { [key: string]: any })[k]);
        if (object.children) {
            this.children = {};
            Object.keys(object.children).forEach(ct => { this.children![ct] = {}; Object.keys(object.children![ct]).forEach(c => this.children![ct]![c] = object.children![ct]![c]!.clone()); });
        }
        if (object.verifyKey) this.verifyKey = object.verifyKey;
        if (object.publicKey) this.publicKey = object.publicKey;
        if (object.publicKeys) this.publicKeys = object.publicKeys;
        return this;
    }

    // TODO extract sign
    static async toDocumentData(objects: DatabaseObjectType[], incrementVersion = false, keyContainer?: KeyContainer): Promise<DocumentData[]> {
        if (objects.length == 0) return [];

        if (!keyContainer) keyContainer = objects[0].app.keyStore.createKeyContainer();

        return await Promise.all(objects.map(async object => {
            let documentData: DocumentData = {};

            Object.keys(object).filter(k => object.ignoreProperties.indexOf(k) == -1 && (!object.databaseOptions.encryptedProperties || object.databaseOptions.encryptedProperties.indexOf(k) == -1)).forEach(k =>
                documentData[k] = (object as { [key: string]: any })[k]
            );

            if (object.databaseOptions.encryptedProperties?.length) {
                let encryptedProperties: { [key: string]: any } = {};
                Object.keys(object).filter(k => object.ignoreProperties.indexOf(k) == -1 && object.databaseOptions.encryptedProperties!.indexOf(k) != -1).forEach(k =>
                    encryptedProperties[k] = (object as { [key: string]: any })[k]
                );

                let secretKey = await SecretKey.generate();

                let privateEncryptionKey = await PrivateEncryptionKey.generate();

                let encryptedPrivateKey: { [path: string]: [string, string] } = {};
                let ownerEncryptedPrivateKey: { [path: string]: [string, string] } = {};

                let ownerPublicKeys: { [path: string]: PublicEncryptionKey } = {};
                for (let o: DatabaseObjectType = object; !App.isApp(o) && o.databaseOptions.ownerMayRead; o = o.owner as DatabaseObjectType) ownerPublicKeys[o.owner.path] = o.owner.publicKey!;
                if (object.databaseOptions.hasPassword && object.publicKey) ownerPublicKeys[object.path] = object.publicKey;

                await Promise.all([
                    ...Object.entries(object.publicKeys ?? {}).filter(k => !ownerPublicKeys[k[0]]).map(async publicKey => encryptedPrivateKey[await publicKey[0]] = [await publicKey[1].export, await ObjectsCrypto.encrypt(await secretKey.export, await SecretKey.derive(privateEncryptionKey, publicKey[1]))]),
                    ...Object.entries(ownerPublicKeys).map(async publicKey => ownerEncryptedPrivateKey[await publicKey[0]] = [await publicKey[1].export, await ObjectsCrypto.encrypt(await secretKey.export, await SecretKey.derive(privateEncryptionKey, publicKey[1]))])
                ]);


                documentData.encryptedProperties = {
                    encrypted: await ObjectsCrypto.encrypt(encryptedProperties, secretKey),
                    publicKey: await privateEncryptionKey.publicKey.export,
                    encryptedPrivateKey: encryptedPrivateKey,
                    ownerEncryptedPrivateKey: ownerEncryptedPrivateKey
                };
            }

            documentData["path"] = object.path;
            if (object.verifyKey) documentData["verifyKey"] = await object.verifyKey?.export;
            if (object.publicKey) documentData["publicKey"] = await object.publicKey?.export;
            if (incrementVersion) documentData["version"]++;


            let signKey: SignKey;
            let ownerPath: string;
            for (let o: DatabaseObjectType = object; !signKey! && !App.isApp(o); o = o.owner as DatabaseObjectType) {
                if (object.app.keyStore.hasKey(o.owner.path, ObjectsKeyType.Sign, keyContainer)) {
                    signKey = await object.app.keyStore.getKey(o.owner.path, ObjectsKeyType.Sign) as SignKey;
                    ownerPath = o.owner.path;
                } else if (!App.isApp(o.owner) && !o.owner.databaseOptions.ownerMayWrite) break;
            }

            // TODO deviceSignKey
            if (!signKey!) throw new Error("no signKey");

            documentData.signature = {
                signature: await ObjectsCrypto.sign(documentData, signKey!),
                ownerPath: ownerPath!,
                verifyKey: await signKey!.verifyKey.export
            };

            // console.log("signed", documentData);

            return documentData;
        }));
    }
    async toDocumentData(incrementVersion = false, keyContainer?: KeyContainer): Promise<{ [key: string]: any }> {
        return (await DatabaseObject.toDocumentData([this], incrementVersion, keyContainer))[0];
    }

    static async deleteDocumentData(objects: DatabaseObjectType[], keyContainer?: KeyContainer): Promise<DocumentData[]> {
        if (objects.length == 0) return [];

        if (!keyContainer) keyContainer = objects[0].app.keyStore.createKeyContainer();

        return await Promise.all(objects.map(async object => {
            if (object.version == 0) throw new Error("trying to delete 0 version");

            let documentData: DocumentData = {
                path: object.path,
                version: -object.version
            };

            let signKey: SignKey;
            let ownerPath: string;
            for (let o: DatabaseObjectType = object; !signKey! && !App.isApp(o); o = o.owner as DatabaseObjectType) {
                if (object.app.keyStore.hasKey(o.owner.path, ObjectsKeyType.Sign, keyContainer)) {
                    signKey = await object.app.keyStore.getKey(o.owner.path, ObjectsKeyType.Sign) as SignKey;
                    ownerPath = o.owner.path;
                } else if (!App.isApp(o.owner) && !o.owner.databaseOptions.ownerMayWrite) break;
            }

            if (!signKey!) throw new Error("no signKey");

            documentData.signature = {
                signature: await ObjectsCrypto.sign(documentData, signKey!),
                ownerPath: ownerPath!,
                verifyKey: await signKey!.verifyKey.export
            };

            // console.log("signed", documentData);

            return documentData;
        }));
    }


    // TODO überprüfen, ob richtiger path
    async getOpaquePassword(password: string): Promise<string> {
        let opaque: { publicKey?: string, verifyKey?: string } = {};
        [opaque.publicKey, opaque.verifyKey] = await Promise.all([PrivateEncryptionKey.generate(password, this.path).then(k => k.publicKey.export), this.databaseOptions.passwordCanSign ? SignKey.generate(password, this.path).then(k => k.verifyKey.export) : undefined]);
        if (!this.databaseOptions.passwordCanSign) delete opaque.verifyKey;

        return btoa(JSON.stringify(opaque));
    }
    async setOpaquePasswort(opaque: string): Promise<this> {
        let o = JSON.parse(atob(opaque));
        [this.publicKey, this.verifyKey] = await Promise.all([PublicEncryptionKey.import(o["keyHash"]), o["verifyKey"] ? await VerifyKey.import(o["verifyKey"]) : undefined]);
        // TODO delete nötig?
        if (!this.databaseOptions.passwordCanSign) delete this.verifyKey;

        return this;
    }
    async setPassword(password: string): Promise<this> {
        [this.publicKey, this.verifyKey] = await Promise.all([PrivateEncryptionKey.generate(password, this.path).then(k => k.publicKey), this.databaseOptions.passwordCanSign ? SignKey.generate(password, this.path).then(k => k.verifyKey) : undefined]);
        // TODO ist das nötig, bzw. vlt. schon so undefined?
        if (!this.databaseOptions.passwordCanSign) delete this.verifyKey;

        return this;
    }




    // TODO ids from firestore (more than 10)
    // TODO allEncryptedFor / allSignedBy from firestore

    static fromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], id: string, opaque?: boolean, onSnapshot?: null, keyContainer?: KeyContainer): Promise<T>;
    static fromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], id: string, opaque: boolean, onSnapshot: (object: T) => void, keyContainer?: KeyContainer): () => void;
    static fromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], id: string, opaque: boolean = false, onSnapshot?: ((object: T) => void) | null, keyContainer?: KeyContainer): Promise<T> | (() => void) {
        let dummy = new this(parent, id);
        if (!onSnapshot) {
            return new Promise(async (resolve, reject) => {
                let documents = await DatabaseObject.collectionFromFirestore.call(this, parent, [{ fieldPath: "path", opStr: "==", value: dummy.path }], opaque, keyContainer);
                if (documents.length != 1) reject("document not found");
                else resolve(documents[0] as T);
            });
        } else {
            return DatabaseObject.collectionFromFirestore.call(this, parent, [{ fieldPath: "path", opStr: "==", value: dummy.path }], opaque, ((objects: T[]) => onSnapshot(objects[0])));
        }
    }

    // TODO changes?
    static collectionFromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[], opaque?: boolean, onSnapshot?: null, keyContainer?: KeyContainer): Promise<T[]>;
    static collectionFromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[], opaque: boolean, onSnapshot: (objects: T[]) => void): (() => void);
    static collectionFromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[] = [], opaque: boolean = false, onSnapshot?: ((objects: T[]) => void) | null, keyContainer?: KeyContainer): Promise<T[]> | (() => void) {
        let dummy = new this(parent);

        let query: firebase.firestore.CollectionReference<firebase.firestore.DocumentData> | firebase.firestore.Query<firebase.firestore.DocumentData>
            = dummy.app.firebase.firestore().collection(parent.path + "/" + dummy.databaseOptions.collection);
        queries.forEach(q => query = query.where(q.fieldPath, q.opStr, q.value));

        if (!onSnapshot)
            return query.get({ source: "server" }).then(s => Promise.all(s.docs.map(d => DatabaseObject.fromDocumentData.call(this, parent, d.data(), d.id, opaque, keyContainer) as Promise<T>)));
        else
            return query.onSnapshot(async s => {
                // type: : (objs: { obj: T, change?: firebase.firestore.DocumentChange<firebase.firestore.DocumentData> }[] => void
                // let changes = s.docChanges();
                // console.log(changes);
                // console.log(s.docs);
                // onSnapshot((await Promise.all(s.docs.map(d => DatabaseObject.getObjectFromDocument.call(this, parent, d)))).map(o => ({ obj: o as T, change: changes.find(c => c.doc.id == o.id) })));
                onSnapshot(await Promise.all(s.docs.map(d => DatabaseObject.fromDocumentData.call(this, parent, d.data(), d.id, opaque, keyContainer))) as T[]);
            }) as (() => void);
    }

    childFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id: string, opaque?: boolean, onSnapshot?: null, keyContainer?: KeyContainer): Promise<C>;
    childFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id: string, opaque: boolean, onSnapshot: (object: C) => void): () => void;
    childFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id: string, opaque: boolean = false, onSnapshot?: ((object: C) => void) | null, keyContainer?: KeyContainer): Promise<C> | (() => void) {
        return DatabaseObject.fromFirestore.call(child as any, this, id, opaque, onSnapshot, keyContainer);
    }

    // TODO ? query
    childrenFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[], opaque?: boolean, onSnapshot?: null, keyContainer?: KeyContainer): Promise<C[]>;
    childrenFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[], opaque: boolean, onSnapshot: (objects: C[]) => void): () => void;
    childrenFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[] = [], opaque: boolean = false, onSnapshot?: ((objects: C[]) => void) | null, keyContainer?: KeyContainer): Promise<C[]> | (() => void) {
        return DatabaseObject.collectionFromFirestore.call(child as any, this, queries, opaque, onSnapshot, keyContainer);
    }

    // TODO not firestore, newChild?
    loadChildrenFromFirestore<C extends (new (parent: this, id?: string) => DatabaseChildObjectType<this>)[]>(children: C, opaque?: boolean, keyContainer?: KeyContainer): Promise<this> {
        return Promise.all(children.map(c => this.childrenFromFirestore(c, [], opaque, undefined, keyContainer))).then(c => {
            this.children = {};
            c.forEach((c1, i) => {
                let collection: { [id: string]: DatabaseChildObjectType<any> } = {};
                c1.forEach(c2 => collection[c2.id] = c2);
                this.children![new children[i](this).databaseOptions.collection] = collection;
            });
            return this;
        });
    }

    async updateFromFirestore(constructor: new (parent: P, id?: string) => T, opaque: boolean = false, keyContainer?: KeyContainer): Promise<this> {
        let updated = await DatabaseObject.fromFirestore.call(constructor, this.parent, this.id, opaque, keyContainer);
        Object.keys(this).forEach(k => (this as { [key: string]: any })[k] = updated[k]);
        return this;
    }


    static async uploadToFirestore(objects: DatabaseObjectType[], keyContainer?: KeyContainer): Promise<void> {
        console.log("toFirestore", objects);
        if(objects.length==0) return;
        
        // TODO
        // keyContainer = objects[0].app.keyStore.createKeyContainer();

        let result = await objects[0].app.firebase.functions("europe-west3").httpsCallable("setDocuments")(JSON.stringify(await DatabaseObject.toDocumentData(objects, true, keyContainer)));
        if (result.data !== true) throw new Error("unkown error");
        objects.forEach(o => o.version++);
    }
    uploadToFirestore(keyContainer?: KeyContainer): Promise<void> {
        return DatabaseObject.uploadToFirestore([this], keyContainer);
    }

    static async deleteFromFirestore(objects: DatabaseObjectType[], keyContainer?: KeyContainer): Promise<void> {
        console.log("delete", objects);


        let result = await objects[0].app.firebase.functions("europe-west3").httpsCallable("setDocuments")(JSON.stringify(await DatabaseObject.deleteDocumentData(objects)));
        if (result.data !== true) throw new Error("unkown error");
    }
    deleteFromFirestore(): Promise<void> {
        return DatabaseObject.deleteFromFirestore([this]);
    }
}