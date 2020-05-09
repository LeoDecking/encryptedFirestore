import { AutoId } from "./AutoId";
import { VerifyKey, SignKey, SecretKey } from "./Key";
import { DatabaseObjectType, GetOwner, DatabaseChildObjectType } from "./DatabaseObjectType";
import { App } from "./App";
import { Crypto } from "./Crypto";
import { KeyContainer } from "./KeyStore";

// Every property must be default initialized!
export abstract class DatabaseObject<Tstring extends string, T extends DatabaseObjectType, P extends DatabaseObjectType | App, ParentIsOwner extends boolean = true> {
    private _type?: Tstring;
    // TODO canEncrypt??
    abstract readonly databaseOptions: {
        parentIsOwner: ParentIsOwner,
        collection: string,
        canSign: boolean,
        ownerMayRead: boolean,
        ownerMayWrite: boolean,
        encryptedProperties?: string[]

    };
    private readonly ignoreProperties = ["databaseOptions", "ignoreProperties", "id", "app", "parent", "verifyKey"];

    readonly app: App;
    readonly parent: P;
    get owner(): GetOwner<T> { return (App.isApp(this.parent) || this.databaseOptions.parentIsOwner ? this.parent : (this.parent as DatabaseObjectType).owner) as GetOwner<T>; }

    readonly id: string;
    get path(): string { return this.parent.path + "/" + this.databaseOptions.collection + "/" + this.id; }
    version: number = 0;

    keyHash: string = "";
    verifyKey?: VerifyKey;
    // you can store the secret key of an object encrypted by different keys
    encryptedSecretKey: { [path: string]: string } = {};


    constructor(parent: P, id: string = AutoId.newId()) {
        this.id = id;
        this.parent = parent;
        this.app = App.isApp(parent) ? parent : (parent as DatabaseObjectType).app;
    }

    static async fromDocumentData<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], documentData: { [key: string]: any }, id: string = AutoId.newId(), opaque: boolean = false, keyContainer: KeyContainer = new KeyContainer()): Promise<T> {
        let object = new this(parent, id);
        object.app.keyStore.verify(object.owner as GetOwner<T>, documentData as T & { signature: string });
        if (documentData.path != object.path) throw new Error("wrong path: " + object.path);


        Object.keys(object).filter(k => object.ignoreProperties.indexOf(k) == -1 && (!object.databaseOptions.encryptedProperties || object.databaseOptions.encryptedProperties.indexOf(k) == -1)).forEach(k =>
            (object as { [key: string]: any })[k] = Crypto.sortObject(documentData[k], true)
        );

        if (!opaque && object.databaseOptions.encryptedProperties?.length && documentData.encryptedProperties) {
            let encryptedProperties: { [key: string]: any } = await Crypto.sortObject(await object.app.keyStore.decrypt(object, documentData.encryptedProperties, keyContainer), true);

            Object.keys(object).filter(k => object.ignoreProperties.indexOf(k) == -1 && object.databaseOptions.encryptedProperties?.indexOf(k) != -1).forEach(k =>
                (object as { [key: string]: any })[k] = Crypto.sortObject(encryptedProperties[k], true)
            );

        }
        // else if(object.databaseOptions.encryptedProperties?.length) {
        //     await Promise.all(Object.keys(object).filter(k => object.ignoreProperties.indexOf(k) == -1 && object.databaseOptions.encryptedProperties?.indexOf(k) != -1).map(async k =>
        //         (object as { [key: string]: any })[k] = Crypto.sortObject(await Crypto.sortObject(await object.app.keyStore.decrypt(object, documentData[k], keyContainer), true), true)
        //     ));
        // }

        if (documentData.verifyKey) object.verifyKey = new VerifyKey(documentData.verifyKey);

        return object as T;
    }

    // TODO test
    async childFromDocumentData<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, documentData: { [key: string]: any }, id: string = AutoId.newId(), opaque: boolean = false, keyContainer: KeyContainer = new KeyContainer()): Promise<C> {
        return await DatabaseObject.fromDocumentData.call(child, parent, documentData, id, opaque, keyContainer);
    }

    async updateFromDocumentData(constructor: new (parent: P, id?: string) => T, documentData: { [key: string]: any }, opaque: boolean = false, keyContainer: KeyContainer = new KeyContainer()): Promise<this> {
        let updated = await DatabaseObject.fromDocumentData.call(constructor, this.parent, documentData, this.id, opaque, keyContainer);
        Object.keys(this).forEach(k => (this as { [key: string]: any })[k] = updated[k]);
        return this;
    }

    // TODO without constructor
    clone(constructor: new (parent: P, id?: string) => T): T {
        let object = new constructor(this.parent, this.id) as T;
        Object.keys(object).forEach(k => (object as { [key: string]: any })[k] = (this.ignoreProperties.indexOf(k) == -1) ? Crypto.sortObject((this as { [key: string]: any })[k]) : (this as { [key: string]: any })[k]);
        return object;
    }

    cloneFrom(object: this): this {
        Object.keys(this).forEach(k => (this as { [key: string]: any })[k] = (this.ignoreProperties.indexOf(k) == -1) ? Crypto.sortObject((object as { [key: string]: any })[k]) : (object as { [key: string]: any })[k]);
        return this;
    }

    async getOpaquePassword(password: string): Promise<string> {
        let opaque: { keyHash?: string, verifyKey?: string } = {};
        opaque.keyHash = Crypto.hash((await SecretKey.generate(password, this.path)).string);
        if (this.databaseOptions.canSign) opaque.verifyKey = (await SignKey.generate(password, this.path)).verifyKey.string;

        return btoa(JSON.stringify(opaque));
    }

    setOpaquePasswort(opaque: string): this {
        let o = JSON.parse(atob(opaque));
        this.keyHash = o["keyHash"];
        this.verifyKey = o["verifyKey"];

        return this;
    }

    // TODO encrypt signKey for parents?
    async setPassword(password?: string): Promise<this> {
        let secretKey: SecretKey;
        if (password == undefined) secretKey = SecretKey.generate();
        else secretKey = await SecretKey.generate(password, this.path);

        this.keyHash = Crypto.hash(secretKey.string);
        this.encryptedSecretKey = {};
        if (this.databaseOptions.ownerMayRead && !App.isApp(this.parent))
            this.encryptedSecretKey[this.owner.path] = await this.app.keyStore.encrypt(this.owner as DatabaseObjectType, secretKey.string);

        if (this.databaseOptions.canSign) {
            let signKey: SignKey;
            if (password == undefined) signKey = SignKey.generate();
            else signKey = await SignKey.generate(password, this.path);

            this.verifyKey = signKey.verifyKey;
        }

        return this;
    }

    newChild<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id?: string): C {
        return new child(this, id);
    }

    hash(): string {
        let object: any = {};
        Object.keys(this).map(async k => {
            if (this.ignoreProperties.indexOf(k) == -1)
                object[k] = (this as { [key: string]: any })[k];
        });
        return Crypto.hash(object);
    }

    // TODO export/save documentData - signature??

    uploadToFirestore(): Promise<void> {
        return DatabaseObject.uploadToFirestore([this]);
    }

    async updateFromFirestore(constructor: new (parent: P, id?: string) => T): Promise<this> {
        let updated = await DatabaseObject.fromFirestore.call(constructor, this.parent, this.id);
        Object.keys(this).forEach(k => (this as { [key: string]: any })[k] = updated[k]);
        return this;
    }

    deleteFromFirestore(): Promise<void> {
        return DatabaseObject.deletefromFirestore([this]);
    }

    static async deletefromFirestore(objects: DatabaseObjectType[]): Promise<void> {
        console.log("delete", objects);

        let keyContainer = new KeyContainer();

        let signedObjects = await Promise.all(objects.map(async object => {
            if (object.version == 0) throw new Error("trying to delete 0 version");

            let documentData: any = {
                path: object.path,
                version: -object.version
            };

            console.log("signed", await object.app.keyStore.sign(object.owner, documentData, keyContainer));
            return await object.app.keyStore.sign(object.owner, documentData, keyContainer);
        }));

        let result = await objects[0].app.firebase.functions("europe-west3").httpsCallable("setDocuments")(JSON.stringify(signedObjects));
        if (result.data !== true) throw new Error("unkown error");
    }

    static async uploadToFirestore(objects: DatabaseObjectType[]): Promise<void> {
        console.log("toFirestore", objects);
        if (objects.length == 0) return;

        let keyContainer = new KeyContainer();

        let signedObjects = await Promise.all(objects.map(async object => {
            let documentData: any = {};

            Object.keys(object).filter(k => object.ignoreProperties.indexOf(k) == -1 && (!object.databaseOptions.encryptedProperties || object.databaseOptions.encryptedProperties.indexOf(k) == -1)).forEach(k =>
                documentData[k] = (object as { [key: string]: any })[k]
            );

            if (object.databaseOptions.encryptedProperties?.length) {
                let encryptedProperties: { [key: string]: any } = {};
                Object.keys(object).filter(k => object.ignoreProperties.indexOf(k) == -1 && object.databaseOptions.encryptedProperties!.indexOf(k) != -1).forEach(k =>
                    encryptedProperties[k] = (object as { [key: string]: any })[k]
                );

                documentData.encryptedProperties = await object.app.keyStore.encrypt(object, encryptedProperties, keyContainer);
            }

            documentData["path"] = object.path;
            if (object.verifyKey) documentData["verifyKey"] = object.verifyKey?.string;
            documentData["version"]++;

            // console.log("signed", await object.app.keyStore.sign(object.owner, documentData, keyContainer));
            return await object.app.keyStore.sign(object.owner, documentData, keyContainer);
        }));
        let result = await objects[0].app.firebase.functions("europe-west3").httpsCallable("setDocuments")(JSON.stringify(signedObjects));
        if (result.data !== true) throw new Error("unkown error");
        objects.forEach(o => o.version++);
    }

    // TODO keycontainer

    // TODO ids from firestore (more than 10)

    static fromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], id: string, opaque?: boolean): Promise<T>;
    static fromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], id: string, opaque: boolean, onSnapshot: (object: T) => void): () => void;
    static fromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], id: string, opaque: boolean = false, onSnapshot?: (object: T) => void): Promise<T> | (() => void) {
        let dummy = new this(parent, id);
        if (!onSnapshot) {
            return new Promise(async (resolve, reject) => {
                let documents = await DatabaseObject.collectionFromFirestore.call(this, parent, [{ fieldPath: "path", opStr: "==", value: dummy.path }], opaque);
                if (documents.length != 1) reject("document not found");
                else resolve(documents[0] as T);
            });
        } else {
            return DatabaseObject.collectionFromFirestore.call(this, parent, [{ fieldPath: "path", opStr: "==", value: dummy.path }], opaque, ((objects: T[]) => onSnapshot(objects[0])));
        }
    }

    // TODO changes?
    static collectionFromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[], opaque?: boolean): Promise<T[]>;
    static collectionFromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[], opaque: boolean, onSnapshot: (objects: T[]) => void): (() => void);
    static collectionFromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[] = [], opaque: boolean = false, onSnapshot?: ((objects: T[]) => void)): Promise<T[]> | (() => void) {
        let dummy = new this(parent);

        let query: firebase.firestore.CollectionReference<firebase.firestore.DocumentData> | firebase.firestore.Query<firebase.firestore.DocumentData>
            = dummy.app.firebase.firestore().collection(parent.path + "/" + dummy.databaseOptions.collection);
        queries.forEach(q => query = query.where(q.fieldPath, q.opStr, q.value));

        if (!onSnapshot)
            return query.get({ source: "server" }).then(s => Promise.all(s.docs.map(d => DatabaseObject.fromDocumentData.call(this, parent, d.data(), d.id, opaque, opaque) as Promise<T>)));
        else
            return query.onSnapshot(async s => {
                // type: : (objs: { obj: T, change?: firebase.firestore.DocumentChange<firebase.firestore.DocumentData> }[] => void
                // let changes = s.docChanges();
                // console.log(changes);
                // console.log(s.docs);
                // onSnapshot((await Promise.all(s.docs.map(d => DatabaseObject.getObjectFromDocument.call(this, parent, d)))).map(o => ({ obj: o as T, change: changes.find(c => c.doc.id == o.id) })));
                onSnapshot(await Promise.all(s.docs.map(d => DatabaseObject.fromDocumentData.call(this, parent, d.data(), d.id, opaque))) as T[]);
            }) as (() => void);
    }

    childFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id: string, opaque?: boolean): Promise<C>;
    childFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id: string, opaque: boolean, onSnapshot: (object: C) => void): () => void;
    childFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id: string, opaque: boolean = false, onSnapshot?: (object: C) => void): Promise<C> | (() => void) {
        return DatabaseObject.fromFirestore.call(child as any, this, id, opaque, onSnapshot);
    }

    childrenFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[], opaqu?: boolean): Promise<C[]>;
    childrenFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[], opaque: boolean, onSnapshot: (objects: C[]) => void): () => void;
    childrenFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[] = [], opaque: boolean = false, onSnapshot?: (objects: C[]) => void): Promise<C[]> | (() => void) {
        return DatabaseObject.collectionFromFirestore.call(child as any, this, queries, opaque, onSnapshot);
    }

}