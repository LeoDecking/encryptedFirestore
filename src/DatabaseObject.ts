import { AutoId } from "./AutoId";
import { VerifyKey, SignKey, SecretKey } from "./Key";
import { DatabaseObjectType, GetOwner, DatabaseChildObjectType } from "./DatabaseObjectType";
import { App } from "./App";
import { Crypto } from "./Crypto";
import { KeyContainer } from "./KeyStore";

// Every property must be default initialized!
export abstract class DatabaseObject<Tstring extends string, T extends DatabaseObjectType, P extends DatabaseObjectType | App, ParentIsOwner extends boolean = true> {
    private _type?: Tstring;
    abstract readonly databaseOptions: {
        parentIsOwner: ParentIsOwner,
        collection: string,
        // TODO useless?
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

    // TODO keygeneration
    constructor(parent: P, id: string = AutoId.newId()) {
        this.id = id;
        this.parent = parent;
        this.app = App.isApp(parent) ? parent : (parent as DatabaseObjectType).app;
    }

    // TODO without constructor
    clone(constructor: new (parent: P, id?: string) => T): T {
        let object = new constructor(this.parent, this.id) as T;
        Object.keys(this).forEach(k => (object as { [key: string]: any })[k] = (this.ignoreProperties.indexOf(k) == -1) ? Crypto.sortObject((this as { [key: string]: any })[k]) : (this as { [key: string]: any })[k]);
        return object;
    }

    // TODO setKeys (all)
    async setSecretKey(keyOrPassword?: SecretKey | string) {
        let secretKey: SecretKey;
        if (keyOrPassword == undefined) secretKey = SecretKey.generate();
        else if (typeof keyOrPassword == "string") secretKey = await SecretKey.generate(keyOrPassword, this.path);
        else secretKey = keyOrPassword as SecretKey;

        this.keyHash = Crypto.hash(secretKey.string);
        this.encryptedSecretKey = {};
        if (this.databaseOptions.ownerMayRead && !App.isApp(this.parent))
            this.encryptedSecretKey[this.owner.path] = await this.app.keyStore.encrypt(this.owner as DatabaseObjectType, secretKey.string);

        return this;
    }

    async setSignKey(keyOrPassword?: SecretKey | string) {
        let signKey: SignKey;
        if (keyOrPassword == undefined) signKey = SignKey.generate();
        else if (typeof keyOrPassword == "string") signKey = await SignKey.generate(keyOrPassword, this.path);
        else signKey = keyOrPassword as SignKey;

        this.verifyKey = signKey.verifyKey;
        // TODO encrypt signKey for owner
        // if (this.databaseOptions.ownerMayWrite && !App.isApp(this.owner))
        //     this.encryptedSecretKey[this.owner.path] = await this.app.keyStore.encrypt(this.owner as DatabaseObjectType, secretKey.string);

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

    uploadToFirestore(): Promise<void> {
        return DatabaseObject.uploadToFirestore([this]);
    }

    delete(): Promise<void> {
        return DatabaseObject.delete([this]);
    }

    static async delete(objects: DatabaseObjectType[]): Promise<void> {
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
            await Promise.all(Object.keys(object).map(async k => {
                if (object.ignoreProperties.indexOf(k) == -1)
                    // TODO (encrypted) sub-properties
                    if (object.databaseOptions.encryptedProperties?.indexOf(k) != -1) {
                        documentData[k] = await object.app.keyStore.encrypt(object, (object as { [key: string]: any })[k], keyContainer);
                    }
                    else {
                        documentData[k] = (object as { [key: string]: any })[k];
                    }
            }));
            documentData["path"] = object.path;
            if (object.verifyKey) documentData["verifyKey"] = object.verifyKey?.string;
            documentData["version"]++;

            console.log("signed", await object.app.keyStore.sign(object.owner, documentData, keyContainer));
            return await object.app.keyStore.sign(object.owner, documentData);
        }));
        let result = await objects[0].app.firebase.functions("europe-west3").httpsCallable("setDocuments")(JSON.stringify(signedObjects));
        if (result.data !== true) throw new Error("unkown error");
    }

    static fromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], id: string): Promise<T>;
    static fromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], id: string, onSnapshot: (object: T) => void): () => void;
    static fromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], id: string, onSnapshot?: (object: T) => void): Promise<T> | (() => void) {
        let dummy = new this(parent, id);
        if (!onSnapshot) {
            return new Promise(async (resolve, reject) => {
                let documents = await DatabaseObject.collectionFromFirestore.call(this, parent, [{ fieldPath: "path", opStr: "==", value: dummy.path }]);
                if (documents.length != 1) reject("document not found");
                else resolve(documents[0] as T);
            });
        } else {
            return DatabaseObject.collectionFromFirestore.call(this, parent, [{ fieldPath: "path", opStr: "==", value: dummy.path }], ((objects: T[]) => onSnapshot(objects[0])));
        }
    }

    static collectionFromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[]): Promise<T[]>;
    static collectionFromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[], onSnapshot: (objects: T[]) => void): (() => void);
    static collectionFromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[] = [], onSnapshot?: ((objects: T[]) => void)): Promise<T[]> | (() => void) {
        let dummy = new this(parent);

        let query: firebase.firestore.CollectionReference<firebase.firestore.DocumentData> | firebase.firestore.Query<firebase.firestore.DocumentData>
            = dummy.app.firebase.firestore().collection(parent.path + "/" + dummy.databaseOptions.collection);
        queries.forEach(q => query = query.where(q.fieldPath, q.opStr, q.value));

        if (!onSnapshot)
            return query.get({ source: "server" }).then(s => Promise.all(s.docs.map(d => DatabaseObject.getObjectFromDocument.call(this, parent, d) as Promise<T>)));
        else
            return query.onSnapshot(async s => {
                // type: : (objs: { obj: T, change?: firebase.firestore.DocumentChange<firebase.firestore.DocumentData> }[] => void
                // let changes = s.docChanges();
                // console.log(changes);
                // console.log(s.docs);
                // onSnapshot((await Promise.all(s.docs.map(d => DatabaseObject.getObjectFromDocument.call(this, parent, d)))).map(o => ({ obj: o as T, change: changes.find(c => c.doc.id == o.id) })));
                onSnapshot(await Promise.all(s.docs.map(d => DatabaseObject.getObjectFromDocument.call(this, parent, d))) as T[]);
            }) as (() => void);
    }

    private static async getObjectFromDocument<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], document: firebase.firestore.QueryDocumentSnapshot<firebase.firestore.DocumentData>): Promise<T> {
        let object = new this(parent, document.id);
        let documentData: { [key: string]: any } = object.app.keyStore.verify(object.owner, document.data() as T & { signature: string });
        if (documentData.path != object.path) throw new Error("wrong path: " + object.path);

        let keyContainer = new KeyContainer();

        await Promise.all(Object.keys(object).map(async k => {
            if (object.ignoreProperties.indexOf(k) == -1)
                // TODO sub-properties
                if (object.databaseOptions.encryptedProperties?.indexOf(k) != -1) {
                    // TODO undefined properties
                    (object as { [key: string]: any })[k] = Crypto.sortObject(await object.app.keyStore.decrypt(object, documentData[k], keyContainer), true);
                }
                else {
                    // console.log("not encrypted property", k)
                    (object as { [key: string]: any })[k] = Crypto.sortObject(documentData[k], true);
                }
            // else console.log("ignore property", k);
        }));
        if (documentData.verifyKey) object.verifyKey = new VerifyKey(documentData.verifyKey);

        return object as T;
    }

    childFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id: string): Promise<C>;
    childFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id: string, onSnapshot: (object: C) => void): () => void;
    childFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id: string, onSnapshot?: (object: C) => void): Promise<C> | (() => void) {
        return DatabaseObject.fromFirestore.call(child as any, this, id, onSnapshot);
    }

    childrenFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[]): Promise<C[]>;
    childrenFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[], onSnapshot: (objects: C[]) => void): () => void;
    childrenFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[] = [], onSnapshot?: (objects: C[]) => void): Promise<C[]> | (() => void) {
        return DatabaseObject.collectionFromFirestore.call(child as any, this, queries, onSnapshot);
    }
}