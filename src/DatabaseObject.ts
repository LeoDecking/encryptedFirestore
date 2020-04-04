import { AutoId } from "./AutoId";
import { VerifyKey } from "./Key";
import { DatabaseObjectType, GetOwner, DatabaseChildObjectType } from "./DatabaseObjectType";
import { App } from "./App";
import { KeyStore } from "./KeyStore";
import { Job, City, AppApp } from "./Job";

export abstract class DatabaseObject<Tstring extends string, T extends DatabaseObjectType, P extends DatabaseObjectType | App, ParentIsOwner extends boolean = true> {
    private _type?: Tstring;
    private readonly ignoreProperties = ["ignoreProperties", "parentIsOwner", "collection", "encryptedProperties", "id", "app", "parent", "verifyKey"];
    // TODO derivedIgnoreProperties
    abstract readonly parentIsOwner: ParentIsOwner;
    abstract readonly collection: string;
    abstract readonly encryptedProperties: string[];

    readonly app: App;
    readonly parent: P;
    get owner(): GetOwner<T> {
        return (App.isApp(this.parent) || this.parentIsOwner ? this.parent : (this.parent as DatabaseObjectType).owner) as GetOwner<T>;
    }

    private readonly id: string;
    get path(): string {
        return this.parent.path + "/" + this.collection + "/" + this.id;
    }
    version: number = 0;

    verifyKey?: VerifyKey;
    // you can store the secret key of an object encrypted by different keys
    encryptedSecretKey: { [path: string]: string } = {};

    constructor(parent: P, id: string = AutoId.newId()) {
        this.id = id;
        this.parent = parent;
        this.app = App.isApp(parent) ? parent : (parent as DatabaseObjectType).app;
    }

    newChild<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id?: string): C {
        return new child(this, id);
    }

    async uploadToFirestore(): Promise<void> {
        console.log("toFirestore", this);

        let documentData: any = {};
        await Promise.all(Object.keys(this).map(async k => {
            // console.log("property", k, (this as { [key: string]: any })[k]);
            if (this.ignoreProperties.indexOf(k) == -1)
                if (this.encryptedProperties?.indexOf(k) != -1) {
                    // console.log("encrypt property", k, await keystore.encrypt(this, (this as { [key: string]: any })[k]));
                    documentData[k] = await this.app.keyStore.encrypt(this, (this as { [key: string]: any })[k]);
                }
                else {
                    // console.log("not encrypted property", k)
                    documentData[k] = (this as { [key: string]: any })[k];
                }
            // else console.log("ignore property", k);
        }));
        documentData["path"] = this.path;
        if (this.verifyKey) documentData["verifyKey"] = this.verifyKey?.string;
        documentData["version"]++;

        // console.log("encrypted", documentData);
        console.log("signed", await this.app.keyStore.sign(this.owner, documentData));
        // TODO test if encrypted properties are there
        let signedObject = await this.app.keyStore.sign(this.owner, documentData);

        let result = await this.app.firebase.functions("europe-west3").httpsCallable("setDocument")(signedObject);
        if (result.data !== true) throw new Error("unkown error");
    }

    async a() {
        let b = await Job.collectionFromFirestore(null,[],()=>alert(42)).
        b
    }

    // TODO realtime in anyy method
    
    static async fromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], id: string): Promise<T> {
        let dummy = new this(parent, id);
        let documents = await DatabaseObject.collectionFromFirestore.call(this, parent, [{ fieldPath: "path", opStr: "==", value: dummy.path }]);
        if (documents.length != 1) throw new Error("document not found");
        return documents[0] as T;
    }

    static async collectionFromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[]): Promise<T[]>;
    static async collectionFromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[], onSnapshot: (objs: { obj: T, change?: firebase.firestore.DocumentChange<firebase.firestore.DocumentData> }[]) => void): Promise<(() => void)>;
    static async collectionFromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[] = [], onSnapshot?: (objs: { obj: T, change?: firebase.firestore.DocumentChange<firebase.firestore.DocumentData> }[]) => void): Promise<T[] | (() => void)> {
        let dummy = new this(parent);

        let query: firebase.firestore.CollectionReference<firebase.firestore.DocumentData> | firebase.firestore.Query<firebase.firestore.DocumentData>
            = dummy.app.firebase.firestore().collection(parent.path + "/" + dummy.collection);
        queries.forEach(q => query = query.where(q.fieldPath, q.opStr, q.value));

        if (!onSnapshot)
            return await Promise.all((await query.get({ source: "server" })).docs.map(d => DatabaseObject.getObjectFromDocument.call(this, parent, d) as Promise<T>)) as T[];
        else
            return query.onSnapshot(async s => {
                let changes = s.docChanges();
                onSnapshot((await Promise.all(s.docs.map(d => DatabaseObject.getObjectFromDocument.call(this, parent, d)))).map(o => ({ obj: o as T, change: changes.find(c => c.doc.id == o.id) })));
            }) as (() => void);
    }

    private static async getObjectFromDocument<T extends DatabaseObjectType>(this: new (parent: T["parent"], id?: string) => T, parent: T["parent"], document: firebase.firestore.QueryDocumentSnapshot<firebase.firestore.DocumentData>): Promise<T> {
        let object = new this(parent, document.id);
        let documentData: { [key: string]: any } = object.app.keyStore.verify(object.owner, document.data() as T & { signature: string });
        if (documentData.path != object.path) throw new Error("wrong path: " + object.path);

        await Promise.all(Object.keys(object).map(async k => {
            if (object.ignoreProperties.indexOf(k) == -1)
                if (object.encryptedProperties?.indexOf(k) != -1) {
                    // TODO undefined properties
                    (object as { [key: string]: any })[k] = await object.app.keyStore.decrypt(object, documentData[k]);
                }
                else {
                    // console.log("not encrypted property", k)
                    (object as { [key: string]: any })[k] = documentData[k];
                }
            // else console.log("ignore property", k);
        }));
        if (documentData.verifyKey) object.verifyKey = new VerifyKey(documentData.verifyKey);

        return object as T;
    }

    childFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, id: string): Promise<C> {
        return DatabaseObject.fromFirestore.call(child as any, this, id) as Promise<C>;
    }

    childrenFromFirestore<C extends DatabaseChildObjectType<this>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[] = []): Promise<C[]> {
        return DatabaseObject.collectionFromFirestore.call(child as any, this, queries) as Promise<C[]>;
    }
}