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



    // readonly path: string;
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

    static async fromFirestore<T extends DatabaseObjectType>(this: new (parent: T["parent"], id: string) => T, parent: T["parent"], id: string): Promise<T> {
        let object = new this(parent, id);
        let documentData: { [key: string]: any } = object.app.keyStore.verify(object.owner, (await object.app.firebase.firestore().doc(object.path).get({ source: "server" })).data() as T & { signature: string });
        console.log("object", object);
        console.log(documentData, documentData);
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

        return object;
    }

    childFromFirestore<C extends DatabaseChildObjectType<T>>(child: new (parent: T, id: string) => C, id: string): Promise<C> {
        return DatabaseObject.fromFirestore.call(child as any, this, id) as Promise<C>;
    }
}