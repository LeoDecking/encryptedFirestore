import { firestore } from "firebase";
import { AutoId } from "./AutoId";
import { VerifyKey } from "./Key";
import { DatabaseObjectType, GetOwner } from "./DatabaseObjectType";
import { App } from "./App";
import { KeyStore } from "./KeyStore";

export abstract class DatabaseObject<Tstring extends string, T extends DatabaseObjectType, P extends DatabaseObjectType | App, ParentIsOwner extends boolean = true> {
    private _type?: Tstring;
    private readonly ignoreProperties = ["ignoreProperties", "parentIsOwner", "collection", "encryptedProperties", "id", "parent", "owner"];
    abstract readonly parentIsOwner: ParentIsOwner;
    abstract readonly collection: string;
    abstract readonly encryptedProperties: string[];

    readonly parent: P;
    readonly owner: GetOwner<T>;


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
        this.parent = parent;
        // this.path = parent.path + "/" + (this as any).collection + "/" + id; 
        this.id = id;

        let current: DatabaseObjectType = this;
        for (; !App.isApp(current.parent) && !current.parentIsOwner; current = current.parent);
        this.owner = current.parent as GetOwner<T>;
    }

    async toFirestore(keystore: KeyStore): Promise<{ [key: string]: any }> {
        let documentData: any = {};
        await Promise.all(Object.keys(this).map(async k => {
            if (this.ignoreProperties.indexOf(k) == -1)
                if (this.encryptedProperties?.indexOf(k) != -1)
                    documentData[k] = await keystore.encrypt(this, (this as { [key: string]: any })[k]);
                else
                    documentData[k] = (this as { [key: string]: any })[k];
        }));
        console.log("encrypted", documentData);
        // TODO test if encrypted properties are there
        return await keystore.sign(this.owner, documentData);
    }

    // static converter<T extends DatabaseObjectType>(this: new (parent: T["parent"]) => T, parent: T["parent"], keystore: KeyStore) {
    //     let constructor = this;
    //     return {
    //         // result will be sent to firebase cloud functions
    //         toFirestore<T>(databaseObject: T): firestore.DocumentData {
    //             let ignoreProperties = ["parentIsOwner", "collection", "encryptedProperties", "parent", "owner"];

    //             let documentData = {};
    //             Object.keys(databaseObject).forEach(k => {
    //                 if (ignoreProperties.indexOf(k) != -1)
    //                     doc
    //             });
    //             // documentData.signature = "";
    //             // TODO test if _type is present
    //             return documentData;
    //         },
    //         // executed on client
    //         fromFirestore(snapshot: firestore.QueryDocumentSnapshot, options: firestore.SnapshotOptions): T {

    //             const data = snapshot.data(options)!;
    //             keystore.sign(owner, new constructor(parent))
    //             return new constructor(parent);
    //         }
    //     };
    // }
}