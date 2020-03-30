import { firestore } from "firebase";
import { AutoId } from "./AutoId";
import { VerifyKey } from "./Key";
import { DatabaseObjectType, GetOwner } from "./DatabaseObjectType";
import { App } from "./App";

export abstract class DatabaseObject<Tstring extends string, T extends DatabaseObjectType, P extends DatabaseObjectType | App, ParentIsOwner extends boolean = true> {
    private _type?: Tstring;
    abstract readonly _parentIsOwner: ParentIsOwner;
    abstract readonly _collection: string;

    readonly parent: P;
    readonly owner: GetOwner<T>;

    abstract readonly _properties: string[];


    id: string = AutoId.newId();
    version: number = 0;

    verifyKey?: VerifyKey<T>;

    // secretKey?: EncryptedProperty<Parent, SecretKey<T>>;

    constructor(parent: P) {
        this.parent = parent;

        let current: DatabaseObjectType = this;
        for (; !App.isApp(current.parent) && !current._parentIsOwner; current = current.parent);
        this.owner = current.parent as GetOwner<T>;
    }

    // private
    getPath(): string {
        let path: string = "";
        for (let current: DatabaseObjectType | App = this; !App.isApp(current); current = current.parent) {
            path = "/" + current._collection + "/" + current.id + path;
        }
        return path;
    }

    static converter<T extends DatabaseObjectType>(this: new (parent: T["parent"]) => T, parent: T["parent"], path: string) {
        let constructor = this;
        return {
            // result will be sent to firebase cloud functions
            toFirestore<T>(databaseObject: T): firestore.DocumentData {
                // TODO throw error if id is undefined
                let documentData = { ...databaseObject, parent: undefined };
                // documentData.signature = "";
                // TODO test if _type is present
                return documentData;
            },
            // executed on client
            fromFirestore(snapshot: firestore.QueryDocumentSnapshot, options: firestore.SnapshotOptions): T {
                const data = snapshot.data(options)!;
                return new constructor(parent);
            }
        };
    }
}