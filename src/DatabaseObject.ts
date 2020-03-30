import { firestore } from "firebase";
import { Job, City, App } from "./Job";
import { AutoId } from "./AutoId";

export class DatabaseObject<Tstring extends string, T extends DatabaseObjectType, P extends DatabaseObjectType> {
    private _type?: Tstring;
    parent?: P;

    // properties: { [K in keyof this]?: true } = { parent: true };
    private superProperties: string[] = ["id", "version", "secretKey"];
    properties: string[] = [];

    id: string = AutoId.newId();
    version: number = 0;

    verifyKey?: VerifyKey<T>;

    // secretKey?: EncryptedProperty<Parent, SecretKey<T>>;

    // parent has to be set except for app
    // TODO only allow parent not to be set for app 
    constructor(parent?: P) {
        this.parent = parent;
    }

    static converter<T extends DatabaseObjectType>(this: new (parent: T["parent"]) => T, parent: T["parent"]) {
        let constructor = this;
        return {
            toFirestore<T>(databaseObject: T): firestore.DocumentData {
                // TODO throw error if id is undefined
                let documentData = { ...databaseObject, parent: undefined };
                // documentData.signature = "";
                // TODO test if _type is present
                return documentData;
            },
            fromFirestore(snapshot: firestore.QueryDocumentSnapshot, options: firestore.SnapshotOptions): T {
                const data = snapshot.data(options)!;
                return new constructor(parent);
            }
        };
    }
}

export type DatabaseObjectType = DatabaseObject<string, DatabaseObjectType, DatabaseObjectType> | never;


class Key<K extends string, T extends DatabaseObjectType> {
    private _keyType?: K;
    private _objectType?: T;

    string: string;
    uint8Array: Uint8Array;

    constructor(_t: new (parent: T["parent"]) => T, key: string | Uint8Array) {
        this.string = typeof key == "string" ? key : "";
        this.uint8Array = typeof key == "string" ? new Uint8Array() : key;
    }
}

class SignKey<T extends DatabaseObjectType> extends Key<"sign", T> { }
export class VerifyKey<T extends DatabaseObjectType> extends Key<"verify", T> { }
class SecretKey<T extends DatabaseObjectType> extends Key<"secret", T> { }
