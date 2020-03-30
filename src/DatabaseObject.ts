import { firestore } from "firebase";
import { AutoId } from "./AutoId";
import { Job, City } from "./Job";

export class DatabaseObject<Tstring extends string, T extends DatabaseObjectType, P extends DatabaseObjectType, O extends DatabaseObjectType = P> {
    type: Tstring;
    parent?: O;

    // properties: { [K in keyof this]?: true } = { parent: true };
    private superProperties: string[] = ["id", "path", "version", "secretKey"];
    properties: string[] = [];

    id: string = AutoId.newId();
    version: number = 0;

    verifyKey?: VerifyKey<T>;

    // secretKey?: EncryptedProperty<Parent, SecretKey<T>>;

    // parent has to be set except for app
    // TODO only allow parent not to be set for app 
    constructor(parent?: O) {
        this.parent = parent;
        this.type=a;
    }

    static converter<T extends DatabaseObjectType>(this: new (parent: T["parent"]) => T, parent: T["parent"], path: string) {
        let constructor = this;
        return {
            // executed in firebase cloud functions
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

type GetOwner<T,B> = B extends true ? T["parent"] : GetOwner<T["parent"],T["owserIsParent"]

Job.converter(new City(), `/${new City().id}/`)

export type DatabaseObjectType = DatabaseObject<string, DatabaseObjectType, DatabaseObjectType, DatabaseObjectType> | never;


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
