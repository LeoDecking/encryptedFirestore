import { firestore } from "firebase";
import { Job, City, App } from "./Job";

export class DatabaseObject<Tstring extends string, T extends DatabaseObjectType, Parent extends DatabaseObjectType> {
    private _type?: Tstring;
    parent?: Parent;

    id?: string;
    version: number = 0;

    verifyKey?: VerifyKey<T>; // TODO verifyKey must be signed by parent

    constructor(parent?: Parent) {
        this.parent = parent;
    }

    // TODO not optional document
    static fromDocumentSnapshot<T extends DatabaseObjectType>(this: new (parent: T["parent"]) => T, parent: T["parent"], document?: firestore.DocumentSnapshot): T {
        //verify signature
        //remove signature
        // add parent
        //set id
        return new this(parent) as T;
    }

    toDocumentData(signKey: SignKey<Parent>): firestore.DocumentData {
        let documentData: Omit<this, "id" | "parent"> & { signature?: string } = { ...this, id: undefined, parent: undefined };
        documentData.signature = "";
        // TODO test if _type is present
        return documentData;
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




let a = Job.fromDocumentSnapshot(new City(new App())).toDocumentData(new SignKey(City, ""));
