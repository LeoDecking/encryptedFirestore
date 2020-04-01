import { firestore } from "firebase";
import { AutoId } from "./AutoId";
import { VerifyKey } from "./Key";
import { DatabaseObjectType, GetOwner } from "./DatabaseObjectType";
import { App } from "./App";
import { KeyStore } from "./KeyStore";

export abstract class DatabaseObject<Tstring extends string, T extends DatabaseObjectType, P extends DatabaseObjectType | App, ParentIsOwner extends boolean = true> {
    private _type?: Tstring;
    private readonly ignoreProperties = ["ignoreProperties", "parentIsOwner", "collection", "encryptedProperties", "id", "parent"];
    // TODO derivedIgnoreProperties
    abstract readonly parentIsOwner: ParentIsOwner;
    abstract readonly collection: string;
    abstract readonly encryptedProperties: string[];

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
    }

    async toFirestore(keystore: KeyStore): Promise<{ [key: string]: any }> {
        console.log("toFirestore", this);

        let documentData: any = {};
        await Promise.all(Object.keys(this).map(async k => {
            // console.log("property", k, (this as { [key: string]: any })[k]);
            if (this.ignoreProperties.indexOf(k) == -1)
                if (this.encryptedProperties?.indexOf(k) != -1) {
                    // console.log("encrypt property", k, await keystore.encrypt(this, (this as { [key: string]: any })[k]));
                    documentData[k] = await keystore.encrypt(this, (this as { [key: string]: any })[k]);
                }
                else {
                    // console.log("not encrypted property", k)
                    documentData[k] = (this as { [key: string]: any })[k];
                }
            // else console.log("ignore property", k);
        }));
        documentData["path"] = this.path;
        if (this.verifyKey) documentData["verifyKey"] = this.verifyKey?.string;

        // console.log("encrypted", documentData);
        console.log("signed", await keystore.sign(this.owner, documentData));
        // TODO test if encrypted properties are there
        return await keystore.sign(this.owner, documentData);
    }
}