import firebase from "firebase/app";
import { DatabaseObjectType, DatabaseChildObjectType } from "./DatabaseObjectType";
// import { KeyStore } from "./KeyStore";
import { DatabaseObject } from "./DatabaseObject";
import { KeyStore } from "./KeyStore";
import { PublicEncryptionKey, VerifyKey } from "objects-crypto";

const AppSymbol = Symbol();
export class App {
    private [AppSymbol]: boolean = true;
    readonly path: string = "";

    readonly firebase: firebase.app.App;
    readonly keyStore: KeyStore;

    readonly verifyKey: VerifyKey;
    readonly publicKey: PublicEncryptionKey;

    readonly databaseOptions: {
        type: "app"
        hasPassword: true
        passwordCanSign: true

    } = { type: "app", hasPassword: true, passwordCanSign: true };


    // TODO deviceVerify/publicKey
    // TODO keyStore any??
    constructor(firebaseApp: firebase.app.App, keyStore: KeyStore, verifyKey: VerifyKey, publicKey: PublicEncryptionKey) {
        this.firebase = firebaseApp;
        this.keyStore = keyStore;
        this.verifyKey = verifyKey;
        this.publicKey = publicKey;
    }

    static isApp(parent: DatabaseObjectType | App): parent is App {
        return (parent as App)[AppSymbol] == true;
    }

    newChild<C extends DatabaseChildObjectType<App>>(child: new (parent: App, id?: string) => C, id?: string): C {
        return new child(this, id);
    }

    childFromFirestore<C extends DatabaseChildObjectType<App>>(child: new (parent: App, id?: string) => C, id: string): Promise<C>;
    childFromFirestore<C extends DatabaseChildObjectType<App>>(child: new (parent: App, id?: string) => C, id: string, onSnapshot: (object: C) => void): () => void;
    childFromFirestore<C extends DatabaseChildObjectType<App>>(child: new (parent: App, id?: string) => C, id: string, onSnapshot?: (object: C) => void): Promise<C> | (() => void) {
        return DatabaseObject.fromFirestore.call(child as any, this, id, onSnapshot);
    }

    childrenFromFirestore<C extends DatabaseChildObjectType<App>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[] | string[]): Promise<C[]>;
    childrenFromFirestore<C extends DatabaseChildObjectType<App>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[] | string[], onSnapshot: (objects: C[]) => void): () => void;
    childrenFromFirestore<C extends DatabaseChildObjectType<App>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[] | string[] = [], onSnapshot?: (objects: C[]) => void): Promise<C[]> | (() => void) {
        return DatabaseObject.collectionFromFirestore.call(child as any, this, queries, onSnapshot);
    }
}