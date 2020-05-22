import firebase from "firebase/app";
import { VerifyKey } from "./Key/Keys";
import { DatabaseObjectType, DatabaseChildObjectType } from "./DatabaseObjectType";
// import { KeyStore } from "./KeyStore";
import { DatabaseObject } from "./DatabaseObject";

const AppSymbol = Symbol();
export class App {
    private [AppSymbol]: boolean = true;
    readonly path: string = "";

    readonly firebase: firebase.app.App;
    readonly keyStore: any;
    readonly verifyKey: VerifyKey;


    constructor(firebaseApp: firebase.app.App, keyStore: any, verifyKey: VerifyKey, deviceVerifyKey: VerifyKey) {
        this.firebase = firebaseApp;
        this.keyStore = keyStore;
        this.verifyKey = verifyKey;
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

    childrenFromFirestore<C extends DatabaseChildObjectType<App>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[]): Promise<C[]>;
    childrenFromFirestore<C extends DatabaseChildObjectType<App>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[], onSnapshot: (objects: C[]) => void): () => void;
    childrenFromFirestore<C extends DatabaseChildObjectType<App>>(child: new (parent: this, id?: string) => C, queries: { fieldPath: string | firebase.firestore.FieldPath, opStr: firebase.firestore.WhereFilterOp, value: any }[] = [], onSnapshot?: (objects: C[]) => void): Promise<C[]> | (() => void) {
        return DatabaseObject.collectionFromFirestore.call(child as any, this, queries, onSnapshot);
    }
}