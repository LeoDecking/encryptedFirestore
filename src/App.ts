import firebase from "firebase/app";
import { VerifyKey } from "./Key";
import { DatabaseObjectType, DatabaseChildObjectType } from "./DatabaseObjectType";
import { DatabaseObject } from ".";
import { KeyStore } from "./KeyStore";

const AppSymbol = Symbol();
export class App {
    private [AppSymbol]: boolean = true;
    readonly path: string = "";

    readonly firebase: firebase.app.App;
    readonly keyStore: KeyStore;
    readonly verifyKey: VerifyKey;


    constructor(firebaseApp: firebase.app.App, keyStore: KeyStore, verifyKey: VerifyKey) {
        this.firebase = firebaseApp;
        this.keyStore = keyStore;
        this.verifyKey = verifyKey;
    }

    static isApp(parent: DatabaseObjectType | App): parent is App {
        return (parent as App)[AppSymbol] == true;
    }

    childFromFirestore<C extends DatabaseChildObjectType<App>>(child: new (parent: App, id: string) => C, id: string): Promise<C> {
        return DatabaseObject.fromFirestore.call(child as any, this, id) as Promise<C>;
    }
}