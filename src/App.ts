import { VerifyKey } from "./Key";
import { DatabaseObjectType } from "./DatabaseObjectType";

const AppSymbol = Symbol();
export abstract class App {
    private [AppSymbol]: boolean = true;

    readonly path: string = "";

    abstract verifyKey?: VerifyKey;

    static isApp(parent: DatabaseObjectType | App): parent is App {
        return (parent as App)[AppSymbol] == true;
    }
}

export class AppApp extends App {
    verifyKey = new VerifyKey("12345");
}