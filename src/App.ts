import { DatabaseObjectType } from ".";

const AppSymbol = Symbol();
export class App {
    // verifyKey in supertype
    [AppSymbol]: boolean = true;

    static isApp(parent: DatabaseObjectType | App): parent is App {
        return (parent as App)[AppSymbol] == true;
    }
}