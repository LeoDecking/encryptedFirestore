import { DatabaseObject, DatabaseObjectType, VerifyKey } from "./DatabaseObject";

export class Job extends DatabaseObject<"job", Job, City> {
    name?: string;
    supersecretValue: number = 23;

    properties = [""];
}

export class City extends DatabaseObject<"city", City, App> {
    cityName: string = "";
}

export class CityAdmin

export class App extends DatabaseObject<"app", App, never> {
    appName: string = "";
    verifyKey?: VerifyKey<App> = new VerifyKey(App, "123");

    static app: App = new App();
}

class Test {
    test?: {
        a: string,
        b: number
    };
}