import { DatabaseObject, DatabaseObjectType, VerifyKey } from "./DatabaseObject";

export class Job extends DatabaseObject<"Job", Job, City> {
    name?: string;
    supersecretValue: number = 23;
}

export class City extends DatabaseObject<"city", City, App> {
    cityName: string = "";
}

export class App extends DatabaseObject<"app", App, never> {
    appName: string = "";
    verifyKey?: VerifyKey<App> = new VerifyKey(App, "123");
    
    static app: App = new App();
}