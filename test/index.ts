import { DatabaseObject, VerifyKey } from "encrypted-firestore";

class Job extends DatabaseObject<"job", Job, City> {
    collection = "jobs";

    name?: string;
    supersecretValue: number = 23;

    properties = [""];
}

class City extends DatabaseObject<"city", City, App> {
    collection = "cities";

    cityName: string = "";
}

class App extends DatabaseObject<"app", App, never> {
    appName: string = "";
    verifyKey?: VerifyKey<App> = new VerifyKey(App, "123");

    static app: App = new App();
}


let city = new City(App.app);
let job = new Job(city);

console.log(job.getPath());
console.log(job);