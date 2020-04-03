import { DatabaseObject } from "./DatabaseObject";
import { App } from "./App";
import { VerifyKey } from ".";

export class Job extends DatabaseObject<"job", Job, City> {
    collection = "jobs";
    encryptedProperties: string[] = ["supersecretValue"];
    parentIsOwner: true = true;

    name?: string;
    supersecretValue: number = 23;
}

export class City extends DatabaseObject<"city", City, App> {
    collection = "cities";
    encryptedProperties: string[] = [];
    parentIsOwner: true = true;

    cityName: string = "";
}
export class AppApp extends App {
    verifyKey = new VerifyKey("12345");
}