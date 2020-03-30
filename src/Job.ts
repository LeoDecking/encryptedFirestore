import { DatabaseObject } from "./DatabaseObject";
import { VerifyKey } from "./Key";
import { App } from "./App";

export class Job extends DatabaseObject<"job", Job, City> {
    _collection = "jobs";
    _parentIsOwner: true = true;
    _properties = ["name"];

    name?: string;
    supersecretValue: number = 23;

}

export class City extends DatabaseObject<"city", City, App> {
    _collection = "cities";
    _parentIsOwner: true = true;
    _properties = [];

    cityName: string = "";
}