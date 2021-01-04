import { DatabaseObject } from "./DatabaseObject";
import { App } from "./App";

export type DatabaseObjectType = DatabaseObject<string, DatabaseObjectType, DatabaseObjectType | App, DatabaseObjectType | App>;
export type DatabaseAncestorObjectType<T extends DatabaseObjectType> = App | DatabaseObject<string, DatabaseObjectType, DatabaseObjectType | App, T["parent"] | (T["parent"] extends App ? App : DatabaseAncestorObjectType<Exclude<T["parent"], App>>)>;
export type DatabaseChildObjectType<T extends DatabaseObjectType | App> = DatabaseObject<string, DatabaseObjectType, T, DatabaseObjectType | App>;
