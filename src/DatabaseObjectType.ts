import { DatabaseObject } from "./DatabaseObject";
import { App } from "./App";

export type DatabaseObjectType = DatabaseObject<string, DatabaseObjectType, DatabaseObjectType | App, boolean>;
export type DatabaseChildObjectType<T extends DatabaseObjectType | App> = DatabaseObject<string, DatabaseObjectType, T , boolean>;

export type GetOwner<T extends DatabaseObjectType> = T["databaseOptions"]["parentIsOwner"] extends true ? T["parent"] : GetOwner2<Exclude<T["parent"], App>>;
type GetOwner2<T extends DatabaseObjectType> = T["databaseOptions"]["parentIsOwner"] extends true ? T["parent"] : GetOwner3<Exclude<T["parent"], App>>;
type GetOwner3<T extends DatabaseObjectType> = T["databaseOptions"]["parentIsOwner"] extends true ? T["parent"] : GetOwner4<Exclude<T["parent"], App>>;
type GetOwner4<T extends DatabaseObjectType> = T["databaseOptions"]["parentIsOwner"] extends true ? T["parent"] : GetOwner5<Exclude<T["parent"], App>>;
type GetOwner5<T extends DatabaseObjectType> = T["databaseOptions"]["parentIsOwner"] extends true ? T["parent"] : GetOwner6<Exclude<T["parent"], App>>;
type GetOwner6<T extends DatabaseObjectType> = T["databaseOptions"]["parentIsOwner"] extends true ? T["parent"] : GetOwner7<Exclude<T["parent"], App>>;
type GetOwner7<T extends DatabaseObjectType> = T["databaseOptions"]["parentIsOwner"] extends true ? T["parent"] : GetOwner8<Exclude<T["parent"], App>>;
type GetOwner8<T extends DatabaseObjectType> = T["databaseOptions"]["parentIsOwner"] extends true ? T["parent"] : GetOwner9<Exclude<T["parent"], App>>;
type GetOwner9<T extends DatabaseObjectType> = T["databaseOptions"]["parentIsOwner"] extends true ? T["parent"] : GetOwner10<Exclude<T["parent"], App>>;
type GetOwner10<T extends DatabaseObjectType> = T["databaseOptions"]["parentIsOwner"] extends true ? T["parent"] : DatabaseObjectType | App;