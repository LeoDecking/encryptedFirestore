import { ObjectsKeyType } from "./Keys";

export abstract class Key<K extends ObjectsKeyType> {
    keyType?: K;
    abstract alorithm: string;
    abstract keyUsages: string[];

    readonly key?: CryptoKey;

    constructor(key?: CryptoKey) {
        this.key = key;
    }
}