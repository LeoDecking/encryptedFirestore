import { ObjectsKeyType, PrivateEncryptionKey, PublicEncryptionKey } from "./Keys";
import * as base64 from "@stablelib/base64";

// WrapKeys können exportiert werden, deswegen wird jedes Mal ein neuer publicKey benutzt wird
export class WrapKey  {
    readonly keyType = ObjectsKeyType.Wrap;
    readonly alorithm = "AES-KW";
    readonly keyUsages = ["wrapKey", "unwrapKey"];

    
    readonly key?: CryptoKey;

    constructor(key?: CryptoKey) {
        this.key=key;
    }


    static async derive(privateEncryptionKey: PrivateEncryptionKey, publicEncryptionKey: PublicEncryptionKey): Promise<WrapKey> {
        let dummy = new this();
        return new WrapKey(await crypto.subtle.deriveKey({ name: "ECDH", public: publicEncryptionKey.key! }, privateEncryptionKey.key!, { name: dummy.alorithm, length: 256 }, true, dummy.keyUsages));
    }    

    async export(): Promise<string> {
        return base64.encode(new Uint8Array(await crypto.subtle.exportKey("raw", this.key!)));
    }
}
