export { PrivateKey, PrivateEncryptionKey, SignKey } from "./PrivateKey";
export { PublicKey, PublicEncryptionKey, VerifyKey } from "./PublicKey";
export { SecretKey } from "./SecretKey";
export { WrapKey } from "./WrapKey";
import * as base64 from "@stablelib/base64";

export enum ObjectsKeyType {
    Secret = "secretKey",

    Sign = "signKey",
    Verify = "verifyKey",

    PrivateEncryption = "privateEncryptionKey",
    PublicEncryption = "publicEncryptionKey",

    Wrap = "wrapKey"

};