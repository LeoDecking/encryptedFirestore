import * as firebase from "firebase-admin";
import { HttpsError } from 'firebase-functions/lib/providers/https';
import { VerifyKey } from "./Key";
import { Crypto } from "./Crypto";

export async function verifyFirestore(firestore: firebase.firestore.Firestore, object: { path?: string, signature?: string, version?: number }, appVerifyKey: VerifyKey, structure: { [collection: string]: { parentIsOwner: boolean } }): Promise<void> {
    if (!object.path || !object.signature || object.version === undefined) throw new HttpsError("internal", "object missing properties");

    let owner: firebase.firestore.DocumentReference<firebase.firestore.DocumentData> | null = firestore.doc(object.path);

    while (owner && (!structure[owner.parent.id].parentIsOwner)) {
        owner = owner?.parent.parent ?? null;
        if (owner && !structure[owner.parent.id ?? ""]) throw new HttpsError("internal", "collection '" + owner?.parent.id + "' not in structure");
    }
    owner = owner?.parent.parent ?? null;

    let verifyKey = appVerifyKey;
    if (owner) {
        let ownerObject = (await owner.get()).data();
        if (!ownerObject) throw new HttpsError("internal", "owner does not exist: '" + owner.path + "'");;
        if (ownerObject.path != "/" + owner.path) throw new Error("wrong path in '" + owner.path);
        if (!ownerObject?.verifyKey) throw new HttpsError("internal", "owner has no verifyKey: '" + owner.path + "'");
        await verifyFirestore(firestore, ownerObject, appVerifyKey, structure);

        verifyKey = new VerifyKey(ownerObject.verifyKey);
    }
    let signature = object.signature;
    delete object.signature;
    if (Crypto.verify(object, signature, verifyKey)) return;
    else {
        throw new HttpsError("permission-denied", "invalid signature for " + object.path);
    }
}