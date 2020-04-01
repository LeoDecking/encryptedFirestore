import firebase from "firebase";
import { VerifyKey } from "./Key";
import { Crypto } from "./Crypto";

// TODO version++
// -> aktuelle Version muss zum Vergleich geladen werden
export async function verifyFirestore(firestore: firebase.firestore.Firestore, object: { path?: string, signature?: string }, appVerifyKey: VerifyKey, structure: { [collection: string]: { parent: string, parentIsOwner: boolean } }): Promise<void> {
    if (!object.path || !object.signature) throw new Error("invaid object");

    let owner: firebase.firestore.DocumentReference<firebase.firestore.DocumentData> | null = firestore.doc(object.path);
    // TODO check if owner is null
    while (owner && (!structure[owner.parent.id].parentIsOwner)) {
        owner = owner?.parent.parent ?? null;
        if (owner && !structure[owner.parent.id ?? ""]) throw new Error("collection '" + owner?.parent.id + "' not in structure");
    }
    owner =  owner?.parent.parent ?? null;

    console.log("owner from " + object.path + " is " + owner?.path);
    let verifyKey = appVerifyKey;
    if (owner) {
        let ownerObject = (await owner.get()).data();
        if (!ownerObject) throw new Error("owner does not exist: '" + owner.path + "'");;
        if (ownerObject.path != "/" + owner.path) throw new Error("wrong path in '" + owner.path);
        if (!ownerObject?.verifyKey) throw new Error("owner has no verifyKey: '" + owner.path + "'");
        await verifyFirestore(firestore, ownerObject, appVerifyKey, structure);

        verifyKey = new VerifyKey(ownerObject.verifyKey);
    }
    let signature = object.signature;
    console.log("object", object);
    delete object.signature;
    console.log("object without signature", object);
    if (Crypto.verify(object, signature, verifyKey)) return;
    else {
        console.log(object, verifyKey);
        throw new Error("invalid signature for " + object.path);
    }
}