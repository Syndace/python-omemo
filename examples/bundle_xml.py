import base64

import omemo

import xml.etree.ElementTree as ET

def b64enc(data):
    return base64.b64encode(data).decode("ASCII")

def b64dec(data):
    return base64.b64decode(data.encode("ASCII"))

OMEMO_NODE = "eu.siacs.conversations.axolotl"

def decodeOMEMOPublicBundle(bundle_stanza):
    spk_node = bundle_stanza.find("{" + OMEMO_NODE + "}signedPreKeyPublic")
    spk = {
        "key": omemo.wireformat.decodePublicKey(b64dec(spk_node.text)),
        "id": int(spk_node.get("signedPreKeyId"))
    }

    spk_signature_node = bundle_stanza.find("{" + OMEMO_NODE + "}signedPreKeySignature")
    spk_signature = b64dec(spk_signature_node.text)

    ik_node = bundle_stanza.find("{" + OMEMO_NODE + "}identityKey")
    ik = omemo.wireformat.decodePublicKey(b64dec(ik_node.text))

    otpks_node = bundle_stanza.find("{" + OMEMO_NODE + "}prekeys")

    otpks = []
    for otpk_node in list(otpks_node):
        otpks.append({
            "key": omemo.wireformat.decodePublicKey(b64dec(otpk_node.text)),
            "id": int(otpk_node.get("preKeyId"))
        })

    return omemo.ExtendedPublicBundle(ik, spk, spk_signature, otpks)

def encodeOMEMOPublicBundle(self, bundle):
    # Prepare the bundle element
    payload = ET.Element("{" + OMEMO_NODE + "}bundle")

    # First, add the SPK key and id
    spk_node = ET.SubElement(
        payload,
        "{" + OMEMO_NODE + "}signedPreKeyPublic",
        { "signedPreKeyId": str(bundle.spk["id"]) }
    )

    spk_node.text = b64enc(omemo.wireformat.encodePublicKey(bundle.spk["key"]))

    # Second, add the SPK signature
    spk_signature_node = ET.SubElement(
        payload,
        "{" + OMEMO_NODE + "}signedPreKeySignature"
    )

    spk_signature_node.text = b64enc(bundle.spk_signature)

    # Third, add the IK
    ik_node = ET.SubElement(payload, "{" + OMEMO_NODE + "}identityKey")
    ik_node.text = b64enc(omemo.wireformat.encodePublicKey(bundle.ik))

    # Fourth and last, add the otpks
    otpks_node = ET.SubElement(payload, "{" + OMEMO_NODE + "}prekeys")

    for otpk in bundle.otpks:
        otpk_node = ET.SubElement(
            otpks_node,
            "{" + OMEMO_NODE + "}preKeyPublic",
            { "preKeyId": str(otpk["id"]) }
        )

        otpk_node.text = b64enc(omemo.wireformat.encodePublicKey(otpk["key"]))

    return payload
