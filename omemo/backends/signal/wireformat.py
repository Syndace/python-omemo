from __future__ import absolute_import

import doubleratchet

from omemo.exceptions import WireFormatException

from .. import wireformat

from . import whispertextprotocol_pb2 as wtp

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

CURRENT_MAJOR_VERSION = 3
CURRENT_MINOR_VERSION = 3
KEY_TYPE_25519 = 5
MAC_SIZE = 8

CRYPTOGRAPHY_BACKEND = default_backend()

def calculateMAC(data, key, IK_sender, IK_receiver):
    global CRYPTOGRAPHY_BACKEND

    # Build the authentication
    auth = hmac.HMAC(
        key,
        hashes.SHA256(),
        backend = CRYPTOGRAPHY_BACKEND
    )

    auth.update(IK_sender + IK_receiver + data)

    # Append the authentication to the ciphertext
    return auth.finalize()[:MAC_SIZE]

def checkVersion(data):
    try:
        version = ord(data[0])
    except TypeError:
        version = data[0]

    major_version = (version >> 4) & 0x0F
    minor_version = (version >> 0) & 0x0F

    if major_version < CURRENT_MAJOR_VERSION or minor_version < CURRENT_MINOR_VERSION:
        raise WireFormatException("Legacy version detected.")

    if major_version > CURRENT_MAJOR_VERSION or minor_version > CURRENT_MINOR_VERSION:
        raise WireFormatException("Newer/unknown version detected.")

    return data[1:]

def prependVersion(data):
    return bytes(bytearray([ CURRENT_MAJOR_VERSION << 4 | CURRENT_MINOR_VERSION ])) + data

def decodePublicKey(key):
    if len(key) != 33:
        raise WireFormatException("The key field must contain 33 bytes of data.")

    try:
        key_type = ord(key[0])
    except TypeError:
        key_type = key[0]

    if key_type != KEY_TYPE_25519:
        raise WireFormatException("Unknown key type.")

    return key[1:]

def encodePublicKey(key):
    return bytes(bytearray([ KEY_TYPE_25519 ])) + key

class WireFormat(wireformat.WireFormat):
    @staticmethod
    def messageFromWire(obj):
        # Due to the nature the mac is calculated by signal, the authentication
        # verification has to be done later in an additional step.

        # Remove the mac
        mac = obj[-MAC_SIZE:]
        obj = obj[:-MAC_SIZE]

        # Check and remove the version
        obj = checkVersion(obj)

        # Unpack the protobuf structure
        obj = wtp.SignalMessage.FromString(obj)

        if not (
            obj.HasField("dh_ratchet_key") and
            obj.HasField("n") and
            obj.HasField("ciphertext")
        ):
            raise WireFormatException("Message incomplete.")

        return {
            "ciphertext": obj.ciphertext,
            "header": doubleratchet.Header(
                decodePublicKey(obj.dh_ratchet_key),
                obj.n,
                obj.pn
            ),
            "additional": mac
        }

    @staticmethod
    def finalizeMessageFromWire(obj, additional):
        dr_additional = additional["DoubleRatchet"]

        ad  = dr_additional["ad"]
        key = dr_additional["key"]
        mac = calculateMAC(obj[:-MAC_SIZE], key, ad["IK_other"], ad["IK_own"])

        if not additional["WireFormat"] == mac:
            raise WireFormatException("Message authentication failed.")

    @staticmethod
    def messageToWire(ciphertext, header, additional):
        # Build the protobuf structure
        wire = wtp.SignalMessage()
        wire.ciphertext = ciphertext
        wire.n = header.n

        if header.pn:
            wire.pn = header.pn
        else:
            wire.pn = 0

        wire.dh_ratchet_key = encodePublicKey(header.dh_pub)
        data = wire.SerializeToString()

        # Prepend the message version
        data = prependVersion(data)

        # The specification of the DoubleRatchet protocol recommends to calculate the mac
        # of ad+ciphertext and append the result to the ciphertext.

        # WhisperSystems instead calculate the mac of ad + the whole protobuf encoded
        # message and truncate the mac to 8 bytes.
        #
        # This way the whole message is authenticated and not only the ciphertext.
        # (idk about the truncation though).
        dr_additional = additional["DoubleRatchet"]

        ad  = dr_additional["ad"]
        key = dr_additional["key"]

        data += calculateMAC(data, key, ad["IK_own"], ad["IK_other"])
        
        return data

    @staticmethod
    def preKeyMessageFromWire(obj):
        obj = checkVersion(obj)

        obj = wtp.PreKeySignalMessage.FromString(obj)

        if not (
            obj.HasField("spk_id") and
            obj.HasField("ek") and
            obj.HasField("ik") and
            obj.HasField("signal_message") and
            obj.HasField("otpk_id")
        ):
            raise WireFormatException("Pre key message incomplete.")

        return {
            "session_init_data": {
                "registration_id": obj.registration_id,
                "otpk_id": obj.otpk_id,
                "spk_id": obj.spk_id,
                "ek": decodePublicKey(obj.ek),
                "ik": decodePublicKey(obj.ik)
            },
            "message": obj.signal_message,
            "additional": None
        }

    @staticmethod
    def finalizePreKeyMessageFromWire(obj, additional):
        # TODO: Verify the mac of the contained message
        pass

    @staticmethod
    def preKeyMessageToWire(session_init_data, message, additional):
        wire = wtp.PreKeySignalMessage()
        wire.registration_id = 0 # This parameter has no use in OMEMO.
        wire.otpk_id = session_init_data["otpk_id"]
        wire.spk_id  = session_init_data["spk_id"]
        wire.ek = encodePublicKey(session_init_data["ek"])
        wire.ik = encodePublicKey(session_init_data["ik"])
        wire.signal_message = message
        data = wire.SerializeToString()
        
        return prependVersion(data)
