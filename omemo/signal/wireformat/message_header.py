from __future__ import absolute_import

from . import whispertextprotocol_pb2 as wtp
from .common import *
from ..exceptions import DeserializationException

import doubleratchet

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

MAC_SIZE = 8

CRYPTOGRAPHY_BACKEND = default_backend()

def calculateMAC(data, IK_sender, IK_receiver, authentication_key):
    global CRYPTOGRAPHY_BACKEND

    # Build the authentication
    auth = hmac.HMAC(
        authentication_key,
        hashes.SHA256(),
        backend = CRYPTOGRAPHY_BACKEND
    )

    auth.update(IK_sender + IK_receiver + data)

    # Append the authentication to the ciphertext
    return auth.finalize()[:MAC_SIZE]

def fromWire(data):
    # Due to the nature the mac is calculated by signal, the authentication verification
    # has to be done later in an additional step.

    # Remove the mac
    mac  = data[-MAC_SIZE:]
    data = data[:-MAC_SIZE]

    # The data left is the data that was used to generate the mac
    auth_data = data

    # Check and remove the version
    data = checkVersion(data)

    # Unpack the protobuf structure
    data = wtp.SignalMessage.FromString(data)

    if not (
        data.HasField("dh_ratchet_key") and
        data.HasField("n") and
        data.HasField("ciphertext")
    ):
        raise DeserializationException("Message incomplete.")

    return {
        "ciphertext": data.ciphertext,
        "header": doubleratchet.Header(
            decodePublicKey(data.dh_ratchet_key),
            data.n,
            data.pn
        ),
        "mac": mac,
        "auth_data": auth_data
    }

def checkAuthentication(mac, data, ad, authentication_key):
    if not mac == calculateMAC(data, ad["IK_other"], ad["IK_own"], authentication_key):
        raise doubleratchet.exceptions.AuthenticationFailedException()

def toWire(ciphertext, header, ad, authentication_key):
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

    # The specification of the DoubleRatchet protocol recommends to calculate the mac of
    # ad+ciphertext and append the result to the ciphertext.

    # WhisperSystems instead calculate the mac of ad + the whole protobuf encoded message
    # and truncate the mac to 8 bytes.
    #
    # This way the whole message is authenticated and not only the ciphertext.
    # (idk about the truncation though).
    data += calculateMAC(data, ad["IK_own"], ad["IK_other"], authentication_key)
    
    return data
