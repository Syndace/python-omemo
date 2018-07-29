from . import whispertextprotocol_pb2 as wtp
from .common import *
from ..exceptions import IncompleteMessageException

import doubleratchet

def fromWire(data):
    # Check and remove the version
    data = checkVersion(data)

    # Unpack the protobuf structure
    data = wtp.SignalMessage.FromString(data)

    if not (
        data.HasField("dh_ratchet_key") and
        data.HasField("n") and
        data.HasField("ciphertext")
    ):
        raise IncompleteMessageException()

    return {
        "ciphertext" : data.ciphertext,
        "header" : doubleratchet.Header(
            decodePublicKey(data.dh_ratchet_key),
            data.n,
            data.pn
        )
    }

def toWire(ciphertext, header):
    # Build the protobuf structure
    wire = wtp.SignalMessage()
    wire.ciphertext = ciphertext
    wire.n = header.n

    if header.pn:
        wire.pn = header.pn
    else:
        wire.pn = 0

    wire.dh_ratchet_key = encodePublicKey(header.dh_enc)
    data = wire.SerializeToString()

    # Prepend the message version
    data = prependVersion(data)
    
    return data
