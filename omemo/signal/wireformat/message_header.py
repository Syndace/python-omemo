from __future__ import absolute_import

from hashlib import sha256
import hmac

from . import whispertextprotocol_pb2 as wtp
from .common import *
from ..exceptions import AuthenticationFailedException, IncompleteMessageException

import doubleratchet

MAC_SIZE = 8
MAC_HASH = sha256

def getMac(data, ad, authentication_key):
    return hmac.new(authentication_key, ad + data, MAC_HASH).digest()[:MAC_SIZE]

def fromWire(data):
    # Throw away the mac for now (use checkAuthentication later)
    data = data[:-MAC_SIZE]

    # Check and remove the version
    data = checkVersion(data)

    # Unpack the protobuf structure
    data = wtp.SignalMessage.FromString(data)

    if not (data.HasField("dh_ratchet_key") and data.HasField("n") and data.HasField("ciphertext")):
        raise IncompleteMessageException()

    return {
        "ciphertext": data.ciphertext,
        "header": doubleratchet.Header(decodePublicKey(data.dh_ratchet_key), data.n, data.pn)
    }

def checkAuthentication(data, ad, authentication_key):
    # Split the serialized data and the mac
    old_mac = data[-MAC_SIZE:]
    data = data[:-MAC_SIZE]
    
    # Recalculate the mac
    new_mac = getMac(data, ad, authentication_key)

    # Verify that both authentications are equal
    if not hmac.compare_digest(old_mac, new_mac):
        raise AuthenticationFailedException()

def toWire(ciphertext, header, ad, authentication_key):
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
    
    # Calculate the mac
    mac = getMac(data, ad, authentication_key)

    # Concatenate the serialized data and the mac
    return data + mac
