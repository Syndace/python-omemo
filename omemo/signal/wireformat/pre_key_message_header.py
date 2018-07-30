from __future__ import absolute_import

from . import whispertextprotocol_pb2 as wtp
from .common import *
from ..exceptions import IncompleteMessageException

def fromWire(data):
    data = checkVersion(data)

    data = wtp.PreKeySignalMessage.FromString(data)

    if not (
        data.HasField("spk_id") and
        data.HasField("ek") and
        data.HasField("ik") and
        data.HasField("signal_message") and
        data.HasField("otpk_id")
    ):
        raise IncompleteMessageException()

    result = {
        "session_init_data": {
            "registration_id": data.registration_id,
            "otpk_id": data.otpk_id,
            "spk_id": data.spk_id,
            "ek": decodePublicKey(data.ek),
            "ik": decodePublicKey(data.ik)
        },
        "message": data.signal_message
    }

    return result

def toWire(session_init_data, message, registration_id = 0):
    wire = wtp.PreKeySignalMessage()
    wire.registration_id = registration_id # Does this parameter have any use in OMEMO?
    wire.otpk_id = session_init_data["otpk_id"]
    wire.spk_id = session_init_data["spk_id"]
    wire.ek = encodePublicKey(session_init_data["ek"])
    wire.ik = encodePublicKey(session_init_data["ik"])
    wire.signal_message = message
    data = wire.SerializeToString()
    
    return prependVersion(data)
