import omemo

import base64
import json
import time

def b64enc(data):
    return base64.b64encode(data).decode("US-ASCII")

def b64enc_pub(data):
    return b64enc(omemo.wireformat.decodePublicKey(data))

class SyncInMemoryStorage(omemo.Storage):
    def __init__(self):
        self.__state = None
        self.__own_data_set  = False
        self.__own_bare_jid  = None
        self.__own_device_id = None
        self.__sessions = {}
        self.__devices = {}

    @classmethod
    def fromKeys(cls, ik_in, spk_in, otpks_in):
        ik = {
            "super": None,
            "enc": b64enc_pub(ik_in["enc"]),
            "dec": b64enc(ik_in["dec"])
        }

        spk = {
            "timestamp": time.time(),
            "key": {
                "super": None,
                "enc": b64enc_pub(spk_in["enc"]),
                "dec": b64enc(spk_in["dec"])
            },
            "signature": b64enc(spk_in["sig"])
        }

        spk_id  = spk_in["id"]
        spk_enc = spk["key"]["enc"]

        otpks = []

        otpk_id_counter = 0
        otpk_ids = {}

        for otpk_id, otpk in otpks_in.items():
            otpk_enc = b64enc_pub(otpk["enc"])
            otpk_dec = b64enc(otpk["dec"])

            otpks.append({
                "super": None,
                "enc": otpk_enc,
                "dec": otpk_dec
            })

            otpk_ids[otpk_enc] = otpk_id

            if otpk_id > otpk_id_counter:
                otpk_id_counter = otpk_id

        self = cls()
        self.storeState(None, {
            "super": {
                "super": {
                    "super": {
                        "ik": ik,
                        "spk": spk,
                        "otpks": otpks,
                        "hidden_otpks": [],
                        "changed": True
                    }
                },
                "spk_id": spk_id,
                "spk_enc": spk_enc,
                "otpk_id_counter": otpk_id_counter,
                "otpk_ids": otpk_ids
            },
            "bound_otpks": {},
            "pk_messages": {}
        })

        return self


    def loadOwnData(self, callback):
        return ({
            "own_bare_jid"  : self.__own_bare_jid,
            "own_device_id" : self.__own_device_id
        } if self.__own_data_set else None)

    def storeOwnData(self, callback, own_bare_jid, own_device_id):
        self.__own_data_set  = True
        self.__own_bare_jid  = own_bare_jid
        self.__own_device_id = own_device_id

    def loadState(self, callback):
        return None if self.__state == None else json.loads(self.__state)

    def storeState(self, callback, state):
        self.__state = json.dumps(state) # Woohoo! The object is json serializable!

    def loadSession(self, callback, bare_jid, device_id):
        return self.__sessions.get(bare_jid, {}).get(device_id, None)

    def storeSession(self, callback, bare_jid, device_id, session):
        self.__sessions[bare_jid] = self.__sessions.get(bare_jid, {})
        self.__sessions[bare_jid][device_id] = session

    def loadActiveDevices(self, callback, bare_jid):
        return self.__devices.get(bare_jid, {}).get("active", [])

    def loadInactiveDevices(self, callback, bare_jid):
        return self.__devices.get(bare_jid, {}).get("inactive", [])

    def storeActiveDevices(self, callback, bare_jid, devices):
        self.__devices[bare_jid] = self.__devices.get(bare_jid, {})
        self.__devices[bare_jid]["active"] = devices

    def storeInactiveDevices(self, callback, bare_jid, devices):
        self.__devices[bare_jid] = self.__devices.get(bare_jid, {})
        self.__devices[bare_jid]["inactive"] = devices

    def isTrusted(self, callback, bare_jid, device):
        return True

    @property
    def is_async(self):
        return False
