from __future__ import absolute_import

from x3dh.exceptions import SessionInitiationException

from . import doubleratchet
from . import signal
from . import x3dh

import time

class X3DHDoubleRatchet(x3dh.State):
    def __init__(self):
        self.__bound_otpks = {}
        self.__pre_key_messages = {}

        super(X3DHDoubleRatchet, self).__init__()

    def initSessionActive(self, other_public_bundle, *args, **kwargs):
        session_init_data = super(X3DHDoubleRatchet, self).initSessionActive(other_public_bundle, *args, **kwargs)

        # When actively initializing a session
        # - The shared secret becomes the root key
        # - The public SPK used for X3DH becomes the other's enc for the dh ratchet
        # - The associated data calculated by X3DH becomes the ad used by the double ratchet encryption/decryption
        session_init_data["dr"] = doubleratchet.DoubleRatchet(session_init_data["sk"], other_enc = other_public_bundle.spk["key"], ad = session_init_data["ad"])

        # The shared secret and ad values are now irrelevant
        del session_init_data["sk"]
        del session_init_data["ad"]

        self.__compressSessionInitData(session_init_data, other_public_bundle)

        return session_init_data

    def initSessionPassive(self, session_init_data, jid, device, otpk_policy, from_storage):
        self.__decompressSessionInitData(session_init_data, jid, device)

        self.__preKeyMessageReceived(session_init_data["otpk"], from_storage)

        session_data = super(X3DHDoubleRatchet, self).initSessionPassive(session_init_data, keep_otpk = True)

        # Decide whether to keep this OTPK
        self.__decideBoundOTPK(jid, device, otpk_policy)

        # When passively initializing the session
        # - The shared secret becomes the root key
        # - The public SPK used by the active part for X3DH becomes the own dh ratchet key
        # - The associated data calculated by X3DH becomes the ad used by the double ratchet encryption/decryption
        return doubleratchet.DoubleRatchet(session_data["sk"], own_key = self.spk, ad = session_data["ad"])

    def __compressSessionInitData(self, session_init_data, bundle):
        """
        Compress the session initialization data by replacing keys with their ids.
        """

        session_init_data["to_other"]["otpk_id"] = bundle.findOTPKId(session_init_data["to_other"]["otpk"])
        session_init_data["to_other"]["spk_id"]  = bundle.findSPKId(session_init_data["to_other"]["spk"])

        del session_init_data["to_other"]["otpk"]
        del session_init_data["to_other"]["spk"]

    def __decompressSessionInitData(self, session_init_data, jid, device):
        """
        Decompress the session initialization data by replacing key ids with the keys.
        """

        session_init_data["spk"] = self.getSPK(session_init_data["spk_id"])
        del session_init_data["spk_id"]

        otpk_id = self.getBoundOTPKId(jid, device)

        # Check, whether the jid+device combination is already bound to some OTPK
        if otpk_id:
            # If it is, check whether the OTPK ids match
            if otpk_id == session_init_data["otpk_id"]:
                session_init_data["otpk"] = self.getBoundOTPK(jid, device)

            # If they don't, consider the old bound OTPK as deleteable and bind the new OTPK
            else:
                self.deleteBoundOTPK(jid, device)
                session_init_data["otpk"] = self.__bindOTPK(jid, device, session_init_data["otpk_id"])
        else:
            # If it is not, get the OTPK from the id and bind the jid+device combination to it
            session_init_data["otpk"] = self.__bindOTPK(jid, device, session_init_data["otpk_id"])

        del session_init_data["otpk_id"]

    def __preKeyMessageReceived(self, otpk, from_storage):
        # Add an entry to the received PreKeyMessage data
        self.__pre_key_messages[otpk] = self.__pre_key_messages.get(otpk, [])
        self.__pre_key_messages[otpk].append({
            "timestamp":    time.time(),
            "from_storage": from_storage,
            "answers":      []
        })

    def getBoundOTPK(self, jid, device):
        try:
            return self.__bound_otpks[jid][device]["otpk"]
        except KeyError:
            return None

    def getBoundOTPKId(self, jid, device):
        try:
            return self.__bound_otpks[jid][device]["id"]
        except KeyError:
            return None

    def hasBoundOTPK(self, jid, device):
        return True if self.getBoundOTPK(jid, device) else False

    def respondedTo(self, jid, device):
        self.__pre_key_messages[self.getBoundOTPK(jid, device)][-1]["answers"].append(time.time())

    def __decideBoundOTPK(self, jid, device, otpk_policy):
        if not otpk_policy.decideOTPK(self.__pre_key_messages[self.getBoundOTPK(jid, device)]):
            self.deleteBoundOTPK(jid, device)

    def deleteBoundOTPK(self, jid, device):
        otpk = self.getBoundOTPK(jid, device)

        if otpk:
            del self.__pre_key_messages[otpk]
            del self.__bound_otpks[jid][device]
            self.deleteOTPK(otpk)

    def __bindOTPK(self, jid, device, otpk_id):
        try:
            otpk = self.getOTPK(otpk_id)
        except signal.exceptions.UnknownKeyException:
            raise SessionInitiationException("The OTPK used for this session initialization has been deleted, the session can not be initiated")

        self.__bound_otpks[jid] = self.__bound_otpks.get(jid, {})
        self.__bound_otpks[jid][device] = {
            "otpk": otpk,
            "id": otpk_id
        }

        self.__pre_key_messages[otpk] = []

        self.hideFromPublicBundle(otpk)

        return otpk
