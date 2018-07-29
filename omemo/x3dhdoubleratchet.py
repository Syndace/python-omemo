from x3dh.exceptions import SessionInitiationException

from . import default
from .exceptions import UnknownKeyException
from .state import State

import time

class X3DHDoubleRatchet(State):
    def __init__(self):
        self.__bound_otpks = {}
        self.__pre_key_messages = {}

        super(X3DHDoubleRatchet, self).__init__()

    def initSessionActive(self, other_public_bundle, *args, **kwargs):
        session_init_data = super(X3DHDoubleRatchet, self).initSessionActive(
            other_public_bundle,
            *args,
            **kwargs
        )

        # When actively initializing a session
        # - The shared secret becomes the root key
        # - The public SPK used for X3DH becomes the other's enc for the dh ratchet
        # - The associated data calculated by X3DH becomes the ad used by the
        #   double ratchet encryption/decryption
        session_init_data["dr"] = default.doubleratchet.DoubleRatchet(
            session_init_data["sk"],
            other_enc = other_public_bundle.spk["key"],
            ad = session_init_data["ad"]
        )

        # The shared secret and ad values are now irrelevant
        del session_init_data["sk"]
        del session_init_data["ad"]

        self.__compressSessionInitData(session_init_data, other_public_bundle)

        return session_init_data

    def initSessionPassive(
        self,
        session_init_data,
        bare_jid,
        device,
        otpk_policy,
        from_storage
    ):
        self.__decompressSessionInitData(session_init_data, bare_jid, device)

        self.__preKeyMessageReceived(session_init_data["otpk"], from_storage)

        session_data = super(X3DHDoubleRatchet, self).initSessionPassive(
            session_init_data,
            keep_otpk = True
        )

        # Decide whether to keep this OTPK
        self.__decideBoundOTPK(bare_jid, device, otpk_policy)

        # When passively initializing the session
        # - The shared secret becomes the root key
        # - The public SPK used by the active part for X3DH becomes the own dh ratchet key
        # - The associated data calculated by X3DH becomes the ad used by the double
        #   ratchet encryption/decryption
        return default.doubleratchet.DoubleRatchet(
            session_data["sk"],
            own_key = self.spk,
            ad = session_data["ad"]
        )

    def __compressSessionInitData(self, session_init_data, bundle):
        """
        Compress the session initialization data by replacing keys with their ids.
        """

        to_other = session_init_data["to_other"]

        to_other["otpk_id"] = bundle.findOTPKId(to_other["otpk"])
        to_other["spk_id"]  = bundle.findSPKId(to_other["spk"])

        del to_other["otpk"]
        del to_other["spk"]

    def __decompressSessionInitData(self, session_init_data, bare_jid, device):
        """
        Decompress the session initialization data by replacing key ids with the keys.
        """

        session_init_data["spk"] = self.getSPK(session_init_data["spk_id"])
        del session_init_data["spk_id"]

        otpk_id = self.getBoundOTPKId(bare_jid, device)

        # Check, whether the bare_jid+device combination is already bound to some OTPK
        if otpk_id:
            # If it is, check whether the OTPK ids match
            if otpk_id == session_init_data["otpk_id"]:
                session_init_data["otpk"] = self.getBoundOTPK(bare_jid, device)

            # If the OTPK ids don't match, consider the old bound OTPK as deleteable and
            # bind the new OTPK
            else:
                self.deleteBoundOTPK(bare_jid, device)

                session_init_data["otpk"] = self.__bindOTPK(
                    bare_jid,
                    device,
                    session_init_data["otpk_id"]
                )
        else:
            # If it is not, get the OTPK from the id and bind the bare_jid+device
            # combination to it
            session_init_data["otpk"] = self.__bindOTPK(
                bare_jid,
                device,
                session_init_data["otpk_id"]
            )

        del session_init_data["otpk_id"]

    def __preKeyMessageReceived(self, otpk, from_storage):
        # Add an entry to the received PreKeyMessage data
        self.__pre_key_messages[otpk] = self.__pre_key_messages.get(otpk, [])
        self.__pre_key_messages[otpk].append({
            "timestamp":    time.time(),
            "from_storage": from_storage,
            "answers":      []
        })

    def getBoundOTPK(self, bare_jid, device):
        try:
            return self.__bound_otpks[bare_jid][device]["otpk"]
        except KeyError:
            return None

    def getBoundOTPKId(self, bare_jid, device):
        try:
            return self.__bound_otpks[bare_jid][device]["id"]
        except KeyError:
            return None

    def hasBoundOTPK(self, bare_jid, device):
        return True if self.getBoundOTPK(bare_jid, device) else False

    def respondedTo(self, bare_jid, device):
        bound_otpk_id = self.getBoundOTPK(bare_jid, device)

        self.__pre_key_messages[bound_otpk_id][-1]["answers"].append(time.time())

    def __decideBoundOTPK(self, bare_jid, device, otpk_policy):
        bound_otpk_id = self.getBoundOTPK(bare_jid, device)

        if not otpk_policy.decideOTPK(self.__pre_key_messages[bound_otpk_id]):
            self.deleteBoundOTPK(bare_jid, device)

    def deleteBoundOTPK(self, bare_jid, device):
        otpk = self.getBoundOTPK(bare_jid, device)

        if otpk:
            del self.__pre_key_messages[otpk]
            del self.__bound_otpks[bare_jid][device]
            self.deleteOTPK(otpk)

    def __bindOTPK(self, bare_jid, device, otpk_id):
        try:
            otpk = self.getOTPK(otpk_id)
        except UnknownKeyException:
            raise SessionInitiationException(
                "The OTPK used for this session initialization has been deleted, " +
                "the session can not be initiated"
            )

        self.__bound_otpks[bare_jid] = self.__bound_otpks.get(bare_jid, {})
        self.__bound_otpks[bare_jid][device] = {
            "otpk": otpk,
            "id": otpk_id
        }

        self.__pre_key_messages[otpk] = []

        self.hideFromPublicBundle(otpk)

        return otpk
