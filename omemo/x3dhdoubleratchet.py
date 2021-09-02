from x3dh.exceptions import KeyExchangeException

from .exceptions import UnknownKeyException
from .extendeddoubleratchet import make as make_ExtendedDoubleRatchet
from .state import make as make_State
from .version import __version__

import base64
import copy
import time

def make(backend):
    class X3DHDoubleRatchet(make_State(backend)):
        def __init__(self):
            super().__init__()

            self.__bound_otpks = {}
            self.__pre_key_messages = {}

            self.__ExtendedDoubleRatchet = make_ExtendedDoubleRatchet(backend)

        def serialize(self):
            bound_otpks = {}

            for bare_jid in self.__bound_otpks:
                bound_otpks[bare_jid] = {}

                for device in self.__bound_otpks[bare_jid]:
                    otpk = self.__bound_otpks[bare_jid][device]

                    bound_otpks[bare_jid][device] = {
                        "otpk" : base64.b64encode(otpk["otpk"]).decode("US-ASCII"),
                        "id"   : otpk["id"]
                    }

            pk_messages = {}

            for otpk, value in self.__pre_key_messages.items():
                otpk = base64.b64encode(otpk).decode("US-ASCII")
                pk_messages[otpk] = copy.deepcopy(value)

            return {
                "super"       : super().serialize(),
                "bound_otpks" : bound_otpks,
                "pk_messages" : pk_messages,
                "version"     : __version__
            }

        @classmethod
        def fromSerialized(cls, serialized, *args, **kwargs):
            version = serialized["version"]

            # Add code to upgrade the state here

            self = super().fromSerialized(serialized["super"], *args, **kwargs)

            bound_otpks = {}

            for bare_jid in serialized["bound_otpks"]:
                bound_otpks[bare_jid] = {}

                for device in serialized["bound_otpks"][bare_jid]:
                    otpk = serialized["bound_otpks"][bare_jid][device]

                    bound_otpks[bare_jid][device] = {
                        "otpk" : base64.b64decode(otpk["otpk"].encode("US-ASCII")),
                        "id"   : otpk["id"]
                    }

            pk_messages = {}

            for otpk, value in serialized["pk_messages"].items():
                otpk = base64.b64decode(otpk.encode("US-ASCII"))
                pk_messages[otpk] = copy.deepcopy(value)

            self.__bound_otpks = bound_otpks
            self.__pre_key_messages = pk_messages

            return self

        def getSharedSecretActive(
            self,
            other_public_bundle,
            *args,
            **kwargs
        ):
            session_init_data = super().getSharedSecretActive(
                other_public_bundle,
                *args,
                **kwargs
            )

            # When actively initializing a session
            # - The shared secret becomes the root key
            # - The public SPK used for X3DH becomes the other's enc for the dh ratchet
            # - The associated data calculated by X3DH becomes the ad used by the
            #   double ratchet encryption/decryption
            session_init_data["dr"] = self.__ExtendedDoubleRatchet(
                other_public_bundle.ik,
                session_init_data["ad"],
                session_init_data["sk"],
                own_key   = None,
                other_pub = other_public_bundle.spk["key"]
            )

            # The shared secret and ad values are now irrelevant
            del session_init_data["sk"]
            del session_init_data["ad"]

            self.__compressSessionInitData(session_init_data, other_public_bundle)

            return session_init_data

        def getSharedSecretPassive(
            self,
            session_init_data,
            bare_jid,
            device,
            otpk_policy,
            additional_information = None
        ):
            self.__decompressSessionInitData(session_init_data, bare_jid, device)

            self.__preKeyMessageReceived(
                session_init_data["otpk"],
                additional_information
            )

            session_data = super().getSharedSecretPassive(
                session_init_data,
                keep_otpk = True
            )

            # Decide whether to keep this OTPK
            self.__decideBoundOTPK(bare_jid, device, otpk_policy)

            # When passively initializing the session
            # - The shared secret becomes the root key
            # - The public SPK used by the active part for X3DH becomes the own dh ratchet
            #   key
            # - The associated data calculated by X3DH becomes the ad used by the double
            #   ratchet encryption/decryption
            return self.__ExtendedDoubleRatchet(
                session_init_data["ik"],
                session_data["ad"],
                session_data["sk"],
                own_key = self.spk
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

                # If the OTPK ids don't match, consider the old bound OTPK as deleteable
                # and bind the new OTPK
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

        def __preKeyMessageReceived(self, otpk, additional_information = None):
            # Add an entry to the received PreKeyMessage data
            self.__pre_key_messages[otpk] = self.__pre_key_messages.get(otpk, [])
            self.__pre_key_messages[otpk].append({
                "timestamp": time.time(),
                "answers":   [],
                "additional_information": additional_information,
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
                raise KeyExchangeException(
                    "The OTPK used for this session initialization has been deleted, " +
                    "the session can not be initiated."
                )

            self.__bound_otpks[bare_jid] = self.__bound_otpks.get(bare_jid, {})
            self.__bound_otpks[bare_jid][device] = {
                "otpk": otpk,
                "id": otpk_id
            }

            self.__pre_key_messages[otpk] = []

            self.hideFromPublicBundle(otpk)

            return otpk

    return X3DHDoubleRatchet
