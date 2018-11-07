from __future__ import absolute_import

import base64

import doubleratchet
import x3dh

from .cbcaead import CBCAEAD
from .rootchain import RootChain
from .symmetrickeyratchet import SymmetricKeyRatchet

class DoubleRatchet(doubleratchet.ratchets.DoubleRatchet):
    def __init__(
        self,
        ad,
        root_key   = None,
        own_key    = None,
        other_pub  = None,
        skr        = None, # ONLY USED FOR DESERIALIZATION
        root_chain = None  # ONLY USED FOR DESERIALIZATION
    ):
        if (root_key == None) == (root_chain == None):
            raise ValueError(
                "Exactly one of root_key, root_chain must be set! Not both, not neither."
            )

        self.__ad = ad

        if skr == None:
            self.__skr = SymmetricKeyRatchet()
        else:
            self.__skr = skr

        if root_chain == None:
            self.__root_chain = RootChain(root_key)
        else:
            self.__root_chain = root_chain

        super(DoubleRatchet, self).__init__(
            self.__skr, # symmetric_key_ratchet
            CBCAEAD(),  # aead
            self.__ad,  # ad
            5000,       # message_key_store_max
            self.__root_chain, # root_chain
            x3dh.implementations.KeyPairCurve25519, # encryption_key_pair_class
            own_key,
            other_pub
        )

    def serialize(self):
        ad = {
            "IK_own"   : base64.b64encode(self.__ad["IK_own"]).decode("US-ASCII"),
            "IK_other" : base64.b64encode(self.__ad["IK_other"]).decode("US-ASCII")
        }

        return {
            "super"      : super(DoubleRatchet, self).serialize(),
            "ad"         : ad,
            "skr"        : self.__skr.serialize(),
            "root_chain" : self.__root_chain.serialize()
        }

    @classmethod
    def fromSerialized(cls, serialized):
        ad = serialized["ad"]

        ad = {
            "IK_own"   : base64.b64decode(ad["IK_own"].encode("US-ASCII")),
            "IK_other" : base64.b64decode(ad["IK_other"].encode("US-ASCII"))
        }

        return super(DoubleRatchet, cls).fromSerialized(
            serialized["super"],
            ad,
            skr = SymmetricKeyRatchet.fromSerialized(serialized["skr"]),
            root_chain = RootChain.fromSerialized(serialized["root_chain"])
        )

    def _makeAD(self, header, ad):
        return ad

    def encryptMessage(self, *args, **kwargs):
        result = super(DoubleRatchet, self).encryptMessage(*args, **kwargs)
        result["additional"] = result["ciphertext"]["additional"]
        result["ciphertext"] = result["ciphertext"]["ciphertext"]
        return result
