from __future__ import absolute_import

import doubleratchet

class RootChain(doubleratchet.kdfchains.KDFChain):
    def __init__(self, key = None):
        super(RootChain, self).__init__(
            doubleratchet.recommended.RootKeyKDF(
                "SHA-256",
                "WhisperRatchet".encode("US-ASCII")
            ),
            key
        )

    def serialize(self):
        return {
            "super": super(RootChain, self).serialize()
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        return super(RootChain, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )
