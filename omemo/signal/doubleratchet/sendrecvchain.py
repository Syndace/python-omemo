from __future__ import absolute_import

import doubleratchet

class SendRecvChain(doubleratchet.chains.ConstKDFChain):
    def __init__(self, key = None):
        # NOTE: The second parameter (= None) usually supplies the constant data that is
        # applied to the KDF chain on each step.
        # In this case, the ChainKeyKDF is constant by itself and ignores the data it
        # gets as input.
        # That means, the second parameter gets ignored and can be set to anything.
        super(SendRecvChain, self).__init__(
            doubleratchet.recommended.ChainKeyKDF("SHA-256", b"\x02", b"\x01"),
            None,
            key
        )

    def serialize(self):
        return {
            "super": super(SendRecvChain, self).serialize()
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        return super(SendRecvChain, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )
