from __future__ import absolute_import

import doubleratchet

from .sendrecvchain import SendRecvChain

class SymmetricKeyRatchet(doubleratchet.ratchets.SymmetricKeyRatchet):
    def __init__(self):
        super(SymmetricKeyRatchet, self).__init__(
            SendRecvChain,
            SendRecvChain
        )

    def serialize(self):
        return {
            "super": super(SymmetricKeyRatchet, self).serialize()
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        return super(SymmetricKeyRatchet, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )
