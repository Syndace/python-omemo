from __future__ import absolute_import

import doubleratchet

class RootChain(doubleratchet.chains.KDFChain):
    def __init__(self, key):
        super(RootChain, self).__init__(
            key,
            doubleratchet.recommended.RootKeyKDF("SHA-256", "WhisperRatchet")
        )
