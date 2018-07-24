from __future__ import absolute_import

import doubleratchet

class SendRecvChain(doubleratchet.chains.ConstKDFChain):
    def __init__(self, key):
        # NOTE: The last parameter (= None) usually supplies the constant data that is
        # applied to the KDF chain on each step.
        # In this case, the ChainKeyKDF is constant by itself and ignores the data it
        # gets as input.
        # That means, the last parameter gets ignored and can be set to anything you want.
        super(SendRecvChain, self).__init__(
            key,
            doubleratchet.recommended.ChainKeyKDF("SHA-256", b"\x02", b"\x01"),
            None
        )
