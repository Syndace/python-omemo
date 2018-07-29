from __future__ import absolute_import

import doubleratchet

from .config import DHRatchetConfig, DoubleRatchetConfig
from .rootchain import RootChain

class DoubleRatchet(doubleratchet.ratchets.DoubleRatchet):
    def __init__(self, root_key, own_key = None, other_enc = None, ad = None):
        double_ratchet_config = DoubleRatchetConfig(ad = ad)
        dh_ratchet_config = DHRatchetConfig(
            RootChain(root_key),
            own_key   = own_key,
            other_enc = other_enc
        )

        super(DoubleRatchet, self).__init__(
            doubleratchet.Config(double_ratchet_config, dh_ratchet_config)
        )

    def _makeAD(self, header, ad):
        return ad
