from __future__ import absolute_import

import doubleratchet
import x3dh

from .sendrecvchain import SendRecvChain

class DoubleRatchetConfig(doubleratchet.DoubleRatchetConfig):
    def __init__(
        self,
        symmetric_key_ratchet = None,
        aead = None,
        ad = None,
        message_key_store_max = 5000
    ):
        if symmetric_key_ratchet == None:
            symmetric_key_ratchet = doubleratchet.ratchets.SymmetricKeyRatchet(
                SendRecvChain,
                SendRecvChain
            )

        if aead == None:
            aead = doubleratchet.recommended.CBCHMACAEAD(
                "SHA-256",
                "WhisperMessageKeys"
            )

        super(DoubleRatchetConfig, self).__init__(
            symmetric_key_ratchet,
            aead,
            ad,
            message_key_store_max
        )

class DHRatchetConfig(doubleratchet.DHRatchetConfig):
    def __init__(
        self,
        root_chain,
        encryption_key_pair_class = x3dh.implementations.EncryptionKeyPairCurve25519,
        own_key = None,
        other_enc = None
    ):
        super(DHRatchetConfig, self).__init__(
            root_chain,
            encryption_key_pair_class,
            own_key,
            other_enc
        )
