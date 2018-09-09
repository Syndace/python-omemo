from __future__ import absolute_import

import x3dh

class PublicKeyEncoder(x3dh.PublicKeyEncoder):
    @staticmethod
    def encodePublicKey(key, key_type):
        if key_type == "25519":
            return b"\x05" + key

        raise NotImplementedError
