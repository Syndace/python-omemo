from __future__ import absolute_import

import x3dh

class CurveTypeEncryptionKeyEncoder(x3dh.EncryptionKeyEncoder):
    @staticmethod
    def encodeEncryptionKey(encryption_key, encryption_key_type):
        if encryption_key_type == "25519":
            return b'\x05' + encryption_key
