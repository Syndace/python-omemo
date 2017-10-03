from __future__ import absolute_import

from Cryptodome.Cipher import AES

from . import doubleratchet
from . import x3dh
from . import wireformat

class X3DHDoubleRatchet(x3dh.State):
    def __init__(self):
        super(X3DHDoubleRatchet, self).__init__()

    def initSessionActive(self, other_public_bundle, *args, **kwargs):
        session_init_data = super(X3DHDoubleRatchet, self).initSessionActive(other_public_bundle, *args, **kwargs)

        # When actively initializing a session
        # - The shared secret becomes the root key
        # - The public SPK used for X3DH becomes the other's enc for the dh ratchet
        # - The associated data calculated by X3DH becomes the ad used by the double ratchet encryption/decryption
        session_init_data["dr"] = doubleratchet.DoubleRatchet(session_init_data["sk"], other_enc = other_public_bundle.spk["key"], ad = session_init_data["ad"])

        # The shared secret and ad values are now irrelevant
        del session_init_data["sk"]
        del session_init_data["ad"]

        self.__compressSessionInitData(session_init_data, other_public_bundle)

        return session_init_data

    def initSessionPassive(self, session_init_data):
        self.__decompressSessionInitData(session_init_data)

        session_data = super(X3DHDoubleRatchet, self).initSessionPassive(session_init_data)

        # When passively initializing the session
        # - The shared secret becomes the root key
        # - The public SPK used by the active part for X3DH becomes the own dh ratchet key
        # - The associated data calculated by X3DH becomes the ad used by the double ratchet encryption/decryption
        return doubleratchet.DoubleRatchet(session_data["sk"], own_key = self.spk, ad = session_data["ad"])

    def __compressSessionInitData(self, session_init_data, bundle):
        """
        Compress the session initialization data by replacing keys with their ids.
        """

        session_init_data["to_other"]["otpk_id"] = bundle.findOTPKId(session_init_data["to_other"]["otpk"])
        session_init_data["to_other"]["spk_id"]  = bundle.findSPKId(session_init_data["to_other"]["spk"])

        del session_init_data["to_other"]["otpk"]
        del session_init_data["to_other"]["spk"]

    def __decompressSessionInitData(self, session_init_data):
        """
        Decompress the session initialization data by replacing key ids with the keys.
        """

        session_init_data["otpk"] = self.getOTPK(session_init_data["otpk_id"])
        session_init_data["spk"]  = self.getSPK(session_init_data["spk_id"])

        del session_init_data["otpk_id"]
        del session_init_data["spk_id"]
    

    def makeKeyTransportMessage(self):
        aes_gcm_key = os.urandom(16)
        aes_gcm_iv  = os.urandom(16)

        aes_gcm = AES.new(aes_gcm_key, AES.MODE_GCM, nonce = aes_gcm_iv)
        aes_gcm_tag = aes_gcm.digest()

        message_data = self.encryptMessage(aes_gcm_key + aes_gcm_tag)

        message = wireformat.message_header.toWire(message_data["ciphertext"], message_data["header"], message_data["ad"], message_data["authentication_key"])

        return {
            "iv": aes_gcm_iv,
            "message": message,
            "cipher": aes_gcm
        }

    def makeMessage(self, plaintext):
        aes_gcm_key = os.urandom(16)
        aes_gcm_iv  = os.urandom(16)

        aes_gcm = AES.new(aes_gcm_key, AES.MODE_GCM, nonce = aes_gcm_iv)

        ciphertext, aes_gcm_tag = aes_gcm.encrypt_and_digest(plaintext)
        
        message_data = self.encryptMessage(aes_gcm_key + aes_gcm_tag)

        message = wireformat.message_header.toWire(message_data["ciphertext"], message_data["header"], message_data["ad"], message_data["authentication_key"])

        return {
            "iv": aes_gcm_iv,
            "message": message,
            "payload": ciphertext
        }
