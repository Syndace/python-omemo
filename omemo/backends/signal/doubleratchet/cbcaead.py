from __future__ import absolute_import

import doubleratchet

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class CBCAEAD(doubleratchet.AEAD):
    CRYPTOGRAPHY_BACKEND = default_backend()

    def __init__(self):
        super(CBCAEAD, self).__init__()

    def __getHKDFOutput(self, message_key):
        # Prepare the salt, which should be a string of 0x00 bytes with the length of
        # the hash digest
        salt = b"\x00" * 32

        # Get 80 bytes from the HKDF calculation
        hkdf_out = HKDF(
            algorithm = hashes.SHA256(),
            length    = 80,
            salt      = salt,
            info      = "WhisperMessageKeys".encode("US-ASCII"),
            backend   = self.__class__.CRYPTOGRAPHY_BACKEND
        ).derive(message_key)

        # Split these 80 bytes in three parts
        return hkdf_out[:32], hkdf_out[32:64], hkdf_out[64:]

    def __getAES(self, key, iv):
        return Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend = self.__class__.CRYPTOGRAPHY_BACKEND
        )

    def encrypt(self, plaintext, message_key, ad):
        encryption_key, authentication_key, iv = self.__getHKDFOutput(message_key)

        # Prepare PKCS#7 padded plaintext
        padder    = padding.PKCS7(128).padder()
        plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the plaintext using AES-256 (the 256 bit are implied by the key size),
        # CBC mode and the previously created key and iv
        aes_cbc    = self.__getAES(encryption_key, iv).encryptor()
        ciphertext = aes_cbc.update(plaintext) + aes_cbc.finalize()

        return {
            "ciphertext" : ciphertext,
            "additional" : {
                "key" : authentication_key,
                "ad"  : ad
            }
        }

    def decrypt(self, ciphertext, message_key, ad):
        decryption_key, authentication_key, iv = self.__getHKDFOutput(message_key)

        # Decrypt the plaintext using AES-256 (the 256 bit are implied by the key size),
        # CBC mode and the previously created key and iv
        aes_cbc   = self.__getAES(decryption_key, iv).decryptor()
        plaintext = aes_cbc.update(ciphertext) + aes_cbc.finalize()

        # Remove the PKCS#7 padding from the plaintext
        unpadder  = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()

        return {
            "plaintext"  : plaintext,
            "additional" : {
                "key" : authentication_key,
                "ad"  : ad
            }
        }
