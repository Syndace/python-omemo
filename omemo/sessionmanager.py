from __future__ import absolute_import

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .x3dhdoubleratchet import X3DHDoubleRatchet
from . import wireformat

class SessionManager(object):
    def __init__(self, my_jid, my_device_id, storage):
        self.__storage = storage
        self.__my_jid = my_jid
        self.__my_device_id = my_device_id

        self.__prepare()

    def __prepare(self):
        self.__state = self.__storage.loadState()

        if not self.__state:
            self.__state = X3DHDoubleRatchet()
            self.__storage.storeState(self.__state)

    def setPublicBundle(self, jid, device_id, bundle):
        self.__bundles[jid] = self.__bundles.get(jid, {})
        self.__bundles[jid][device_id] = bundle

    def getSession(self, jid, device):
        return self.__sessions[jid][device]

    def deleteSession(self, jid, device):
        del self.__sessions[jid][device]

    def __encryptMessage(self, other_jid, plaintext):
        messages = {
            other_jid: {},
            self.__my_jid: {}
        }

        aes_gcm_key = AESGCM.generate_key(bit_length = 128)
        aes_gcm_iv  = os.urandom(16)

        aes_gcm = AESGCM(aes_gcm_key)

        ciphertext = aes_gcm.encrypt(aes_gcm_iv, plaintext, None)

        aes_gcm_tag = ciphertext[-16:]
        ciphertext  = ciphertext[:-16]

        other_devices = list(self.__bundles[other_jid].keys())
        my_devices    = list(self.__bundles[self.__my_jid].keys())
        my_devices.remove(self.__my_device_id)

        def encryptAll(devices, jid):
            for device in devices:
                try:
                    dr = self.__sessions[jid][device]
                    pre_key = False
                except KeyError:
                    session_init_data = self.initSessionActive(self.__bundles[jid][device])
                    dr                = session_init_data["dr"]
                    session_init_data = session_init_data["to_other"]

                    pre_key = True

                self.__sessions[jid] = self.__sessions.get(jid, {})
                self.__sessions[jid][device] = dr

                message = dr.encryptMessage(aes_gcm_key + aes_gcm_tag)

                message_data = wireformat.message_header.toWire(message["ciphertext"], message["header"], message["ad"], message["authentication_key"])

                if pre_key:
                    message_data = wireformat.pre_key_message_header.toWire(session_init_data, message_data)

                messages[jid][device] = { "message": message_data, "pre_key": pre_key }

        encryptAll(other_devices, other_jid)
        encryptAll(my_devices, self.__my_jid)

        return {
            "iv": aes_gcm_iv,
            "messages": messages,
            "payload": ciphertext,
            "cipher": aes_gcm
        }

    def encryptMessage(self, other_jid, plaintext):
        result = self.__encryptMessage(other_jid, plaintext)
        del result["cipher"]
        return result

    def encryptKeyTransportMessage(self, other_jid):
        result = self.__encryptMessage(other_jid, b"")
        del result["payload"]
        return result

    def decryptPreKeyMessage(self, jid, device, iv, message, payload = None):
        # Make sure the key exists
        self.__sessions[jid] = self.__sessions.get(jid, {})

        # Unpack the pre key message data
        message_and_init_data = wireformat.pre_key_message_header.fromWire(message)

        # Prepare the DoubleRatchet
        self.__sessions[jid][device] = self.initSessionPassive(message_and_init_data["session_init_data"])

        # Now, decrypt the contained message
        return self.decryptMessage(jid, device, iv, message_and_init_data["message"], payload)

    def decryptMessage(self, jid, device, iv, message, payload = None):
        # Unpack the message data
        message_data = wireformat.message_header.fromWire(message)

        # Get the concatenation of the AES GCM key and tag
        aes_gcm_key_tag = self.__sessions[jid][device].decryptMessage(message_data["ciphertext"], message_data["header"])

        # Check the authentication
        wireformat.message_header.checkAuthentication(message, aes_gcm_key_tag["ad"], aes_gcm_key_tag["authentication_key"])

        aes_gcm_key = aes_gcm_key_tag["plaintext"][:16]
        aes_gcm_tag = aes_gcm_key_tag["plaintext"][16:]

        aes_gcm = AESGCM(aes_gcm_key)

        if payload == None:
            # Return the prepared cipher
            return aes_gcm, None
        else:
            # Return the plaintext
            return None, aes_gcm.decrypt(iv, payload + aes_gcm_tag, None)
