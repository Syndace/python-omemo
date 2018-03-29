from __future__ import absolute_import

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import SessionManagerException
from .x3dhdoubleratchet import X3DHDoubleRatchet
from . import wireformat

class SessionManager(object):
    def __init__(self, my_jid, my_device_id, storage):
        self.__storage = storage
        self.__my_jid = my_jid
        self.__my_device_id = my_device_id

        self.__devices_cache  = {}
        self.__sessions_cache = {}

        self.__prepare()

    def __prepare(self):
        self.__state = self.__storage.loadState()

        if not self.__state:
            self.__state = X3DHDoubleRatchet()
            self.__storage.storeState(self.__state)

    def __listDevices(self, jid):
        try:
            return self.__devices_cache[jid]
        except KeyError:
            self.__devices_cache[jid] = set(self.__storage.listDevices(jid))
            return self.__devices_cache[jid]

    def __addDevices(self, jid, devices):
        self.__devices_cache[jid] = self.__devices_cache.get(jid, set())
        self.__devices_cache[jid] |= set(devices)

    def __loadSession(self, jid, device):
        try:
            return self.__sessions_cache[jid][device]
        except KeyError:
            self.__sessions_cache[jid] = self.__sessions_cache.get(jid, {})
            self.__sessions_cache[jid][device] = self.__storage.loadSession(jid, device)
            return self.__sessions_cache[jid][device]

    def __storeSession(self, jid, device, session):
        self.__sessions_cache[jid] = self.__sessions_cache.get(jid, {})
        self.__sessions_cache[jid][device] = session
        self.__storage.storeSession(jid, device, session)

    def __encryptMessage(self, other_jid, plaintext, bundles):
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

        self.__addDevices(other_jid,     list(bundles.get(other_jid,     {}).keys()))
        self.__addDevices(self.__my_jid, list(bundles.get(self.__my_jid, {}).keys()))

        other_devices = self.__listDevices(other_jid)
        my_devices    = self.__listDevices(self.__my_jid)

        try:
            my_devices.remove(self.__my_device_id)
        except ValueError:
            pass

        def encryptAll(devices, jid):
            for device in devices:
                dr = self.__loadSession(jid, device)

                pre_key = dr == None

                if pre_key:
                    try:
                        bundle = bundles[jid][device]
                    except KeyError:
                        raise SessionManagerException("Bundle for " + jid + " on device " + str(device) + " required to initiate a session!")

                    session_init_data = self.__state.initSessionActive(bundle)

                    # Store the changed state
                    self.__storage.storeState(self.__state)

                    dr                = session_init_data["dr"]
                    session_init_data = session_init_data["to_other"]

                    pre_key = True

                message = dr.encryptMessage(aes_gcm_key + aes_gcm_tag)

                # Store the new/changed session
                self.__storeSession(jid, device, dr)

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

    def encryptMessage(self, other_jid, plaintext, bundles):
        result = self.__encryptMessage(other_jid, plaintext, bundles)
        del result["cipher"]
        return result

    def encryptKeyTransportMessage(self, other_jid, bundles):
        result = self.__encryptMessage(other_jid, b"", bundles)
        del result["payload"]
        return result

    def decryptPreKeyMessage(self, jid, device, iv, message, payload = None):
        # Unpack the pre key message data
        message_and_init_data = wireformat.pre_key_message_header.fromWire(message)

        # Prepare the DoubleRatchet
        dr = self.__state.initSessionPassive(message_and_init_data["session_init_data"])

        # Store the changed state
        self.__storage.storeState(self.__state)

        # Store the new session
        self.__storeSession(jid, device, dr)

        # Now, decrypt the contained message
        return self.decryptMessage(jid, device, iv, message_and_init_data["message"], payload)

    def decryptMessage(self, jid, device, iv, message, payload = None):
        # Unpack the message data
        message_data = wireformat.message_header.fromWire(message)

        # Load the session
        dr = self.__loadSession(jid, device)

        # Get the concatenation of the AES GCM key and tag
        aes_gcm_key_tag = dr.decryptMessage(message_data["ciphertext"], message_data["header"])

        # Store the changed session
        self.__storeSession(jid, device, dr)

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

    @property
    def state(self):
        return self.__state
