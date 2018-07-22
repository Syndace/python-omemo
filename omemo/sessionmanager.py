from __future__ import absolute_import

import copy
import functools
import logging
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import promise
from . import storagewrapper
from . import wireformat
from .exceptions.sessionmanagerexceptions import *
from .x3dhdoubleratchet import X3DHDoubleRatchet

def checkSelf(self, *args, **kwargs):
    return self._storage.is_async

def checkPositionalArgument(position):
    def _checkPositionalArgument(*args, **kwargs):
        return args[position].is_async

    return _checkPositionalArgument

def checkConst(const):
    def _checkConst(*args, **kwargs):
        return const

    return _checkConst

class SessionManager(object):
    @classmethod
    @promise.maybe_coroutine(checkPositionalArgument(2))
    def create(cls, my_jid, storage, otpk_policy, my_device_id = None):
        self = cls()

        self._storage = storagewrapper.StorageWrapper(storage)
        self.__otpk_policy = otpk_policy
        self.__my_jid = my_jid
        self.__my_device_id = my_device_id

        self.__devices_cache  = {}
        self.__sessions_cache = {}

        yield self.__prepare()

        promise.returnValue(self)

    @promise.maybe_coroutine(checkSelf)
    def __prepare(self):
        state = yield self._storage.loadState()

        if state:
            self.__state = state["state"]   
            self.__my_device_id = state["device_id"]
        else:
            self.__state = X3DHDoubleRatchet()

            if not self.__my_device_id:
                raise SessionManagerException("Device id required for initial setup")

            yield self._storage.storeState(self.__state, self.__my_device_id)
            yield self._storage.storeActiveDevices(self.__my_jid, [ self.__my_device_id ])

    @promise.maybe_coroutine(checkSelf)
    def __listDevices(self, jid):
        try:
            promise.returnValue(copy.deepcopy(self.__devices_cache[jid]))
        except KeyError:
            active   = yield self._storage.loadActiveDevices(jid)
            inactive = yield self._storage.loadInactiveDevices(jid)

            self.__devices_cache[jid] = {
                "active"   : set(active),
                "inactive" : set(inactive)
            }

            promise.returnValue(copy.deepcopy(self.__devices_cache[jid]))

    @promise.maybe_coroutine(checkSelf)
    def __loadSession(self, jid, device):
        try:
            promise.returnValue(self.__sessions_cache[jid][device])
        except KeyError:
            self.__sessions_cache[jid] = self.__sessions_cache.get(jid, {})
            self.__sessions_cache[jid][device] = yield self._storage.loadSession(jid, device)
            promise.returnValue(self.__sessions_cache[jid][device])

    @promise.maybe_coroutine(checkSelf)
    def __storeSession(self, jid, device, session):
        self.__sessions_cache[jid] = self.__sessions_cache.get(jid, {})
        self.__sessions_cache[jid][device] = session
        yield self._storage.storeSession(jid, device, session)

    @promise.maybe_coroutine(checkSelf)
    def __encryptMessage(self, jids, plaintext, bundles = None, devices = None, callback = None, always_trust = False):
        # Lift a single jid into a list
        if not isinstance(jids, list):
            jids = [ jids ]

        # Add the own jid to the list
        jids = set(jids) | set([ self.__my_jid ])

        # If no callback was passed, log the exceptions
        if not callback:
            callback = lambda e, jid, device: logging.getLogger("SessionManager").debug("Exception during encryption for device " + str(device) + " of jid " + jid + ": " + str(e.__class__.__name__))

        # If no bundles were passed, default to an empty dict
        if not bundles:
            bundles = {}

        if devices:
            devices = { jid: devices.get(jid, []) for jid in jids }
        else:
            devices = {}

            for jid in jids:
                # Load all active devices for this jid
                devices[jid] = (yield self.__listDevices(jid))["active"]

                # If there are no active devices for this jid, generate an exception
                if len(devices[jid]) == 0:
                    del devices[jid]
                    callback(NoDevicesException(), jid, None)

        # Don't encrypt the message for the sending device
        try:
            devices[self.__my_jid].remove(self.__my_device_id)
        except (KeyError, ValueError):
            pass

        # Store all encrypted messages into this array
        # The elements will look like this: { "rid": receiver_id:int, "pre_key": pre_key:bool, "message": message_data:bytes, "jid": jid:string }
        messages = []

        aes_gcm_key = AESGCM.generate_key(bit_length = 128)
        aes_gcm_iv  = os.urandom(16)

        aes_gcm = AESGCM(aes_gcm_key)

        ciphertext = aes_gcm.encrypt(aes_gcm_iv, plaintext, None)

        aes_gcm_tag = ciphertext[-16:]
        ciphertext  = ciphertext[:-16]

        @promise.maybe_coroutine(checkConst(checkSelf(self)))
        def __encryptAll(devices, jid):
            encrypted_count = 0

            for device in devices:
                if not (yield self._storage.isTrusted(jid, device)) and not always_trust:
                    callback(UntrustedException(), jid, device)
                    continue

                if self.__state.hasBoundOTPK(jid, device):
                    self.__state.respondedTo(jid, device)
                    yield self._storage.storeState(self.__state, self.__my_device_id)

                dr = yield self.__loadSession(jid, device)

                pre_key = dr == None

                if pre_key:
                    try:
                        bundle = bundles[jid][device]
                    except KeyError:
                        callback(MissingBundleException(), jid, device)
                        continue

                    session_init_data = self.__state.initSessionActive(bundle)

                    # Store the changed state
                    yield self._storage.storeState(self.__state, self.__my_device_id)

                    dr                = session_init_data["dr"]
                    session_init_data = session_init_data["to_other"]

                    pre_key = True

                message = dr.encryptMessage(aes_gcm_key + aes_gcm_tag)

                # Store the new/changed session
                yield self.__storeSession(jid, device, dr)

                message_data = wireformat.message_header.toWire(message["ciphertext"], message["header"], message["ad"], message["authentication_key"])

                if pre_key:
                    message_data = wireformat.pre_key_message_header.toWire(session_init_data, message_data)

                messages.append({ "message": message_data, "pre_key": pre_key, "jid": jid, "rid": device })

                encrypted_count += 1

            if encrypted_count == 0:
                if jid != self.__my_jid:
                    callback(NoTrustedDevicesException(), jid, None)

        for jid, deviceList in devices.items():
            yield __encryptAll(deviceList, jid)

        promise.returnValue({
            "iv": aes_gcm_iv,
            "sid": self.__my_device_id,
            "messages": messages,
            "payload": ciphertext,
            "cipher": aes_gcm
        })

    @promise.maybe_coroutine(checkSelf)
    def encryptMessage(self, *args, **kwargs):
        result = yield self.__encryptMessage(*args, **kwargs)
        del result["cipher"]
        promise.returnValue(result)

    @promise.maybe_coroutine(checkSelf)
    def encryptKeyTransportMessage(self, jids, *args, **kwargs):
        result = yield self.__encryptMessage(jids, b"", *args, **kwargs)
        del result["payload"]
        promise.returnValue(result)

    @promise.maybe_coroutine(checkSelf)
    def buildSession(self, jid, device, bundle, callback = None):
        """
        Special version of encryptKeyTransportMessage, which does not encrypt a
        new KeyTransportMessage for all devices of the receiver and all devices
        of the sender but encrypts it for just the one specific device of the
        receiver.

        This can be used to build a session with a specific device without
        sending an initial text message.
        """

        result = yield self.encryptKeyTransportMessage(jid, { jid: { device: bundle } }, { jid: [ device ] }, callback, always_trust = True)
        promise.returnValue(result)

    @promise.maybe_coroutine(checkSelf)
    def decryptPreKeyMessage(self, jid, device, iv, message, from_storage, payload = None):
        """
        Decrypt a PreKeyMessage, passively building a session with given jid and device.

        message is the binary data that is contained in the <key> xml tag for our device.
        Set from_storage to True, if the PreKeyMessage was received from any storage mechanism, e.g. MAM.
        """

        # Unpack the pre key message data
        message_and_init_data = wireformat.pre_key_message_header.fromWire(message)

        # Prepare the DoubleRatchet
        dr = self.__state.initSessionPassive(message_and_init_data["session_init_data"], jid, device, self.__otpk_policy, from_storage)

        # Store the changed state
        yield self._storage.storeState(self.__state, self.__my_device_id)

        # Store the new session
        yield self.__storeSession(jid, device, dr)

        # Now, decrypt the contained message
        result = yield self.decryptMessage(jid, device, iv, message_and_init_data["message"], payload, True)
        promise.returnValue(result)

    @promise.maybe_coroutine(checkSelf)
    def decryptMessage(self, jid, device, iv, message, payload = None, pre_key_message = False):
        if not pre_key_message:
            # If this is not part of a PreKeyMessage, we received a normal Message and can safely delete the OTPK
            self.__state.deleteBoundOTPK(jid, device)
            yield self._storage.storeState(self.__state, self.__my_device_id)

        # Unpack the message data
        message_data = wireformat.message_header.fromWire(message)

        # Load the session
        dr = yield self.__loadSession(jid, device)

        # Get the concatenation of the AES GCM key and tag
        aes_gcm_key_tag = dr.decryptMessage(message_data["ciphertext"], message_data["header"])

        # Store the changed session
        yield self.__storeSession(jid, device, dr)

        # Check the authentication
        wireformat.message_header.checkAuthentication(message, aes_gcm_key_tag["ad"], aes_gcm_key_tag["authentication_key"])

        aes_gcm_key = aes_gcm_key_tag["plaintext"][:16]
        aes_gcm_tag = aes_gcm_key_tag["plaintext"][16:]

        aes_gcm = AESGCM(aes_gcm_key)

        if payload == None:
            # Return the prepared cipher
            promise.returnValue(( aes_gcm, None ))
        else:
            # Return the plaintext
            promise.returnValue(( None, aes_gcm.decrypt(iv, payload + aes_gcm_tag, None) ))

    @promise.maybe_coroutine(checkSelf)
    def newDeviceList(self, devices, jid = None):
        if not jid:
            jid = self.__my_jid

        devices = set(devices)

        if jid == self.__my_jid:
            # The own device can never become inactive
            devices |= set([ self.__my_device_id ])

        devices_old = yield self.__listDevices(jid)
        devices_old = devices_old["active"] | devices_old["inactive"]
        
        self.__devices_cache[jid] = {
            "active": devices,
            "inactive": devices_old - devices
        }

        yield self._storage.storeActiveDevices(jid, self.__devices_cache[jid]["active"])
        yield self._storage.storeInactiveDevices(jid, self.__devices_cache[jid]["inactive"])

    @promise.maybe_coroutine(checkSelf)
    def getDevices(self, jid = None):
        if not jid:
            jid = self.__my_jid

        result = yield self.__listDevices(jid)
        promise.returnValue(result)

    @property
    def state(self):
        return self.__state
