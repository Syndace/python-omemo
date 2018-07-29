import copy
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from x3dh.exceptions import SessionInitiationException

from . import default
from . import promise
from . import storagewrapper
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
    def create(cls, my_bare_jid, storage, otpk_policy, my_device_id = None):
        self = cls()

        self._storage = storagewrapper.StorageWrapper(storage)

        self.__otpk_policy  = otpk_policy
        self.__my_bare_jid  = my_bare_jid
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
            yield self._storage.storeActiveDevices(self.__my_bare_jid, [
                self.__my_device_id
            ])

    @promise.maybe_coroutine(checkSelf)
    def __listDevices(self, bare_jid):
        try:
            promise.returnValue(copy.deepcopy(self.__devices_cache[bare_jid]))
        except KeyError:
            active   = yield self._storage.loadActiveDevices(bare_jid)
            inactive = yield self._storage.loadInactiveDevices(bare_jid)

            self.__devices_cache[bare_jid] = {
                "active"   : set(active),
                "inactive" : set(inactive)
            }

            promise.returnValue(copy.deepcopy(self.__devices_cache[bare_jid]))

    @promise.maybe_coroutine(checkSelf)
    def __loadSession(self, bare_jid, device):
        try:
            promise.returnValue(self.__sessions_cache[bare_jid][device])
        except KeyError:
            session = yield self._storage.loadSession(bare_jid, device)

            self.__sessions_cache[bare_jid] = self.__sessions_cache.get(bare_jid, {})
            self.__sessions_cache[bare_jid][device] = session
            promise.returnValue(self.__sessions_cache[bare_jid][device])

    @promise.maybe_coroutine(checkSelf)
    def __storeSession(self, bare_jid, device, session):
        self.__sessions_cache[bare_jid] = self.__sessions_cache.get(bare_jid, {})
        self.__sessions_cache[bare_jid][device] = session
        yield self._storage.storeSession(bare_jid, device, session)

    def __loggingEncryptMessageCallback(self, e, bare_jid, device):
        logging.getLogger("SessionManager").debug(
            "Exception during encryption for device " +
            str(device) +
            " of bare jid " +
            bare_jid +
            ": " +
            str(e.__class__.__name__)
        )

    @promise.maybe_coroutine(checkSelf)
    def __encryptMessage(
        self,
        bare_jids,
        plaintext,
        bundles = None,
        devices = None,
        callback = None,
        always_trust = False
    ):
        # Lift a single bare_jid into a list
        if not isinstance(bare_jids, list):
            bare_jids = [ bare_jids ]

        # Add the own bare_jid to the list
        bare_jids = set(bare_jids) | set([ self.__my_bare_jid ])

        # If no callback was passed, log the exceptions
        if not callback:
            callback = self.__loggingEncryptMessageCallback

        # If no bundles were passed, default to an empty dict
        if not bundles:
            bundles = {}

        if devices:
            devices = { bare_jid: devices.get(bare_jid, []) for bare_jid in bare_jids }
        else:
            devices = {}

            for bare_jid in bare_jids:
                # Load all active devices for this bare_jid
                devices[bare_jid] = (yield self.__listDevices(bare_jid))["active"]

                # If there are no active devices for this jid, generate an exception
                if len(devices[bare_jid]) == 0:
                    del devices[bare_jid]
                    callback(NoDevicesException(), bare_jid, None)

        # Don't encrypt the message for the sending device
        try:
            devices[self.__my_bare_jid].remove(self.__my_device_id)
        except (KeyError, ValueError):
            pass

        # Store all encrypted messages into this array
        # The elements will look like this:
        # {
        #     "rid"      : receiver_id  :int,
        #     "pre_key"  : pre_key      :bool,
        #     "message"  : message_data :bytes,
        #     "bare_jid" : bare_jid     :string
        # }
        messages = []

        aes_gcm_key = AESGCM.generate_key(bit_length = 128)
        aes_gcm_iv  = os.urandom(16)

        aes_gcm = AESGCM(aes_gcm_key)

        ciphertext = aes_gcm.encrypt(aes_gcm_iv, plaintext, None)

        aes_gcm_tag = ciphertext[-16:]
        ciphertext  = ciphertext[:-16]

        @promise.maybe_coroutine(checkConst(checkSelf(self)))
        def __encryptAll(devices, bare_jid):
            encrypted_count = 0

            for device in devices:
                is_trusted = yield self._storage.isTrusted(bare_jid, device)
                if not is_trusted and not always_trust:
                    callback(UntrustedException(), bare_jid, device)
                    continue

                if self.__state.hasBoundOTPK(bare_jid, device):
                    self.__state.respondedTo(bare_jid, device)
                    yield self._storage.storeState(self.__state, self.__my_device_id)

                dr = yield self.__loadSession(bare_jid, device)

                pre_key = dr == None

                if pre_key:
                    try:
                        bundle = bundles[bare_jid][device]
                    except KeyError:
                        callback(MissingBundleException(), bare_jid, device)
                        continue

                    try:
                        session_init_data = self.__state.initSessionActive(bundle)
                    except SessionInitiationException as e:
                        callback(e, bare_jid, device)
                        continue

                    # Store the changed state
                    yield self._storage.storeState(self.__state, self.__my_device_id)

                    dr                = session_init_data["dr"]
                    session_init_data = session_init_data["to_other"]

                    pre_key = True

                message = dr.encryptMessage(aes_gcm_key + aes_gcm_tag)

                # Store the new/changed session
                yield self.__storeSession(bare_jid, device, dr)

                message_data = default.wireformat.message_header.toWire(
                    message["ciphertext"],
                    message["header"]
                )

                if pre_key:
                    message_data = default.wireformat.pre_key_message_header.toWire(
                        session_init_data,
                        message_data
                    )

                messages.append({
                    "message"  : message_data,
                    "pre_key"  : pre_key,
                    "bare_jid" : bare_jid,
                    "rid"      : device
                })

                encrypted_count += 1

            if encrypted_count == 0:
                if bare_jid != self.__my_bare_jid:
                    callback(NoTrustedDevicesException(), bare_jid, None)

        for bare_jid, deviceList in devices.items():
            yield __encryptAll(deviceList, bare_jid)

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
    def encryptKeyTransportMessage(self, bare_jids, *args, **kwargs):
        result = yield self.__encryptMessage(bare_jids, b"", *args, **kwargs)
        del result["payload"]
        promise.returnValue(result)

    @promise.maybe_coroutine(checkSelf)
    def buildSession(self, bare_jid, device, bundle, callback = None):
        """
        Special version of encryptKeyTransportMessage, which does not encrypt a
        new KeyTransportMessage for all devices of the receiver and all devices
        of the sender but encrypts it for just the one specific device of the
        receiver.

        This can be used to build a session with a specific device without
        sending an initial text message.
        """

        promise.returnValue((yield self.encryptKeyTransportMessage(
            bare_jid,
            { bare_jid: { device: bundle } },
            { bare_jid: [ device ] },
            callback,
            always_trust = True
        )))

    @promise.maybe_coroutine(checkSelf)
    def decryptMessage(
        self,
        bare_jid,
        device,
        iv,
        message,
        is_pre_key_message,
        payload = None,
        from_storage = False
    ):
        if is_pre_key_message:
            # Unpack the pre key message data
            message_and_init_data = default.wireformat.pre_key_message_header.fromWire(message)

            # Prepare the DoubleRatchet
            dr = self.__state.initSessionPassive(
                message_and_init_data["session_init_data"],
                bare_jid,
                device,
                self.__otpk_policy,
                from_storage
            )

            # Store the changed state
            yield self._storage.storeState(self.__state, self.__my_device_id)

            # Store the new session
            yield self.__storeSession(bare_jid, device, dr)

            # Unpack the "normal" message that was wrapped into the PreKeyMessage
            message = message_and_init_data["message"]
        else:
            # If this is not part of a PreKeyMessage,
            # we received a normal Message and can safely delete the OTPK
            self.__state.deleteBoundOTPK(bare_jid, device)
            yield self._storage.storeState(self.__state, self.__my_device_id)

        # Unpack the message data
        message_data = default.wireformat.message_header.fromWire(message)

        # Load the session
        dr = yield self.__loadSession(bare_jid, device)

        # Get the concatenation of the AES GCM key and tag
        plaintext = dr.decryptMessage(
            message_data["ciphertext"],
            message_data["header"]
        )

        # Store the changed session
        yield self.__storeSession(bare_jid, device, dr)

        aes_gcm_key = plaintext[:16]
        aes_gcm_tag = plaintext[16:]

        aes_gcm = AESGCM(aes_gcm_key)

        if payload == None:
            # Return the prepared cipher
            promise.returnValue(( aes_gcm, None ))
        else:
            # Return the plaintext
            promise.returnValue((
                None,
                aes_gcm.decrypt(iv, payload + aes_gcm_tag, None)
            ))

    @promise.maybe_coroutine(checkSelf)
    def newDeviceList(self, devices, bare_jid = None):
        if not bare_jid:
            bare_jid = self.__my_bare_jid

        devices = set(devices)

        if bare_jid == self.__my_bare_jid:
            # The own device can never become inactive
            devices |= set([ self.__my_device_id ])

        devices_old = yield self.__listDevices(bare_jid)
        devices_old = devices_old["active"] | devices_old["inactive"]

        active   = devices
        inactive = devices_old - active

        self.__devices_cache[bare_jid] = { "active": active, "inactive": inactive }

        yield self._storage.storeActiveDevices(bare_jid, active)
        yield self._storage.storeInactiveDevices(bare_jid, inactive)

    @promise.maybe_coroutine(checkSelf)
    def getDevices(self, bare_jid = None):
        if not bare_jid:
            bare_jid = self.__my_bare_jid

        result = yield self.__listDevices(bare_jid)
        promise.returnValue(result)

    @property
    def state(self):
        return self.__state
