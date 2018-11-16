from __future__ import absolute_import

import copy
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from x3dh.exceptions import KeyExchangeException

from . import promise
from . import storagewrapper
from .exceptions import *
from .x3dhdoubleratchet import make as make_X3DHDoubleRatchet

def d(*args, **kwargs):
    logging.getLogger("omemo.SessionManager").debug(*args, **kwargs)

def w(*args, **kwargs):
    logging.getLogger("omemo.SessionManager").warning(*args, **kwargs)

def e(*args, **kwargs):
    logging.getLogger("omemo.SessionManager").error(*args, **kwargs)

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
    @promise.maybe_coroutine(checkPositionalArgument(1))
    def create(cls, storage, otpk_policy, backend, my_bare_jid, my_device_id):
        self = cls()

        self._storage = storagewrapper.StorageWrapper(storage)

        self.__otpk_policy = otpk_policy

        self.__state = None

        self.__my_bare_jid  = my_bare_jid
        self.__my_device_id = my_device_id

        self.__devices_cache  = {}
        self.__sessions_cache = {}

        self.__backend = backend
        self.__X3DHDoubleRatchet = make_X3DHDoubleRatchet(self.__backend)

        yield self.__prepare()

        promise.returnValue(self)

    @promise.maybe_coroutine(checkSelf)
    def __prepare(self):
        state = yield self._storage.loadState()
        if state == None:
            self.__state = self.__X3DHDoubleRatchet()

            yield self._storage.storeState(self.__state.serialize())
            yield self._storage.storeActiveDevices(self.__my_bare_jid, [
                self.__my_device_id
            ])
        else:
            self.__state = self.__X3DHDoubleRatchet.fromSerialized(state)

        own_data = yield self._storage.loadOwnData()
        if own_data == None:

            yield self._storage.storeOwnData(self.__my_bare_jid, self.__my_device_id)
        else:
            if (not self.__my_bare_jid  == own_data["own_bare_jid"] or
                not self.__my_device_id == own_data["own_device_id"]):
                raise InconsistentInfoException(
                    "Given storage is only usable for jid \"" + own_data["own_bare_jid"] +
                    "\" on device " + str(own_data["own_device_id"]) + "."
                )

    @promise.maybe_coroutine(checkSelf)
    def __listDevices(self, bare_jid):
        if not (bare_jid in self.__devices_cache):
            active   = yield self._storage.loadActiveDevices(bare_jid)
            inactive = yield self._storage.loadInactiveDevices(bare_jid)

            self.__devices_cache[bare_jid] = {
                "active"   : set(active),
                "inactive" : set(inactive)
            }

        promise.returnValue(copy.deepcopy(self.__devices_cache[bare_jid]))

    @promise.maybe_coroutine(checkSelf)
    def __loadSession(self, bare_jid, device):
        self.__sessions_cache[bare_jid] = self.__sessions_cache.get(bare_jid, {})

        if not (device in self.__sessions_cache[bare_jid]):
            session = yield self._storage.loadSession(bare_jid, device)

            if session != None:
                session = self.__backend.DoubleRatchet.fromSerialized(session)

            self.__sessions_cache[bare_jid][device] = session

        promise.returnValue(self.__sessions_cache[bare_jid][device])

    @promise.maybe_coroutine(checkSelf)
    def __storeSession(self, bare_jid, device, session):
        self.__sessions_cache[bare_jid] = self.__sessions_cache.get(bare_jid, {})
        self.__sessions_cache[bare_jid][device] = session

        yield self._storage.storeSession(bare_jid, device, session.serialize())

    def __loggingEncryptMessageCallback(self, e, bare_jid, device):
        w(
            "Exception during encryption for device " +
            str(device) +
            " of bare jid " +
            bare_jid +
            ": " +
            str(e.__class__.__name__),
            exc_info = e
        )

    @promise.maybe_coroutine(checkSelf)
    def __encryptMessage(
        self,
        bare_jids,
        plaintext,
        bundles = None,
        devices = None,
        callback = None,
        always_trust = False,
        dry_run = False,
        _DEBUG_ek = None,
        _DEBUG_sendingRatchetKey = None
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
        if bundles == None:
            bundles = {}

        if devices != None:
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
                    if not dry_run:
                        self.__state.respondedTo(bare_jid, device)
                        yield self._storage.storeState(self.__state.serialize())

                dr = yield self.__loadSession(bare_jid, device)

                pre_key = dr == None

                if pre_key:
                    try:
                        bundle = bundles[bare_jid][device]
                    except KeyError:
                        callback(MissingBundleException(), bare_jid, device)
                        continue

                    if not dry_run:
                        try:
                            session_init_data = self.__state.getSharedSecretActive(
                                bundle,
                                _DEBUG_ek = _DEBUG_ek,
                                _DEBUG_sendingRatchetKey = _DEBUG_sendingRatchetKey
                            )
                        except KeyExchangeException as e:
                            callback(e, bare_jid, device)
                            continue

                        # Store the changed state
                        yield self._storage.storeState(self.__state.serialize())

                        dr                = session_init_data["dr"]
                        session_init_data = session_init_data["to_other"]

                        pre_key = True

                if not dry_run:
                    message = dr.encryptMessage(aes_gcm_key + aes_gcm_tag)

                    # Store the new/changed session
                    yield self.__storeSession(bare_jid, device, dr)

                    message_data = self.__backend.WireFormat.messageToWire(
                        message["ciphertext"],
                        message["header"],
                        { "DoubleRatchet": message["additional"] }
                    )

                    if pre_key:
                        message_data = self.__backend.WireFormat.preKeyMessageToWire(
                            session_init_data,
                            message_data,
                            { "DoubleRatchet": message["additional"] }
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
                    callback(NoEligibleDevicesException(), bare_jid, None)

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
    def buildSession(
        self,
        bare_jid,
        device,
        bundle,
        callback = None,
        dry_run = False,
        _DEBUG_ek = None,
        _DEBUG_sendingRatchetKey = None
    ):
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
            always_trust = True,
            dry_run = dry_run,
            _DEBUG_ek = _DEBUG_ek,
            _DEBUG_sendingRatchetKey = _DEBUG_sendingRatchetKey
        )))

    @promise.maybe_coroutine(checkSelf)
    def _decryptMessage(
        self,
        bare_jid,
        device,
        message,
        is_pre_key_message,
        additional_information = None,
        _DEBUG_newRatchetKey = None
    ):
        if is_pre_key_message:
            # Unpack the pre key message data
            message_and_init_data = self.__backend.WireFormat.preKeyMessageFromWire(
                message
            )

            # Prepare the DoubleRatchet
            dr = self.__state.getSharedSecretPassive(
                message_and_init_data["session_init_data"],
                bare_jid,
                device,
                self.__otpk_policy,
                additional_information
            )

            # Store the changed state
            yield self._storage.storeState(self.__state.serialize())

            # Store the new session
            yield self.__storeSession(bare_jid, device, dr)

            # Unpack the "normal" message that was wrapped into the PreKeyMessage
            message = message_and_init_data["message"]
        else:
            # If this is not part of a PreKeyMessage,
            # we received a normal Message and can safely delete the OTPK
            self.__state.deleteBoundOTPK(bare_jid, device)
            yield self._storage.storeState(self.__state.serialize())

        # Unpack the message data
        message_data = self.__backend.WireFormat.messageFromWire(message)

        # Load the session
        dr = yield self.__loadSession(bare_jid, device)

        if dr == None:
            raise NoSessionException(
                "Don't have a session with \"" + bare_jid + "\" on device " +
                str(device) + "."
            )

        # Get the concatenation of the AES GCM key and tag
        plaintext = dr.decryptMessage(
            message_data["ciphertext"],
            message_data["header"],
            _DEBUG_newRatchetKey = _DEBUG_newRatchetKey
        )

        # Check the authentication
        self.__backend.WireFormat.finalizeMessageFromWire(
            message,
            {
                "WireFormat": message_data["additional"],
                "DoubleRatchet": plaintext["additional"]
            }
        )

        # Store the changed session
        yield self.__storeSession(bare_jid, device, dr)

        promise.returnValue(plaintext["plaintext"])

    @promise.maybe_coroutine(checkSelf)
    def decryptMessage(
        self,
        bare_jid,
        device,
        iv,
        message,
        is_pre_key_message,
        payload = None,
        additional_information = None
    ):
        plaintext = yield self._decryptMessage(
            bare_jid,
            device,
            message,
            is_pre_key_message,
            additional_information
        )

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
    def newDeviceList(self, devices, bare_jid):
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
    def public_bundle(self):
        return self.__state.getPublicBundle()

    @property
    def fingerprint(self):
        return self.public_bundle.fingerprint

    @property
    def republish_bundle(self):
        return self.__state.changed

    ###############################
    # DEBUG ADDITIONS, DO NOT USE #
    ###############################

    def _DEBUG_simulatePreKeyMessage(
        self,
        other_session_manager,
        otpk_id,
        ek,
        sending_ratchet_key
    ):
        from .extendedpublicbundle import ExtendedPublicBundle

        e("WARNING: RUNNING UNSAFE DEBUG-ONLY OPERATION")
        d("Simulating pre key message.")

        other_bundle = other_session_manager.state.getPublicBundle()

        ik  = other_bundle.ik
        spk = other_bundle.spk
        spk_signature = other_bundle.spk_signature
        otpks = [ otpk for otpk in other_bundle.otpks if otpk["id"] == otpk_id ]

        other_bundle = ExtendedPublicBundle(ik, spk, spk_signature, otpks)

        my_own_data    = self._storage.loadOwnData()
        other_own_data = other_session_manager._storage.loadOwnData()

        self.newDeviceList(
            [ my_own_data["own_device_id"] ],
            my_own_data["own_bare_jid"]
        )

        self.newDeviceList(
            [ other_own_data["own_device_id"] ],
            other_own_data["own_bare_jid"]
        )

        self.buildSession(
            other_own_data["own_bare_jid"],
            other_own_data["own_device_id"],
            other_bundle,
            _DEBUG_ek = ek,
            _DEBUG_sendingRatchetKey = sending_ratchet_key
        )

    def _DEBUG_simulateMessage(self, other_session_manager):
        e("WARNING: RUNNING UNSAFE DEBUG-ONLY OPERATION")
        d("Simulating message.")

        my_own_data    = self._storage.loadOwnData()
        other_own_data = other_session_manager._storage.loadOwnData()

        self.newDeviceList(
            [ my_own_data["own_device_id"] ],
            my_own_data["own_bare_jid"]
        )

        self.newDeviceList(
            [ other_own_data["own_device_id"] ],
            other_own_data["own_bare_jid"]
        )

        self.encryptKeyTransportMessage(other_own_data["own_bare_jid"])

    def _DEBUG_compareState(self, other_session_manager, state):
        e("WARNING: RUNNING UNSAFE DEBUG-ONLY OPERATION")
        d("Comparing states.")

        import base64

        other_own_data = other_session_manager._storage.loadOwnData()

        dr = self.__loadSession(
            other_own_data["own_bare_jid"],
            other_own_data["own_device_id"]
        )

        assert dr != None

        dr = dr.serialize()

        root_key = base64.b64decode(dr["root_chain"]["super"]["key"].encode("US-ASCII"))
        assert root_key == state["rootKey"]

        try:
            schain_key = dr["skr"]["super"]["schain"]["super"]["super"]["key"]
            schain_key = base64.b64decode(schain_key.encode("US-ASCII"))
        except TypeError:
            pass
        else:
            assert schain_key == state["senderChainKey"]

        if state["receiverChainKey"] != None:
            try:
                rchain_key = dr["skr"]["super"]["rchain"]["super"]["super"]["key"]
                rchain_key = base64.b64decode(rchain_key.encode("US-ASCII"))
            except TypeError:
                pass
            else:
                assert rchain_key == state["receiverChainKey"]
