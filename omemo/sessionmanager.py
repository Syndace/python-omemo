from __future__ import absolute_import
from __future__ import division

import copy
import logging
import os
import time

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
    ################################
    # construction and preparation #
    ################################

    @classmethod
    @promise.maybe_coroutine(checkPositionalArgument(1))
    def create(
        cls,
        storage,
        otpk_policy,
        backend,
        my_bare_jid,
        my_device_id,
        inactive_per_jid_max = 15,
        inactive_global_max = 0,
        inactive_max_age = 0
    ):
        self = cls()

        # Store the parameters
        self._storage = storagewrapper.StorageWrapper(storage)

        self.__otpk_policy = otpk_policy

        self.__backend = backend
        self.__X3DHDoubleRatchet = make_X3DHDoubleRatchet(self.__backend)

        self.__my_bare_jid  = my_bare_jid
        self.__my_device_id = my_device_id

        self.__inactive_per_jid_max = inactive_per_jid_max
        self.__inactive_global_max  = inactive_global_max
        self.__inactive_max_age     = inactive_max_age

        # Prepare the caches
        self.__state = None

        self.__devices_cache  = {}
        self.__sessions_cache = {}

        yield self.__prepare()

        promise.returnValue(self)

    @promise.maybe_coroutine(checkSelf)
    def __prepare(self):
        state = yield self._storage.loadState()
        if state == None:
            self.__state = self.__X3DHDoubleRatchet()

            yield self._storage.storeState(self.__state.serialize())

            yield self.__storeActiveDevices(self.__my_bare_jid, [
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

    ##############
    # encryption #
    ##############

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
        yield self.runInactiveDeviceCleanup()

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
            devices = {
                bare_jid: set(devices.get(bare_jid, [])) for bare_jid in bare_jids
            }
        else:
            devices = {}

            for bare_jid in bare_jids:
                # Load all active devices for this bare_jid
                devices[bare_jid] = yield self.__loadActiveDevices(bare_jid)

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

        result = yield self.encryptKeyTransportMessage(
            bare_jid,
            { bare_jid: { device: bundle } },
            { bare_jid: [ device ] },
            callback,
            always_trust = True,
            dry_run = dry_run,
            _DEBUG_ek = _DEBUG_ek,
            _DEBUG_sendingRatchetKey = _DEBUG_sendingRatchetKey
        )

        promise.returnValue(result)

    ##############
    # decryption #
    ##############

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
        yield self.runInactiveDeviceCleanup()

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

    ############################
    # public bundle management #
    ############################

    @property
    def public_bundle(self):
        """
        Fill a PublicBundle object with the public bundle data of this State.

        :returns: An instance of ExtendedPublicBundle, filled with the public data of this
            State.
        """

        return self.__state.getPublicBundle()

    @property
    def republish_bundle(self):
        """
        Read, whether this State has changed since it was loaded/since this flag was last
        cleared.

        :returns: A boolean indicating, whether the public bundle data has changed since
            last reading this flag.

        Clears the flag when reading.
        """

        return self.__state.changed

    #####################
    # device management #
    #####################

    @promise.maybe_coroutine(checkSelf)
    def __loadActiveDevices(self, bare_jid):
        self.__devices_cache[bare_jid] = self.__devices_cache.get(bare_jid, {})

        if not "active" in self.__devices_cache[bare_jid]:
            devices = yield self._storage.loadActiveDevices(bare_jid)

            self.__devices_cache[bare_jid]["active"] = set(devices)

        promise.returnValue(copy.deepcopy(self.__devices_cache[bare_jid]["active"]))

    @promise.maybe_coroutine(checkSelf)
    def __loadInactiveDevices(self, bare_jid):
        self.__devices_cache[bare_jid] = self.__devices_cache.get(bare_jid, {})

        if not "inactive" in self.__devices_cache[bare_jid]:
            devices = yield self._storage.loadInactiveDevices(bare_jid)
            devices = copy.deepcopy(devices)

            self.__devices_cache[bare_jid]["inactive"] = devices

        promise.returnValue(copy.deepcopy(self.__devices_cache[bare_jid]["inactive"]))

    @promise.maybe_coroutine(checkSelf)
    def __storeActiveDevices(self, bare_jid, devices):
        self.__devices_cache[bare_jid] = self.__devices_cache.get(bare_jid, {})
        self.__devices_cache[bare_jid]["active"] = set(devices)

        yield self._storage.storeActiveDevices(
            bare_jid,
            self.__devices_cache[bare_jid]["active"]
        )

    @promise.maybe_coroutine(checkSelf)
    def __storeInactiveDevices(self, bare_jid, devices):
        self.__devices_cache[bare_jid] = self.__devices_cache.get(bare_jid, {})
        self.__devices_cache[bare_jid]["inactive"] = copy.deepcopy(devices)
        
        yield self._storage.storeInactiveDevices(
            bare_jid,
            self.__devices_cache[bare_jid]["inactive"]
        )

    @promise.maybe_coroutine(checkSelf)
    def newDeviceList(self, active_new, bare_jid):
        active_new = set(active_new)

        if bare_jid == self.__my_bare_jid:
            # The own device can never become inactive
            active_new |= set([ self.__my_device_id ])

        active_old   = yield self.__loadActiveDevices(bare_jid)
        inactive_old = yield self.__loadInactiveDevices(bare_jid)

        devices_old = active_old | set(inactive_old.keys())

        inactive_new = devices_old - active_new

        now = time.time()

        inactive_new = {
            device: inactive_old.get(device, now)
            for device in inactive_new
        }

        yield self.__storeActiveDevices(bare_jid, active_new)
        yield self.__storeInactiveDevices(bare_jid, inactive_new)

        yield self.runInactiveDeviceCleanup()

    @promise.maybe_coroutine(checkSelf)
    def getDevices(self, bare_jid = None):
        yield self.runInactiveDeviceCleanup()

        if bare_jid == None:
            bare_jid = self.__my_bare_jid

        active   = yield self.__loadActiveDevices(bare_jid)
        inactive = yield self.__loadInactiveDevices(bare_jid)

        promise.returnValue({
            "active"   : active,
            "inactive" : inactive
        })

    @promise.maybe_coroutine(checkSelf)
    def __deleteInactiveDevices(self, bare_jid, delete_devices):
        for device in delete_devices:
            yield self.__deleteSession(bare_jid, device)

        inactive_devices = yield self.__loadInactiveDevices(bare_jid)
        
        for device in delete_devices:
            inactive_devices.pop(device, None)

        yield self.__storeInactiveDevices(bare_jid, inactive_devices)

    @promise.maybe_coroutine(checkSelf)
    def deleteInactiveDevicesByQuota(self, per_jid_max = 15, global_max = 0):
        """
        Delete inactive devices by setting a quota. With per_jid_max you can define the
        amount of inactive devices that are kept for each jid, with global_max you can
        define a global maximum for inactive devices. If any of the quotas is reached,
        inactive devices are deleted on an LRU basis. This also deletes the corresponding
        sessions, so if a device comes active again and tries to send you an encrypted
        message you will not be able to decrypt it.

        The value "0" means no limitations/keep all inactive devices.

        It is recommended to always restrict the amount of per-jid inactive devices. If
        storage space limitations don't play a role, it is recommended to not restrict the
        global amount of inactive devices. Otherwise, the global_max can be used to
        control the amount of storage that can be used up by inactive sessions. The
        default of 15 per-jid devices is very permissive, but it is not recommended to
        decrease that number without a good reason.

        This is the recommended way to handle inactive device deletion. For a time-based
        alternative, look at the deleteInactiveDevicesByAge method.
        """

        if per_jid_max < 1 and global_max < 1:
            return

        if per_jid_max < 1:
            per_jid_max = None

        if global_max < 1:
            global_max = None

        bare_jids = yield self._storage.listJIDs()

        if not per_jid_max == None:
            for bare_jid in bare_jids:
                devices = yield self.__loadInactiveDevices(bare_jid)

                if len(devices) > per_jid_max:
                    # This sorts the devices from smaller to bigger timestamp, which means
                    # from old to young.
                    devices = sorted(devices.items(), key = lambda device: device[1])

                    # This gets the first (=oldest) n entries, so that only the
                    # per_jid_max youngest entries are left.
                    devices = devices[:-per_jid_max]

                    # Get the device ids and discard the timestamps.
                    devices = list(map(lambda device: device[0], devices))

                    yield self.__deleteInactiveDevices(bare_jid, devices)
        
        if not global_max == None:
            all_inactive_devices = []

            for bare_jid in bare_jids:
                devices = yield self.__loadInactiveDevices(bare_jid)

                all_inactive_devices.extend(map(
                    lambda device: (bare_jid, device[0], device[1]),
                    devices.items()
                ))

            if len(all_inactive_devices) > global_max:
                # This sorts the devices from smaller to bigger timestamp, which means
                # from old to young.
                devices = sorted(all_inactive_devices, key = lambda device: device[2])

                # This gets the first (=oldest) n entries, so that only the global_max
                # youngest entries are left.
                devices = devices[:-global_max]

                # Get the list of devices to delete for each jid
                delete_devices = {}

                for device in devices:
                    bare_jid  = device[0]
                    device_id = device[1]

                    delete_devices[bare_jid] = delete_devices.get(bare_jid, [])
                    delete_devices[bare_jid].append(device_id)

                # Now, delete the devices
                for bare_jid, devices in delete_devices.items():
                    yield self.__deleteInactiveDevices(bare_jid, devices)

    @promise.maybe_coroutine(checkSelf)
    def deleteInactiveDevicesByAge(self, age_days):
        """
        Delete all inactive devices from the device list storage and cache that are older
        then a given number of days. This also deletes the corresponding sessions, so if
        a device comes active again and tries to send you an encrypted message you will
        not be able to decrypt it. You are not allowed to delete inactive devices that
        were inactive for less than a day. Thus, the minimum value for age_days is 1.

        It is recommended to keep inactive devices for a longer period of time (e.g.
        multiple months), as it reduces the chance for message loss and doesn't require a
        lot of storage.

        The recommended alternative to deleting inactive devices by age is to delete them
        by count/quota. Look at the deleteInactiveDevicesByQuota method for that variant.
        """

        if age_days < 1:
            return

        now = time.time()

        bare_jids = yield self._storage.listJIDs()

        for bare_jid in bare_jids:
            devices = yield self.__loadInactiveDevices(bare_jid)

            delete_devices = []
            for device, timestamp in list(devices.items()):
                elapsed_s = now - timestamp
                elapsed_m = elapsed_s / 60
                elapsed_h = elapsed_m / 60
                elapsed_d = elapsed_h / 24

                if elapsed_d >= age_days:
                    delete_devices.append(device)

            if len(delete_devices) > 0:
                yield self.__deleteInactiveDevices(bare_jid, delete_devices)

    @promise.maybe_coroutine(checkSelf)
    def runInactiveDeviceCleanup(self):
        """
        Runs both the deleteInactiveDevicesByAge and the deleteInactiveDevicesByQuota
        methods with the configuration that was set when calling create.
        """

        yield self.deleteInactiveDevicesByQuota(
            self.__inactive_per_jid_max,
            self.__inactive_global_max
        )

        yield self.deleteInactiveDevicesByAge(self.__inactive_max_age)

    ######################
    # session management #
    ######################

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

    @promise.maybe_coroutine(checkSelf)
    def __deleteSession(self, bare_jid, device):
        self.__sessions_cache[bare_jid] = self.__sessions_cache.get(bare_jid, {})

        self.__sessions_cache[bare_jid].pop(device, None)

        yield self._storage.deleteSession(bare_jid, device)

    #########
    # other #
    #########

    @promise.maybe_coroutine(checkSelf)
    def deleteJID(self, bare_jid):
        """
        Delete all data associated with a JID. This includes the list of active/inactive
        devices and all sessions with that JID.
        """

        yield self.runInactiveDeviceCleanup()

        self.__sessions_cache.pop(bare_jid, None)
        self.__devices_cache.pop(bare_jid, None)

        yield self._storage.deleteJID(bare_jid)
