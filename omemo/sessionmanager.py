from __future__ import absolute_import
from __future__ import division

import base64
import copy
import logging
import os
import sys
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import promise
from . import storagewrapper
from .exceptions import *
from .extendeddoubleratchet import make as make_ExtendedDoubleRatchet
from .x3dhdoubleratchet import make as make_X3DHDoubleRatchet

import x3dh

# This makes me sad
if sys.version_info[0] == 3:
    string_type = str
else:
    string_type = basestring

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
        inactive_global_max  =  0,
        inactive_max_age     =  0
    ):
        self = cls()

        # Store the parameters
        self._storage = storagewrapper.StorageWrapper(storage)

        self.__otpk_policy = otpk_policy

        self.__backend = backend
        self.__X3DHDoubleRatchet = make_X3DHDoubleRatchet(self.__backend)
        self.__ExtendedDoubleRatchet = make_ExtendedDoubleRatchet(self.__backend)

        self.__my_bare_jid  = my_bare_jid
        self.__my_device_id = my_device_id

        self.__inactive_per_jid_max = inactive_per_jid_max
        self.__inactive_global_max  = inactive_global_max
        self.__inactive_max_age     = inactive_max_age

        # Prepare the caches
        self.__state = None

        self.__sessions_cache = {}
        self.__devices_cache  = {}
        self.__trust_cache    = {}

        yield self.__prepare()

        promise.returnValue(self)

    @promise.maybe_coroutine(checkSelf)
    def __prepare(self):
        state = yield self._storage.loadState()
        if state == None:
            self.__state = self.__X3DHDoubleRatchet()

            yield self._storage.storeState(self.__state.serialize())

            yield self.__storeActiveDevices(self.__my_bare_jid, [ self.__my_device_id ])
        else:
            self.__state = self.__X3DHDoubleRatchet.fromSerialized(state)

        own_data = yield self._storage.loadOwnData()
        if own_data == None:
            yield self._storage.storeOwnData(self.__my_bare_jid, self.__my_device_id)
        else:
            if (not self.__my_bare_jid  == own_data["own_bare_jid"] or
                not self.__my_device_id == own_data["own_device_id"]):
                raise InconsistentInfoException(
                    "Given storage is only usable for jid {} on device {}."
                    .format(own_data["own_bare_jid"], own_data["own_device_id"])
                )

    ##############
    # encryption #
    ##############

    @promise.maybe_coroutine(checkSelf)
    def encryptMessage(
        self,
        bare_jids,
        plaintext,
        bundles = None,
        expect_problems = None
    ):
        # Dirty hack to access ciphertext from _encryptMessage
        ciphertext = []

        def _encryptMessage(aes_gcm):
            ciphertext.append(aes_gcm.update(plaintext) + aes_gcm.finalize())

        encrypted = yield self.encryptKeyTransportMessage(
            bare_jids,
            _encryptMessage,
            bundles,
            expect_problems
        )

        encrypted["payload"] = ciphertext[0]

        promise.returnValue(encrypted)

    @promise.maybe_coroutine(checkSelf)
    def encryptRatchetForwardingMessage(
        self,
        bare_jids,
        bundles = None,
        expect_problems = None
    ):
        encrypted = yield self.encryptKeyTransportMessage(
            bare_jids,
            lambda aes_gcm: aes_gcm.finalize(),
            bundles,
            expect_problems
        )

        promise.returnValue(encrypted)

    @promise.maybe_coroutine(checkSelf)
    def encryptKeyTransportMessage(
        self,
        bare_jids,
        encryption_callback,
        bundles = None,
        expect_problems = None
    ):
        """
        bare_jids: iterable<string>
        encryption_callback: A function which is called using an instance of cryptography.hazmat.primitives.ciphers.CipherContext, which you can use to encrypt any sort of data. You don't have to return anything.
        bundles: { [bare_jid: string] => { [device_id: int] => ExtendedPublicBundle } }
        expect_problems: { [bare_jid: string] => iterable<int> }

        returns: {
            iv: bytes,
            sid: int,
            keys: {
                [bare_jid: string] => {
                    [device: int] => {
                        "data"    : bytes,
                        "pre_key" : boolean
                    }
                }
            }
        }
        """

        yield self.runInactiveDeviceCleanup()

        #########################
        # parameter preparation #
        #########################

        if isinstance(bare_jids, string_type):
            bare_jids = set([ bare_jids ])
        else:
            bare_jids = set(bare_jids)

        if bundles == None:
            bundles = {}

        if expect_problems == None:
            expect_problems = {}
        else:
            for bare_jid in expect_problems:
                expect_problems[bare_jid] = set(expect_problems[bare_jid])

        # Add the own bare jid to the set of jids
        bare_jids.add(self.__my_bare_jid)

        ########################################################
        # check all preconditions and prepare missing sessions #
        ########################################################

        problems = []

        # Prepare the lists of devices to encrypt for
        encrypt_for = {}

        for bare_jid in bare_jids:
            devices = yield self.__loadActiveDevices(bare_jid)

            if len(devices) == 0:
                problems.append(NoDevicesException(bare_jid))
            else:
                encrypt_for[bare_jid] = devices

        # Remove the sending devices from the list
        encrypt_for[self.__my_bare_jid].remove(self.__my_device_id)

        # Check whether all required bundles are available
        for bare_jid, devices in encrypt_for.items():
            missing_bundles = set()

            for device in devices:
                session = yield self.__loadSession(bare_jid, device)

                if session == None:
                    if not device in bundles.get(bare_jid, {}):
                        missing_bundles.add(device)

            devices -= missing_bundles

            for device in missing_bundles:
                if not device in expect_problems.get(bare_jid, set()):
                    problems.append(MissingBundleException(bare_jid, device))

        # Check for missing sessions and simulate the key exchange
        for bare_jid, devices in encrypt_for.items():
            key_exchange_problems = {}

            for device in devices:
                # Load the session
                session = yield self.__loadSession(bare_jid, device)

                # If no session exists, create a new session
                if session == None:
                    # Get the required bundle
                    bundle = bundles[bare_jid][device]

                    try:
                        # Build the session, discarding the result afterwards. This is
                        # just to check that the key exchange works.
                        self.__state.getSharedSecretActive(bundle)
                    except x3dh.exceptions.KeyExchangeException as e:
                        key_exchange_problems[device] = str(e)

            encrypt_for[bare_jid] -= set(key_exchange_problems.keys())

            for device, message in key_exchange_problems.items():
                if not device in expect_problems.get(bare_jid, set()):
                    problems.append(KeyExchangeException(
                        bare_jid,
                        device,
                        message
                    ))

        # Check the trust for each device
        for bare_jid, devices in encrypt_for.items():
            untrusted = []

            for device in devices:
                # Load the session
                session = yield self.__loadSession(bare_jid, device)

                # Get the identity key of the recipient
                other_ik = bundles[bare_jid][device].ik if session == None else session.ik

                if not (yield self.__checkTrust(bare_jid, device, other_ik)):
                    untrusted.append((device, other_ik))

            devices -= set(map(lambda x: x[0], untrusted))

            for device, other_ik in untrusted:
                if not device in expect_problems.get(bare_jid, set()):
                    problems.append(UntrustedException(bare_jid, device, other_ik))

        # Check for jids with no eligible devices
        for bare_jid, devices in list(encrypt_for.items()):
            # Skip this check for my own bare jid
            if bare_jid == self.__my_bare_jid:
                continue

            if len(devices) == 0:
                problems.append(NoEligibleDevicesException(bare_jid))
                del encrypt_for[bare_jid]

        # If there were and problems, raise an Exception with a list of those.
        if len(problems) > 0:
            raise EncryptionProblemsException(problems)

        ##############
        # encryption #
        ##############

        # Prepare AES-GCM key and IV
        aes_gcm_iv  = os.urandom(16)
        aes_gcm_key = os.urandom(16)

        # Create the AES-GCM instance
        aes_gcm = Cipher(
            algorithms.AES(aes_gcm_key),
            modes.GCM(aes_gcm_iv),
            backend=default_backend()
        ).encryptor()

        # Encrypt the plain data
        encryption_callback(aes_gcm)

        # Store the tag
        aes_gcm_tag = aes_gcm.tag

        # {
        #     [bare_jid: string] => {
        #         [device: int] => {
        #             "data"    : bytes,
        #             "pre_key" : boolean
        #         }
        #     }
        # }
        encrypted_keys = {}

        for bare_jid, devices in encrypt_for.items():
            encrypted_keys[bare_jid] = {}

            for device in devices:
                # Note whether this is a response to a PreKeyMessage
                if self.__state.hasBoundOTPK(bare_jid, device):
                    self.__state.respondedTo(bare_jid, device)
                    yield self._storage.storeState(self.__state.serialize())

                # Load the session
                session = yield self.__loadSession(bare_jid, device)

                # If no session exists, this will be a PreKeyMessage
                pre_key = session == None

                # Create a new session                
                if pre_key:
                    # Get the required bundle
                    bundle = bundles[bare_jid][device]

                    # Build the session
                    session_and_init_data = self.__state.getSharedSecretActive(bundle)
                    
                    session = session_and_init_data["dr"]
                    session_init_data = session_and_init_data["to_other"]

                # Encrypt the AES GCM key and tag
                encrypted_data = session.encryptMessage(aes_gcm_key + aes_gcm_tag)

                # Store the new/changed session
                yield self.__storeSession(bare_jid, device, session)

                # Serialize the data into a simple message format
                serialized = self.__backend.WireFormat.messageToWire(
                    encrypted_data["ciphertext"],
                    encrypted_data["header"],
                    { "DoubleRatchet": encrypted_data["additional"] }
                )

                # If it is a PreKeyMessage, apply an additional step to the serialization.
                if pre_key:
                    serialized = self.__backend.WireFormat.preKeyMessageToWire(
                        session_init_data,
                        serialized,
                        { "DoubleRatchet": encrypted_data["additional"] }
                    )

                # Add the final encrypted and serialized data.
                encrypted_keys[bare_jid][device] = {
                    "data"    : serialized,
                    "pre_key" : pre_key
                }

        promise.returnValue({
            "iv"   : aes_gcm_iv,
            "sid"  : self.__my_device_id,
            "keys" : encrypted_keys
        })

    ##############
    # decryption #
    ##############

    @promise.maybe_coroutine(checkSelf)
    def decryptMessage(
        self,
        bare_jid,
        device,
        iv,
        message,
        is_pre_key_message,
        ciphertext,
        additional_information = None,
        allow_untrusted = False
    ):
        aes_gcm = yield self.decryptKeyTransportMessage(
            bare_jid,
            device,
            iv,
            message,
            is_pre_key_message,
            additional_information,
            allow_untrusted
        )

        promise.returnValue(aes_gcm.update(ciphertext) + aes_gcm.finalize())

    @promise.maybe_coroutine(checkSelf)
    def decryptRatchetForwardingMessage(
        self,
        bare_jid,
        device,
        iv,
        message,
        is_pre_key_message,
        additional_information = None,
        allow_untrusted = False
    ):
        aes_gcm = yield self.decryptKeyTransportMessage(
            bare_jid,
            device,
            iv,
            message,
            is_pre_key_message,
            additional_information,
            allow_untrusted
        )

        aes_gcm.finalize()

    @promise.maybe_coroutine(checkSelf)
    def decryptKeyTransportMessage(
        self,
        bare_jid,
        device,
        iv,
        message,
        is_pre_key_message,
        additional_information = None,
        allow_untrusted = False
    ):
        yield self.runInactiveDeviceCleanup()

        if is_pre_key_message:
            # Unpack the pre key message data
            message_and_init_data = self.__backend.WireFormat.preKeyMessageFromWire(
                message
            )

            other_ik = message_and_init_data["session_init_data"]["ik"]

            # Before doing anything else, check the trust
            if not allow_untrusted:
                if not (yield self.__checkTrust(bare_jid, device, other_ik)):
                    raise UntrustedException(bare_jid, device, other_ik)

            # Prepare the DoubleRatchet
            try:
                session = self.__state.getSharedSecretPassive(
                    message_and_init_data["session_init_data"],
                    bare_jid,
                    device,
                    self.__otpk_policy,
                    additional_information
                )
            except x3dh.exceptions.KeyExchangeException as e:
                raise KeyExchangeException(bare_jid, device, str(e))

            # Store the changed state
            yield self._storage.storeState(self.__state.serialize())

            # Store the new session
            yield self.__storeSession(bare_jid, device, session)

            # Unpack the "normal" message that was wrapped into the PreKeyMessage
            message = message_and_init_data["message"]

        # Load the session
        session = yield self.__loadSession(bare_jid, device)
        if session == None:
            raise NoSessionException(bare_jid, device)

        # Before doing anything else, check the trust
        if not allow_untrusted:
            if not (yield self.__checkTrust(bare_jid, device, session.ik)):
                raise UntrustedException(bare_jid, device, session.ik)

        # Now that the trust was checked, go on with normal processing
        if not is_pre_key_message:
            # If this is not part of a PreKeyMessage, we received a normal Message and can
            # safely delete the OTPK bound to this bare_jid+device.
            self.__state.deleteBoundOTPK(bare_jid, device)
            yield self._storage.storeState(self.__state.serialize())

        # Unpack the message data
        message_data = self.__backend.WireFormat.messageFromWire(message)

        # Get the concatenation of the AES GCM key and tag
        plaintext = session.decryptMessage(
            message_data["ciphertext"],
            message_data["header"]
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
        yield self.__storeSession(bare_jid, device, session)

        plaintext = plaintext["plaintext"]

        aes_gcm_key = plaintext[:16]
        aes_gcm_tag = plaintext[16:]

        promise.returnValue(Cipher(
            algorithms.AES(aes_gcm_key),
            modes.GCM(iv, aes_gcm_tag),
            backend=default_backend()
        ).decryptor())

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

    ######################
    # session management #
    ######################

    @promise.maybe_coroutine(checkSelf)
    def __loadSession(self, bare_jid, device):
        self.__sessions_cache[bare_jid] = self.__sessions_cache.get(bare_jid, {})

        if not (device in self.__sessions_cache[bare_jid]):
            session = yield self._storage.loadSession(bare_jid, device)

            if not session == None:
                session = self.__ExtendedDoubleRatchet.fromSerialized(session, None)

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

        yield self._storage.storeActiveDevices(bare_jid, devices)

    @promise.maybe_coroutine(checkSelf)
    def __storeInactiveDevices(self, bare_jid, devices):
        self.__devices_cache[bare_jid] = self.__devices_cache.get(bare_jid, {})
        self.__devices_cache[bare_jid]["inactive"] = copy.deepcopy(devices)
        
        yield self._storage.storeInactiveDevices(bare_jid, devices)

    @promise.maybe_coroutine(checkSelf)
    def newDeviceList(self, bare_jid, active_new):
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

    ####################
    # trust management #
    ####################

    @promise.maybe_coroutine(checkSelf)
    def __loadTrust(self, bare_jid, device):
        self.__trust_cache[bare_jid] = self.__trust_cache.get(bare_jid, {})

        if not device in self.__trust_cache[bare_jid]:
            trust = yield self._storage.loadTrust(bare_jid, device)

            self.__trust_cache[bare_jid][device] = None if trust == None else {
                "key"     : base64.b64decode(trust["key"].encode("US-ASCII")),
                "trusted" : trust["trusted"]
            }

        promise.returnValue(copy.deepcopy(self.__trust_cache[bare_jid][device]))

    @promise.maybe_coroutine(checkSelf)
    def __storeTrust(self, bare_jid, device, trust):
        self.__trust_cache[bare_jid] = self.__trust_cache.get(bare_jid, {})
        self.__trust_cache[bare_jid][device] = copy.deepcopy(trust)

        yield self._storage.storeTrust(
            bare_jid,
            device,
            {
                "key"     : base64.b64encode(trust["key"]).decode("US-ASCII"),
                "trusted" : trust["trusted"]
            }
        )

    @promise.maybe_coroutine(checkSelf)
    def __checkTrust(self, bare_jid, device, key):
        trust = yield self.__loadTrust(bare_jid, device)

        if trust == None:
            promise.returnValue(False)

        if not trust["key"] == key:
            promise.returnValue(False)

        promise.returnValue(trust["trusted"])

    @promise.maybe_coroutine(checkSelf)
    def trust(self, bare_jid, device, key):
        yield self.__storeTrust(bare_jid, device, {
            "key"     : key,
            "trusted" : True
        })

    @promise.maybe_coroutine(checkSelf)
    def distrust(self, bare_jid, device, key):
        yield self.__storeTrust(bare_jid, device, {
            "key"     : key,
            "trusted" : False
        })

    def getTrustForDevice(self, bare_jid, device):
        """
        Get trust information for a single device.
        The result is structured like this:

        {
            "key"     : a bytes-like object encoding the public key,
            "trusted" : boolean
        }

        or None, if no trust was stored for that device.
        """

        return self.__loadTrust(bare_jid, device)

    @promise.maybe_coroutine(checkSelf)
    def getTrustForJID(self, bare_jid):
        """
        All-in-one trust information for all devices of a bare jid.
        The result is structured like this:

        {
            "active"   : { device: int => trust_info }
            "inactive" : { device: int => trust_info }
        }

        where trust_info is the structure returned by getTrustForDevice.
        """

        result = {
            "active"   : {},
            "inactive" : {}
        }

        devices = yield self.__loadActiveDevices(bare_jid)

        for device in devices:
            result["active"][device] = yield self.getTrustForDevice(bare_jid, device)

        devices = yield self.__loadInactiveDevices(bare_jid)

        for device in devices:
            result["inactive"][device] = yield self.getTrustForDevice(bare_jid, device)

        promise.returnValue(result)

    #########
    # other #
    #########

    @promise.maybe_coroutine(checkSelf)
    def deleteJID(self, bare_jid):
        """
        Delete all data associated with a JID. This includes the list of active/inactive
        devices, all sessions with that JID and all information about trusted keys.
        """

        yield self.runInactiveDeviceCleanup()

        self.__sessions_cache.pop(bare_jid, None)
        self.__devices_cache.pop(bare_jid, None)
        self.__trust_cache.pop(bare_jid, None)

        yield self._storage.deleteJID(bare_jid)
