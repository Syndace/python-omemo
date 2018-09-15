import pytest

import logging

logging.basicConfig(level = logging.DEBUG)

import omemo
from omemo import SessionManager
from omemo.exceptions import *

import x3dh

from asyncinmemorystorage import AsyncInMemoryStorage
from syncinmemorystorage  import SyncInMemoryStorage

from deletingotpkpolicy import DeletingOTPKPolicy
from keepingotpkpolicy  import KeepingOTPKPolicy

from example_data import *
from example_data import (
    ALICE_BARE_JID     as A_JID,
    BOB_BARE_JID       as B_JID,
    CHARLIE_BARE_JID   as C_JID,
    DAVE_BARE_JID      as D_JID,
    ALICE_DEVICE_ID    as A_DID,
    BOB_DEVICE_ID      as B_DID,
    CHARLIE_DEVICE_ID  as C_DID,
    DAVE_DEVICE_ID     as D_DID,
    ALICE_DEVICE_IDS   as A_DIDS,
    BOB_DEVICE_IDS     as B_DIDS,
    CHARLIE_DEVICE_IDS as C_DIDS,
    DAVE_DEVICE_IDS    as D_DIDS
)

def assertPromiseFulfilled(promise):
    assert isinstance(promise, omemo.promise.Promise)
    assert promise.fulfilled

    return promise.value

def assertPromiseRejected(promise):
    assert isinstance(promise, omemo.promise.Promise)
    assert promise.rejected

    return promise.reason

def getDevices(sm_sync, sm_async, jid, inactive, active):
    inactive = set(inactive)
    active   = set(active)

    devices_sync  = sm_sync.getDevices(jid)
    devices_async = assertPromiseFulfilled(sm_async.getDevices(jid))

    assert devices_sync ["inactive"] == inactive
    assert devices_async["inactive"] == inactive
    assert devices_sync ["active"]   == active
    assert devices_async["active"]   == active

def newDeviceList(sm_sync, sm_async, devices, jid):
    sm_sync.newDeviceList(devices, jid)
    assertPromiseFulfilled(sm_async.newDeviceList(devices, jid))

def createSessionManagers():
    st_sync  = SyncInMemoryStorage()
    st_async = AsyncInMemoryStorage()

    sm_sync  = SessionManager.create(st_sync,  DeletingOTPKPolicy, A_JID, A_DID)
    sm_async = SessionManager.create(st_async, DeletingOTPKPolicy, A_JID, A_DID)

    assert isinstance(sm_sync, SessionManager)
    assert isinstance(assertPromiseFulfilled(sm_async), SessionManager)

    return st_sync, sm_sync, st_async, sm_async.value

def createOtherSessionManagers(jid, dids, other_dids, otpkpolicy = None):
    if otpkpolicy == None:
        otpkpolicy = DeletingOTPKPolicy

    sms_sync  = {}
    sms_async = {}

    for did in dids:
        st_sync  = SyncInMemoryStorage()
        st_async = AsyncInMemoryStorage()

        sm_sync  = SessionManager.create(st_sync,  otpkpolicy, jid, did)
        sm_async = SessionManager.create(st_async, otpkpolicy, jid, did)

        assert isinstance(sm_sync, SessionManager)
        assert isinstance(assertPromiseFulfilled(sm_async), SessionManager)

        sm_async = sm_async.value

        for other_jid in other_dids:
            newDeviceList(sm_sync, sm_async, other_dids[other_jid], other_jid)

        sms_sync[did]  = sm_sync
        sms_async[did] = sm_async
    
    return sms_sync, sms_async

def encryptMessage(
    sm_sync,
    sm_async,
    sms_sync,
    sms_async,
    jids,
    dids,
    pass_bundles,
    plaintext,
    explicit_devices,
    callback,
    dry_run = False
):
    is_single_recipient = isinstance(jids, str)

    if is_single_recipient:
        sms_sync  = { jids: sms_sync }
        sms_async = { jids: sms_async }
        dids      = { jids: dids }

        if pass_bundles != True and pass_bundles != False:
            pass_bundles = { jids: pass_bundles }

        jids = [ jids ]

    devices = None

    if explicit_devices:
        devices = dids

    bundles_sync  = None
    bundles_async = None

    if pass_bundles != False:
        bundles_sync  = {}
        bundles_async = {}

        for jid in jids:
            bundles_sync [jid] = {}
            bundles_async[jid] = {}

            bundles_to_pass = None

            if pass_bundles == True:
                bundles_to_pass = dids[jid]
            else:
                bundles_to_pass = pass_bundles[jid]

            for did in bundles_to_pass:
                bundles_sync [jid][did] = sms_sync [jid][did].public_bundle
                bundles_async[jid][did] = sms_async[jid][did].public_bundle

    actualCallback = callback

    if isinstance(callback, ErrorExpectingCallback):
        actualCallback = callback.callback

    sync_encrypted = sm_sync.encryptMessage(
        jids,
        plaintext,
        bundles  = bundles_sync,
        devices  = devices,
        callback = actualCallback,
        dry_run  = dry_run
    )

    if isinstance(callback, ErrorExpectingCallback):
        callback.next()

    async_encrypted = assertPromiseFulfilled(sm_async.encryptMessage(
        jids,
        plaintext,
        bundles  = bundles_async,
        devices  = devices,
        callback = actualCallback,
        dry_run  = dry_run
    ))

    if isinstance(callback, ErrorExpectingCallback):
        callback.done()

    return {
        "sync"  : sync_encrypted,
        "async" : async_encrypted
    }

def buildSession(sm_sync, sm_async, other_sm_sync, other_sm_async, jid, did, callback):
    actualCallback = callback

    if isinstance(callback, ErrorExpectingCallback):
        actualCallback = callback.callback

    result_sync = sm_sync.buildSession(
        jid,
        did,
        other_sm_sync.public_bundle,
        actualCallback
    )

    if isinstance(callback, ErrorExpectingCallback):
        callback.next()

    result_async = assertPromiseFulfilled(sm_async.buildSession(
        jid,
        did,
        other_sm_async.public_bundle,
        actualCallback
    ))

    if isinstance(callback, ErrorExpectingCallback):
        callback.done()


    return {
        "sync"  : result_sync,
        "async" : result_async
    }

def failingErrorCallback(error, jid, device):
    assert False

class ErrorExpectingCallback(object):
    def __init__(self, expected_errors):
        self.__original_expected_errors = expected_errors[:]

        self.__refresh()

    def callback(self, error, jid, device):
        assert len(self.__expected_errors) > 0

        expected_error = self.__expected_errors.pop(0)
        assert isinstance(error, expected_error[0])
        assert jid    == expected_error[1]
        assert device == expected_error[2]

    def __refresh(self):
        self.__expected_errors = self.__original_expected_errors[:]

    def next(self):
        self.done()
        self.__refresh()

    def done(self):
        assert len(self.__expected_errors) == 0

def decryptMessage(
    s_jid,
    r_dids,
    sms_sync,
    sms_async,
    msgs,
    plaintext,
    expect_cipher = False,
    expected_exception = None
):
    msgs_sync  = msgs["sync"]
    msgs_async = msgs["async"]

    for jid in r_dids:
        for did in r_dids[jid]:
            sm_sync  = sms_sync [jid][did]
            sm_async = sms_async[jid][did]

            msg_sync = msgs_sync["messages"]
            msg_sync = list(
                filter(lambda m: m["bare_jid"] == jid and m["rid"] == did, msg_sync)
            )

            assert len(msg_sync) == 1

            msg_sync = msg_sync[0]

            msg_async = msgs_async["messages"]
            msg_async = list(
                filter(lambda m: m["bare_jid"] == jid and m["rid"] == did, msg_async)
            )

            assert len(msg_async) == 1

            msg_async = msg_async[0]

            if expected_exception == None:
                cipher_sync, plaintext_sync = sm_sync.decryptMessage(
                    s_jid,
                    msgs_sync["sid"],
                    msgs_sync["iv"],
                    msg_sync["message"],
                    msg_sync["pre_key"],
                    msgs_sync.get("payload", None)
                )

                cipher_async, plaintext_async = assertPromiseFulfilled(
                    sm_async.decryptMessage(
                        s_jid,
                        msgs_async["sid"],
                        msgs_async["iv"],
                        msg_async["message"],
                        msg_async["pre_key"],
                        msgs_async.get("payload", None)
                    )
                )
            
                if expect_cipher:
                    assert cipher_sync  != None
                    assert cipher_async != None
                    assert plaintext_sync  == None
                    assert plaintext_async == None
                else:
                    assert cipher_sync  == None
                    assert cipher_async == None
                    assert plaintext_sync  == plaintext
                    assert plaintext_async == plaintext
            else:
                with pytest.raises(expected_exception):
                    sm_sync.decryptMessage(
                        s_jid,
                        msgs_sync["sid"],
                        msgs_sync["iv"],
                        msg_sync["message"],
                        msg_sync["pre_key"],
                        msgs_sync.get("payload", None)
                    )

                assert isinstance(assertPromiseRejected(
                    sm_async.decryptMessage(
                        s_jid,
                        msgs_async["sid"],
                        msgs_async["iv"],
                        msg_async["message"],
                        msg_async["pre_key"],
                        msgs_async.get("payload", None)
                    )
                ), expected_exception)

def messageEncryption_singleRecipient(
    expected_successes,
    callback,
    explicit_devices = False,
    pass_bundles     = True,
    pass_devices     = True,
    trusted_devices  = True
):
    st_sync, sm_sync, st_async, sm_async = createSessionManagers()

    if trusted_devices == True:
        st_sync.trust({ B_JID: B_DIDS })
        st_async.trust({ B_JID: B_DIDS })
    else:
        st_sync.trust({ B_JID: trusted_devices })
        st_async.trust({ B_JID: trusted_devices })

    if pass_devices:
        newDeviceList(sm_sync, sm_async, B_DIDS, B_JID)

    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        B_DIDS,
        { A_JID: [ A_DID ] }
    )

    plaintext = "This is a test!".encode("US-ASCII")

    encrypted_messages = encryptMessage(
        sm_sync,
        sm_async,
        b_sms_sync,
        b_sms_async,
        B_JID,
        B_DIDS,
        pass_bundles     = pass_bundles,
        plaintext        = plaintext,
        explicit_devices = explicit_devices,
        callback         = callback
    )

    decryptMessage(
        A_JID,
        { B_JID: expected_successes },
        { B_JID: b_sms_sync },
        { B_JID: b_sms_async },
        encrypted_messages,
        plaintext
    )

def test_create_supplyInfo():
    createSessionManagers()

def test_create_missingInfo():
    st_sync  = SyncInMemoryStorage()
    st_async = AsyncInMemoryStorage()

    with pytest.raises(NotInitializedException):
        sm_sync = SessionManager.create(st_sync,  DeletingOTPKPolicy)

    sm_async = SessionManager.create(st_async, DeletingOTPKPolicy)
    assert isinstance(assertPromiseRejected(sm_async), NotInitializedException)

def test_create_storedInfo():
    st_sync, _, st_async, _ = createSessionManagers()

    sm_sync  = SessionManager.create(st_sync,  DeletingOTPKPolicy)
    sm_async = SessionManager.create(st_async, DeletingOTPKPolicy)

    assert isinstance(sm_sync, SessionManager)
    assert isinstance(assertPromiseFulfilled(sm_async), SessionManager)

def test_deviceList():
    _, sm_sync, _, sm_async = createSessionManagers()

    getDevices(sm_sync, sm_async, None,  [], [ A_DID ])
    getDevices(sm_sync, sm_async, A_JID, [], [ A_DID ])
    
    newDeviceList(sm_sync, sm_async, A_DIDS, A_JID)
    getDevices(sm_sync, sm_async, A_JID, [], A_DIDS)
    
    newDeviceList(sm_sync, sm_async, A_DIDS[:2], A_JID)
    getDevices(sm_sync, sm_async, A_JID, A_DIDS[2:], A_DIDS[:2])
    
    newDeviceList(sm_sync, sm_async, [], A_JID)
    getDevices(sm_sync, sm_async, A_JID, set(A_DIDS) - set([ A_DID ]), [ A_DID ])

def test_messageEncryption_singleRecipient_implicitDevices():
    messageEncryption_singleRecipient(
        expected_successes = B_DIDS,
        callback           = failingErrorCallback
    )

def test_messageEncryption_singleRecipient_explicitDevices():
    messageEncryption_singleRecipient(
        expected_successes = B_DIDS,
        callback           = failingErrorCallback,
        explicit_devices   = True
    )

def test_messageEncryption_multipleRecipients():
    _, sm_sync, _, sm_async = createSessionManagers()

    newDeviceList(sm_sync, sm_async, B_DIDS, B_JID)
    newDeviceList(sm_sync, sm_async, C_DIDS, C_JID)

    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        B_DIDS,
        { A_JID: [ A_JID ], B_JID: B_DIDS, C_JID: C_DIDS }
    )

    c_sms_sync, c_sms_async = createOtherSessionManagers(
        C_JID,
        C_DIDS,
        { A_JID: [ A_JID ], B_JID: B_DIDS, C_JID: C_DIDS }
    )

    plaintext = "This is a test!".encode("US-ASCII")

    encrypted_messages = encryptMessage(
        sm_sync,
        sm_async,
        { B_JID: b_sms_sync,  C_JID: c_sms_sync },
        { B_JID: b_sms_async, C_JID: c_sms_async },
        [ B_JID, C_JID ],
        { B_JID: B_DIDS, C_JID: C_DIDS },
        pass_bundles     = True,
        plaintext        = plaintext,
        explicit_devices = False,
        callback         = failingErrorCallback
    )

    decryptMessage(
        A_JID,
        { B_JID: B_DIDS,      C_JID: C_DIDS },
        { B_JID: b_sms_sync,  C_JID: c_sms_sync },
        { B_JID: b_sms_async, C_JID: c_sms_async },
        encrypted_messages,
        plaintext
    )

def test_messageEncryption_implicitOwnDevices():
    a_sms_sync, a_sms_async = createOtherSessionManagers(
        A_JID,
        A_DIDS,
        { A_JID: A_DIDS, B_JID: B_DIDS }
    )

    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        B_DIDS,
        { A_JID: A_DIDS, B_JID: B_DIDS }
    )

    plaintext = "This is a test!".encode("US-ASCII")

    encrypted_messages = encryptMessage(
        a_sms_sync[A_DID],
        a_sms_async[A_DID],
        { A_JID: a_sms_sync,  B_JID: b_sms_sync },
        { A_JID: a_sms_async, B_JID: b_sms_async },
        [ A_JID, B_JID ],
        { A_JID: A_DIDS, B_JID: B_DIDS },
        pass_bundles     = True,
        plaintext        = plaintext,
        explicit_devices = False,
        callback         = failingErrorCallback
    )

    decryptMessage(
        A_JID,
        { A_JID: set(A_DIDS) - set([ A_DID ]), B_JID: B_DIDS },
        { A_JID: a_sms_sync,  B_JID: b_sms_sync },
        { A_JID: a_sms_async, B_JID: b_sms_async },
        encrypted_messages,
        plaintext
    )

def test_messageEncryption_missingBundle():
    expected_errors = [ (MissingBundleException, B_JID, did) for did in B_DIDS[2:] ]

    messageEncryption_singleRecipient(
        expected_successes = B_DIDS[:2],
        callback           = ErrorExpectingCallback(expected_errors),
        pass_bundles       = B_DIDS[:2]
    )

def test_messageEncryption_allBundlesMissing():
    expected_errors = [ (MissingBundleException, B_JID, did) for did in B_DIDS ]
    expected_errors.append((NoEligibleDevicesException, B_JID, None))

    messageEncryption_singleRecipient(
        expected_successes = [],
        callback           = ErrorExpectingCallback(expected_errors),
        pass_bundles       = []
    )

def test_messageEncryption_untrustedDevice():
    expected_errors = [ (UntrustedException, B_JID, did) for did in B_DIDS[2:] ]

    messageEncryption_singleRecipient(
        expected_successes = B_DIDS[:2],
        callback           = ErrorExpectingCallback(expected_errors),
        trusted_devices    = B_DIDS[:2]
    )

def test_messageEncryption_noTrustedDevices():
    expected_errors = [ (UntrustedException, B_JID, did) for did in B_DIDS ]
    expected_errors.append((NoEligibleDevicesException, B_JID, None))

    messageEncryption_singleRecipient(
        expected_successes = [],
        callback           = ErrorExpectingCallback(expected_errors),
        trusted_devices    = []
    )

def test_messageEncryption_noDevices():
    expected_errors = [ (NoDevicesException, B_JID, None) ]

    messageEncryption_singleRecipient(
        expected_successes = [],
        callback           = ErrorExpectingCallback(expected_errors),
        pass_devices       = False
    )

def test_buildSession():
    _, sm_sync, _, sm_async = createSessionManagers()

    newDeviceList(sm_sync, sm_async, [ B_DID ], B_JID)

    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] }
    )

    b_sm_sync  = b_sms_sync[B_DID]
    b_sm_async = b_sms_async[B_DID]

    result = buildSession(
        sm_sync,
        sm_async,
        b_sm_sync,
        b_sm_async,
        B_JID,
        B_DID,
        failingErrorCallback
    )

    decryptMessage(
        A_JID,
        { B_JID: [ B_DID ] },
        { B_JID: b_sms_sync },
        { B_JID: b_sms_async },
        result,
        plaintext = None,
        expect_cipher = True
    )

def test_decryptMessage_noSession():
    _, sm_sync, _, sm_async = createSessionManagers()

    newDeviceList(sm_sync, sm_async, [ B_DID ], B_JID)

    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] }
    )

    b_sm_sync  = b_sms_sync[B_DID]
    b_sm_async = b_sms_async[B_DID]

    result_a = buildSession(
        sm_sync,
        sm_async,
        b_sm_sync,
        b_sm_async,
        B_JID,
        B_DID,
        failingErrorCallback
    )

    assert len(result_a["sync"] ["messages"]) == 1
    assert len(result_a["async"]["messages"]) == 1
    assert result_a["sync"] ["messages"][0]["rid"] == B_DID
    assert result_a["async"]["messages"][0]["rid"] == B_DID
    assert result_a["sync"] ["messages"][0]["pre_key"]
    assert result_a["async"]["messages"][0]["pre_key"]

    plaintext = "Second message".encode("US_ASCII")

    result_b = encryptMessage(
        sm_sync,
        sm_async,
        b_sms_sync,
        b_sms_async,
        B_JID,
        [ B_DID ],
        pass_bundles     = False,
        plaintext        = plaintext,
        explicit_devices = False,
        callback         = failingErrorCallback
    )

    assert len(result_b["sync"] ["messages"]) == 1
    assert len(result_b["async"]["messages"]) == 1
    assert result_b["sync"] ["messages"][0]["rid"] == B_DID
    assert result_b["async"]["messages"][0]["rid"] == B_DID
    assert not result_b["sync"] ["messages"][0]["pre_key"]
    assert not result_b["async"]["messages"][0]["pre_key"]

    decryptMessage(
        A_JID,
        { B_JID: [ B_DID ] },
        { B_JID: b_sms_sync },
        { B_JID: b_sms_async },
        result_b,
        plaintext,
        expected_exception = NoSessionException
    )

def otpkPolicyTest(otpkpolicy, expect_exception):
    _, sm_sync, _, sm_async = createSessionManagers()

    newDeviceList(sm_sync, sm_async, [ B_DID ], B_JID)

    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] },
        otpkpolicy = otpkpolicy
    )

    b_sm_sync  = b_sms_sync[B_DID]
    b_sm_async = b_sms_async[B_DID]

    result = buildSession(
        sm_sync,
        sm_async,
        b_sm_sync,
        b_sm_async,
        B_JID,
        B_DID,
        failingErrorCallback
    )

    decryptMessage(
        A_JID,
        { B_JID: [ B_DID ] },
        { B_JID: b_sms_sync },
        { B_JID: b_sms_async },
        result,
        plaintext = None,
        expect_cipher = True
    )

    expected_exception = None

    if expect_exception:
        expected_exception = x3dh.exceptions.KeyExchangeException

    decryptMessage(
        A_JID,
        { B_JID: [ B_DID ] },
        { B_JID: b_sms_sync },
        { B_JID: b_sms_async },
        result,
        plaintext = None,
        expect_cipher = True,
        expected_exception = expected_exception
    )

def test_otpkPolicy_default():
    pass#assert False

def test_otpkPolicy_deleting():
    otpkPolicyTest(DeletingOTPKPolicy, True)

def test_otpkPolicy_keeping():
    otpkPolicyTest(KeepingOTPKPolicy, False)

def test_dryRun():
    st_sync, sm_sync, st_async, sm_async = createSessionManagers()

    st_sync.trust({  B_JID: B_DIDS[1:] })
    st_async.trust({ B_JID: B_DIDS[1:] })

    newDeviceList(sm_sync, sm_async, B_DIDS, B_JID)

    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        B_DIDS,
        { A_JID: [ A_DID ] }
    )

    plaintext = "This is a test!".encode("US-ASCII")

    expected_errors = [
        (UntrustedException,     B_JID, B_DIDS[0]),
        (MissingBundleException, B_JID, B_DIDS[2])
    ]

    before_dry_run_sync  = st_sync.dump()
    before_dry_run_async = st_async.dump()

    encrypted_messages = encryptMessage(
        sm_sync,
        sm_async,
        b_sms_sync,
        b_sms_async,
        B_JID,
        B_DIDS,
        pass_bundles     = B_DIDS[:2],
        plaintext        = plaintext,
        explicit_devices = False,
        callback         = ErrorExpectingCallback(expected_errors),
        dry_run          = True
    )

    after_dry_run_sync  = st_sync.dump()
    after_dry_run_async = st_async.dump()

    assert before_dry_run_sync  == after_dry_run_sync
    assert before_dry_run_async == after_dry_run_async

    encrypted_messages = encryptMessage(
        sm_sync,
        sm_async,
        b_sms_sync,
        b_sms_async,
        B_JID,
        B_DIDS,
        pass_bundles     = B_DIDS[:2],
        plaintext        = plaintext,
        explicit_devices = False,
        callback         = ErrorExpectingCallback(expected_errors),
        dry_run          = False
    )

    decryptMessage(
        A_JID,
        { B_JID: [ B_DIDS[1] ] },
        { B_JID: b_sms_sync },
        { B_JID: b_sms_async },
        encrypted_messages,
        plaintext
    )

    after_normal_run_sync  = st_sync.dump()
    after_normal_run_async = st_async.dump()

    assert not after_dry_run_sync  == after_normal_run_sync
    assert not after_dry_run_async == after_normal_run_async
