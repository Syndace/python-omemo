import pytest

import logging

logging.basicConfig(level = logging.DEBUG)

import omemo
from omemo import SessionManager
from omemo.exceptions import *

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
    ALICE_BARE_JID     as A_JID,
    ALICE_DEVICE_ID    as A_DID,
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

def createOtherSessionManagers(jid, dids, other_dids):
    sms_sync  = {}
    sms_async = {}

    for did in dids:
        st_sync  = SyncInMemoryStorage()
        st_async = AsyncInMemoryStorage()

        sm_sync  = SessionManager.create(st_sync,  DeletingOTPKPolicy, jid, did)
        sm_async = SessionManager.create(st_async, DeletingOTPKPolicy, jid, did)

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
    callback
):
    is_single_recipient = isinstance(jids, str)

    if is_single_recipient:
        sms_sync  = { jids: sms_sync }
        sms_async = { jids: sms_async }
        dids      = { jids: dids }
        jids      = [ jids ]

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
                bundles_to_pass = pass_bundles

            for did in bundles_to_pass:
                bundles_sync [jid][did] = sms_sync [jid][did].public_bundle
                bundles_async[jid][did] = sms_async[jid][did].public_bundle

    sync_encrypted = sm_sync.encryptMessage(
        jids,
        plaintext,
        bundles  = bundles_sync,
        devices  = devices,
        callback = callback
    )

    async_encrypted = assertPromiseFulfilled(sm_async.encryptMessage(
        jids,
        plaintext,
        bundles  = bundles_async,
        devices  = devices,
        callback = callback
    ))

    return {
        "sync"  : sync_encrypted,
        "async" : async_encrypted
    }

def failingErrorCallback(error, jid, device):
    assert False

class ErrorExpectingCallback(object):
    def __init__(self, expected_errors):
        self.__expected_errors = expected_errors[:]

    def callback(self, error, jid, device):
        assert len(self.__expected_errors) > 0

        expected_error = self.__expected_errors.pop(0)
        assert isinstance(error, expected_error[0])
        assert jid    == expected_error[1]
        assert device == expected_error[2]

    def done(self):
        assert len(self.__expected_errors) == 0

def decryptMessage(s_jid, r_dids, sms_sync, sms_async, msgs, plaintext):
    msgs_sync  = msgs["sync"]
    msgs_async = msgs["async"]

    for jid in r_dids:
        for did in r_dids[jid]:
            sm_sync  = sms_sync [jid][did]
            sm_async = sms_async[jid][did]

            msg = msgs_sync["messages"]
            msg = list(filter(lambda m: m["bare_jid"] == jid and m["rid"] == did, msg))

            assert len(msg) == 1

            msg = msg[0]

            cipher_sync, plaintext_sync = sm_sync.decryptMessage(
                s_jid,
                msgs_sync["sid"],
                msgs_sync["iv"],
                msg["message"],
                msg["pre_key"],
                msgs_sync["payload"]
            )

            msg = msgs_async["messages"]
            msg = list(filter(lambda m: m["bare_jid"] == jid and m["rid"] == did, msg))

            assert len(msg) == 1

            msg = msg[0]

            cipher_async, plaintext_async = assertPromiseFulfilled(
                sm_async.decryptMessage(
                    s_jid,
                    msgs_async["sid"],
                    msgs_async["iv"],
                    msg["message"],
                    msg["pre_key"],
                    msgs_async["payload"]
                )
            )
        
            assert cipher_sync  == None
            assert cipher_async == None
            assert plaintext_sync  == plaintext
            assert plaintext_async == plaintext

def messageEncryption_singleRecipient(
    explicit_devices,
    pass_bundles,
    expected_successes,
    callback
):
    _, sm_sync, _, sm_async = createSessionManagers()

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
        explicit_devices   = False,
        pass_bundles       = True,
        expected_successes = B_DIDS,
        callback           = failingErrorCallback
    )

def test_messageEncryption_singleRecipient_explicitDevices():
    messageEncryption_singleRecipient(
        explicit_devices   = True,
        pass_bundles       = True,
        expected_successes = B_DIDS,
        callback           = failingErrorCallback
    )

def test_messageEncryption_multipleRecipients():
    pass#assert False

def test_messageEncryption_implicitOwnDevices():
    pass#assert False

def test_messageEncryption_missingBundle():
    expected_errors = []

    # Once for the sync call and once for the async one.
    for _ in range(2):
        for did in B_DIDS[2:]:
            expected_errors.append((MissingBundleException, B_JID, did))

    errorExpectingCallback = ErrorExpectingCallback(expected_errors)

    messageEncryption_singleRecipient(
        explicit_devices   = False,
        pass_bundles       = B_DIDS[:2],
        expected_successes = B_DIDS[:2],
        callback           = errorExpectingCallback.callback
    )

    errorExpectingCallback.done()

def test_messageEncryption_untrustedDevice():
    pass#assert False

def test_messageEncryption_noTrustedDevices():
    pass#assert False

def test_messageEncryption_noDevices():
    pass#assert False

def test_buildSession():
    pass#assert False

def test_listMissingBundles():
    pass#assert False

def test_decryptMessage_noSession():
    pass#assert False

def test_DeletingOTPKPolicy():
    pass#assert False

def test_KeepingOTPKPolicy():
    pass#assert False
