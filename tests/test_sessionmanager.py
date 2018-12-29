import pytest

import logging
import os

logging.basicConfig(level = logging.DEBUG)

import omemo
from omemo import SessionManager
from omemo.exceptions import *

from omemo_backend_signal import BACKEND as SignalBackend

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

def assertPromiseFulfilledOrRaise(promise):
    assert isinstance(promise, omemo.promise.Promise)

    assert promise.done

    if promise.fulfilled:
        return promise.value

    raise promise.reason

def assertPromiseRejected(promise):
    assert isinstance(promise, omemo.promise.Promise)
    assert promise.rejected

    return promise.reason

def overrideOwnData(st_sync, st_async, jid, did):
    done = False

    def cb(success, value):
        assert success
        done = True

    st_sync.storeOwnData(None, jid, did)
    st_async.storeOwnData(cb, jid, did)
    
    while not cb: pass

def getDevices(sm_sync, sm_async, jid, inactive, active):
    inactive = set(inactive)
    active   = set(active)

    devices_sync  = sm_sync.getDevices(jid)
    devices_async = assertPromiseFulfilled(sm_async.getDevices(jid))

    assert set(devices_sync ["inactive"].keys()) == inactive
    assert set(devices_async["inactive"].keys()) == inactive
    assert devices_sync ["active"] == active
    assert devices_async["active"] == active

def newDeviceList(sm_sync, sm_async, jid, devices):
    sm_sync.newDeviceList(jid, devices)
    assertPromiseFulfilled(sm_async.newDeviceList(jid, devices))

def createSessionManagers(st_sync = None, st_async = None, expect = None):
    if st_sync == None:
        st_sync = SyncInMemoryStorage()

    if st_async == None:
        st_async = AsyncInMemoryStorage()

    try:
        sm_sync = SessionManager.create(
            st_sync,
            DeletingOTPKPolicy,
            SignalBackend,
            A_JID,
            A_DID
        )
    except Exception as e:
        assert expect != None
        assert isinstance(e, expect)

    sm_async_promise = SessionManager.create(
        st_async,
        DeletingOTPKPolicy,
        SignalBackend,
        A_JID,
        A_DID
    )

    if expect == None:
        sm_async = assertPromiseFulfilled(sm_async_promise)
    else:
        assert isinstance(assertPromiseRejected(sm_async_promise), expect)

    if expect == None:
        assert isinstance(sm_sync,  SessionManager)
        assert isinstance(sm_async, SessionManager)

        return st_sync, sm_sync, st_async, sm_async

def createOtherSessionManagers(jid, dids, other_dids, otpk_policy = None):
    if otpk_policy == None:
        otpk_policy = DeletingOTPKPolicy

    sms_sync  = {}
    sms_async = {}

    for did in dids:
        st_sync  = SyncInMemoryStorage()
        st_async = AsyncInMemoryStorage()

        sm_sync  = SessionManager.create(st_sync, otpk_policy, SignalBackend, jid, did)
        sm_async = assertPromiseFulfilled(SessionManager.create(
            st_async,
            otpk_policy,
            SignalBackend,
            jid,
            did
        ))

        assert isinstance(sm_sync,  SessionManager)
        assert isinstance(sm_async, SessionManager)

        for other_jid in other_dids:
            newDeviceList(sm_sync, sm_async, other_jid, other_dids[other_jid])

        sms_sync[did]  = sm_sync
        sms_async[did] = sm_async
    
    return sms_sync, sms_async

def trust(sm_sync, sm_async, sms_sync, sms_async, jid_to_trust, devices_to_trust):
    try:
        for device in devices_to_trust:
            ik_sync  = sms_sync [device].public_bundle.ik
            ik_async = sms_async[device].public_bundle.ik

            sm_sync.trust(jid_to_trust, device, ik_sync)
            assertPromiseFulfilled(sm_async.trust(jid_to_trust, device, ik_async))
    except TypeError:
        ik_sync  = sms_sync .public_bundle.ik
        ik_async = sms_async.public_bundle.ik

        sm_sync.trust(jid_to_trust, devices_to_trust, ik_sync)
        assertPromiseFulfilled(sm_async.trust(jid_to_trust, devices_to_trust, ik_async))

def distrust(sm_sync, sm_async, sms_sync, sms_async, jid_to_trust, devices_to_trust):
    try:
        for device in devices_to_trust:
            ik_sync  = sms_sync [device].public_bundle.ik
            ik_async = sms_async[device].public_bundle.ik

            sm_sync.distrust(jid_to_trust, device, ik_sync)
            assertPromiseFulfilled(sm_async.distrust(jid_to_trust, device, ik_async))
    except TypeError:
        ik_sync  = sms_sync .public_bundle.ik
        ik_async = sms_async.public_bundle.ik

        sm_sync.distrust(jid_to_trust, devices_to_trust, ik_sync)
        assertPromiseFulfilled(sm_async.distrust(
            jid_to_trust,   
            devices_to_trust,
            ik_async
        ))

def messageEncryption(
    pass_bundles      = None,
    trust_devices     = None,
    pass_devices      = True,
    expect_problems   = None,
    expected_problems = None,
    trust_alice       = True,
    allow_untrusted_decryption = False,
    expect_untrusted_decryption = False
):
    if pass_bundles == None:
        pass_bundles = set(B_DIDS)
    else:
        pass_bundles = set(pass_bundles)

    if trust_devices == None:
        trust_devices = set(B_DIDS)
    else:
        trust_devices = set(trust_devices)

    if expect_problems == None:
        expect_problems = set()
    else:
        expect_problems = set(expect_problems)

    st_sync, sm_sync, st_async, sm_async = createSessionManagers()
    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        B_DIDS,
        { A_JID: [ A_DID ] }
    )

    if pass_devices:
        newDeviceList(sm_sync, sm_async, B_JID, B_DIDS)

    trust(sm_sync, sm_async, b_sms_sync, b_sms_async, B_JID, trust_devices)

    if trust_alice:
        for b_did in B_DIDS:
            trust(b_sms_sync[b_did], b_sms_async[b_did], sm_sync, sm_async, A_JID, A_DID)

    bundles_sync = {
        did: b_sms_sync[did].public_bundle
        for did in B_DIDS
        if did in pass_bundles
    }

    bundles_async = {
        did: b_sms_async[did].public_bundle
        for did in B_DIDS
        if did in pass_bundles
    }

    problems_sync  = []
    problems_async = []

    msg = "single message".encode("UTF-8")

    try:
        encrypted_sync = sm_sync.encryptMessage(
            [ B_JID ],
            msg,
            { B_JID: bundles_sync },
            { B_JID: expect_problems }
        )
    except EncryptionProblemsException as e:
        problems_sync = e.problems

    try:
        encrypted_async = assertPromiseFulfilledOrRaise(sm_async.encryptMessage(
            [ B_JID ],
            msg,
            { B_JID: bundles_async },
            { B_JID: expect_problems }
        ))
    except EncryptionProblemsException as e:
        problems_async = e.problems

    if expected_problems == None:
        successes_sync  = set(encrypted_sync ["keys"][B_JID].keys())
        successes_async = set(encrypted_async["keys"][B_JID].keys())

        expected_successes = set(B_DIDS) - expect_problems

        assert expected_successes == successes_sync == successes_async

        for did in expected_successes:
            try:
                # Check that the pre_key flag is set correctly
                expect_pre_key = did in bundles_sync
                assert encrypted_sync["keys"][B_JID][did]["pre_key"] == expect_pre_key

                decrypted_sync = b_sms_sync[did].decryptMessage(
                    A_JID,
                    A_DID,
                    encrypted_sync["iv"],
                    encrypted_sync["keys"][B_JID][did]["data"],
                    encrypted_sync["keys"][B_JID][did]["pre_key"],
                    encrypted_sync["payload"],
                    allow_untrusted = allow_untrusted_decryption
                )

                assert not expect_untrusted_decryption
            except UntrustedException as e:
                assert expect_untrusted_decryption
                assert e == UntrustedException(A_JID, A_DID, sm_sync.public_bundle.ik)

            try:
                # Check that the pre_key flag is set correctly
                expect_pre_key = did in bundles_async
                assert encrypted_async["keys"][B_JID][did]["pre_key"] == expect_pre_key

                decrypted_async = assertPromiseFulfilledOrRaise(
                    b_sms_async[did].decryptMessage(
                        A_JID,
                        A_DID,
                        encrypted_async["iv"],
                        encrypted_async["keys"][B_JID][did]["data"],
                        encrypted_async["keys"][B_JID][did]["pre_key"],
                        encrypted_async["payload"],
                        allow_untrusted = allow_untrusted_decryption
                    )
                )

                assert not expect_untrusted_decryption
            except UntrustedException as e:
                assert expect_untrusted_decryption
                assert e == UntrustedException(A_JID, A_DID, sm_async.public_bundle.ik)

            if not expect_untrusted_decryption:
                assert decrypted_sync == decrypted_async == msg
    else:
        assert len(problems_sync) == len(problems_async) == len(expected_problems)

        zipped = zip(problems_sync, problems_async, expected_problems)

        for problem_sync, problem_async, problem_expected in zipped:
            if isinstance(problem_expected, UntrustedException):
                problem_expected_sync = UntrustedException(
                    problem_expected.bare_jid,
                    problem_expected.device,
                    sm_sync.public_bundle.ik
                    if problem_expected.bare_jid == A_JID else
                    b_sms_sync[problem_expected.device].public_bundle.ik
                )

                problem_expected_async = UntrustedException(
                    problem_expected.bare_jid,
                    problem_expected.device,
                    sm_async.public_bundle.ik
                    if problem_expected.bare_jid == A_JID else
                    b_sms_async[problem_expected.device].public_bundle.ik
                )

                assert problem_sync  == problem_expected_sync
                assert problem_async == problem_expected_async
            else:
                assert problem_sync == problem_async == problem_expected

def test_create():
    st_sync, _, st_async, _ = createSessionManagers()

    # Create using the same storage with the same information
    createSessionManagers(st_sync, st_async)

    # Replace the device id
    overrideOwnData(st_sync, st_async, A_JID, B_DID)

    # This time, the create call should raise an InconsistentInfoException
    createSessionManagers(st_sync, st_async, InconsistentInfoException)

    # Replace the jid
    overrideOwnData(st_sync, st_async, B_JID, A_DID)

    # This time, the create call should raise an InconsistentInfoException
    createSessionManagers(st_sync, st_async, InconsistentInfoException)

    # Replace both the device id and the jid
    overrideOwnData(st_sync, st_async, B_JID, B_DID)

    # This time, the create call should raise an InconsistentInfoException
    createSessionManagers(st_sync, st_async, InconsistentInfoException)

    # Go back to the original data
    overrideOwnData(st_sync, st_async, A_JID, A_DID)

    # Create using the same storage with the same information
    createSessionManagers(st_sync, st_async)

def test_bundle_serialization():
    _, sm_sync, _, sm_async = createSessionManagers()

    bundle_sync  = sm_sync.public_bundle
    bundle_async = sm_async.public_bundle

    sb = SignalBackend
    ex = omemo.ExtendedPublicBundle
    
    assert ex.parse(sb, **bundle_sync.serialize(sb))  == bundle_sync
    assert ex.parse(sb, **bundle_async.serialize(sb)) == bundle_async

def test_deviceList():
    _, sm_sync, _, sm_async = createSessionManagers()

    getDevices(sm_sync, sm_async, None,  [], [ A_DID ])
    getDevices(sm_sync, sm_async, A_JID, [], [ A_DID ])
    
    newDeviceList(sm_sync, sm_async, A_JID, A_DIDS)
    getDevices(sm_sync, sm_async, A_JID, [], A_DIDS)
    
    newDeviceList(sm_sync, sm_async, A_JID, A_DIDS[:2])
    getDevices(sm_sync, sm_async, A_JID, A_DIDS[2:], A_DIDS[:2])
    
    newDeviceList(sm_sync, sm_async, A_JID, [])
    getDevices(sm_sync, sm_async, A_JID, set(A_DIDS) - set([ A_DID ]), [ A_DID ])

def test_messageEncryption():
    messageEncryption()

def test_messageEncryption_missingBundle():
    messageEncryption(pass_bundles = B_DIDS[:2], expected_problems = [
        MissingBundleException(B_JID, B_DIDS[2])
    ])

def test_messageEncryption_allBundlesMissing():
    messageEncryption(pass_bundles = [], expected_problems = [
        MissingBundleException(B_JID, B_DIDS[0]),
        MissingBundleException(B_JID, B_DIDS[1]),
        MissingBundleException(B_JID, B_DIDS[2]),
        NoEligibleDevicesException(B_JID)
    ])

def test_messageEncryption_untrustedDevice():
    messageEncryption(trust_devices = B_DIDS[:2], expected_problems = [
        UntrustedException(B_JID, B_DIDS[2], "placeholder")
    ])

def test_messageEncryption_noTrustedDevices():
    messageEncryption(trust_devices = [], expected_problems = [
        UntrustedException(B_JID, B_DIDS[0], "placeholder"),
        UntrustedException(B_JID, B_DIDS[1], "placeholder"),
        UntrustedException(B_JID, B_DIDS[2], "placeholder"),
        NoEligibleDevicesException(B_JID)
    ])

def test_messageEncryption_noDevices():
    messageEncryption(pass_devices = False, expected_problems = [
        NoDevicesException(B_JID)
    ])

def test_messageEncryption_expectProblems():
    messageEncryption(
        pass_bundles = B_DIDS[:2],
        trust_devices = B_DIDS[1:],
        expected_problems = [
            MissingBundleException(B_JID, B_DIDS[2]),
            UntrustedException(B_JID, B_DIDS[0], "placeholder")
        ]
    )

    messageEncryption(
        pass_bundles = B_DIDS[:2],
        trust_devices = B_DIDS[1:],
        expect_problems = [ B_DIDS[0], B_DIDS[2] ]
    )

def encryptBigFile(encryptor, name):
    location = os.path.dirname(os.path.abspath(__file__))

    plaintext_path = os.path.join(location, "confidential.txt")
    encrypted_path = os.path.join(location, "confidential_encrypted_" + name + ".txt")

    with open(plaintext_path, "rb") as src, open(encrypted_path, "wb") as dest:
        while True:
            block = src.read(1024)

            if len(block) == 0:
                dest.write(encryptor.finalize())
                break

            dest.write(encryptor.update(block))

def decryptBigFile(decryptor, name):
    location = os.path.dirname(os.path.abspath(__file__))

    plaintext_path = os.path.join(location, "confidential.txt")
    encrypted_path = os.path.join(location, "confidential_encrypted_" + name + ".txt")
    decrypted_path = os.path.join(location, "confidential_decrypted_" + name + ".txt")

    with open(encrypted_path, "rb") as src, open(decrypted_path, "wb") as dest:
        while True:
            block = src.read(1024)

            if len(block) == 0:
                dest.write(decryptor.finalize())
                break

            dest.write(decryptor.update(block))

    os.remove(encrypted_path)

    with open(plaintext_path, "rb") as src, open(decrypted_path, "rb") as dest:
        while True:
            plaintext_block = src.read(1024)
            decrypted_block = dest.read(1024)

            assert plaintext_block == decrypted_block

            if len(plaintext_block) == len(decrypted_block) == 0:
                break

    os.remove(decrypted_path)

def test_keyTransportMessage():
    _, sm_sync, _, sm_async = createSessionManagers()
    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] }
    )

    newDeviceList(sm_sync, sm_async, B_JID, [ B_DID ])
    trust(sm_sync, sm_async, b_sms_sync, b_sms_async, B_JID, [ B_DID ])

    b_sm_sync  = b_sms_sync [B_DID]
    b_sm_async = b_sms_async[B_DID]

    encrypted_sync = sm_sync.encryptKeyTransportMessage(
        [ B_JID ],
        lambda encryptor: encryptBigFile(encryptor, "sync"),
        { B_JID: { B_DID: b_sm_sync.public_bundle } }
    )

    encrypted_async = assertPromiseFulfilled(sm_async.encryptKeyTransportMessage(
        [ B_JID ],
        lambda encryptor: encryptBigFile(encryptor, "async"),
        { B_JID: { B_DID: b_sm_async.public_bundle } }
    ))

    decryptor_sync = b_sm_sync.decryptKeyTransportMessage(
        A_JID,
        A_DID,
        encrypted_sync["iv"],
        encrypted_sync["keys"][B_JID][B_DID]["data"],
        encrypted_sync["keys"][B_JID][B_DID]["pre_key"],
        allow_untrusted = True
    )

    decryptor_async = assertPromiseFulfilledOrRaise(b_sm_async.decryptKeyTransportMessage(
        A_JID,
        A_DID,
        encrypted_async["iv"],
        encrypted_async["keys"][B_JID][B_DID]["data"],
        encrypted_async["keys"][B_JID][B_DID]["pre_key"],
        allow_untrusted = True
    ))

    decryptBigFile(decryptor_sync,  "sync")
    decryptBigFile(decryptor_async, "async")

def test_ratchetForwardingMessage():
    _, sm_sync, _, sm_async = createSessionManagers()
    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] }
    )

    newDeviceList(sm_sync, sm_async, B_JID, [ B_DID ])
    trust(sm_sync, sm_async, b_sms_sync, b_sms_async, B_JID, [ B_DID ])

    b_sm_sync  = b_sms_sync [B_DID]
    b_sm_async = b_sms_async[B_DID]

    encrypted_sync = sm_sync.encryptRatchetForwardingMessage(
        [ B_JID ],
        { B_JID: { B_DID: b_sm_sync.public_bundle } }
    )

    encrypted_async = assertPromiseFulfilled(sm_async.encryptRatchetForwardingMessage(
        [ B_JID ],
        { B_JID: { B_DID: b_sm_async.public_bundle } }
    ))

    b_sm_sync.decryptRatchetForwardingMessage(
        A_JID,
        A_DID,
        encrypted_sync["iv"],
        encrypted_sync["keys"][B_JID][B_DID]["data"],
        encrypted_sync["keys"][B_JID][B_DID]["pre_key"],
        allow_untrusted = True
    )

    assertPromiseFulfilledOrRaise(b_sm_async.decryptRatchetForwardingMessage(
        A_JID,
        A_DID,
        encrypted_async["iv"],
        encrypted_async["keys"][B_JID][B_DID]["data"],
        encrypted_async["keys"][B_JID][B_DID]["pre_key"],
        allow_untrusted = True
    ))

def test_messageDecryption_noTrust():
    messageEncryption(trust_alice = False, expect_untrusted_decryption = True)

def test_messageDecryption_noTrust_allowUntrusted():
    messageEncryption(trust_alice = False, allow_untrusted_decryption = True)

def test_messageDecryption_noSession():
    _, sm_sync, _, sm_async = createSessionManagers()
    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] }
    )

    newDeviceList(sm_sync, sm_async, B_JID, [ B_DID ])
    trust(sm_sync, sm_async, b_sms_sync, b_sms_async, B_JID, [ B_DID ])

    b_sm_sync  = b_sms_sync [B_DID]
    b_sm_async = b_sms_async[B_DID]

    sm_sync.encryptMessage(
        [ B_JID ],
        "first message".encode("UTF-8"),
        { B_JID: { B_DID: b_sm_sync.public_bundle } }
    )

    assertPromiseFulfilled(sm_async.encryptMessage(
        [ B_JID ],
        "first message".encode("UTF-8"),
        { B_JID: { B_DID: b_sm_async.public_bundle } }
    ))

    encrypted_sync = sm_sync.encryptMessage(
        [ B_JID ],
        "second message".encode("UTF-8")
    )

    encrypted_async = assertPromiseFulfilled(sm_async.encryptMessage(
        [ B_JID ],
        "second message".encode("UTF-8")
    ))

    try:
        decrypted_sync = b_sm_sync.decryptMessage(
            A_JID,
            A_DID,
            encrypted_sync["iv"],
            encrypted_sync["keys"][B_JID][B_DID]["data"],
            encrypted_sync["keys"][B_JID][B_DID]["pre_key"],
            encrypted_sync["payload"]
        )

        assert False
    except NoSessionException as e:
        assert e == NoSessionException(A_JID, A_DID)

    try:
        decrypted_async = assertPromiseFulfilledOrRaise(b_sm_async.decryptMessage(
            A_JID,
            A_DID,
            encrypted_async["iv"],
            encrypted_async["keys"][B_JID][B_DID]["data"],
            encrypted_async["keys"][B_JID][B_DID]["pre_key"],
            encrypted_async["payload"]
        ))

        assert False
    except NoSessionException as e:
        assert e == NoSessionException(A_JID, A_DID)

def otpkPolicyTest(otpk_policy, expect_exception):
    _, sm_sync, _, sm_async = createSessionManagers()
    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] },
        otpk_policy = otpk_policy
    )

    newDeviceList(sm_sync, sm_async, B_JID, [ B_DID ])

    b_sm_sync  = b_sms_sync [B_DID]
    b_sm_async = b_sms_async[B_DID]

    trust(sm_sync, sm_async, b_sms_sync, b_sms_async, B_JID, [ B_DID ])
    trust(b_sm_sync, b_sm_async, sm_sync, sm_async, A_JID, A_DID)

    pre_key_message_sync = sm_sync.encryptMessage(
        [ B_JID ],
        "first message".encode("UTF-8"),
        { B_JID: { B_DID: b_sm_sync.public_bundle } }
    )

    pre_key_message_async = assertPromiseFulfilled(sm_async.encryptMessage(
        [ B_JID ],
        "first message".encode("UTF-8"),
        { B_JID: { B_DID: b_sm_async.public_bundle } }
    ))

    params_sync = [
        A_JID,
        A_DID,
        pre_key_message_sync["iv"],
        pre_key_message_sync["keys"][B_JID][B_DID]["data"],
        pre_key_message_sync["keys"][B_JID][B_DID]["pre_key"],
        pre_key_message_sync["payload"]
    ]

    params_async = [
        A_JID,
        A_DID,
        pre_key_message_async["iv"],
        pre_key_message_async["keys"][B_JID][B_DID]["data"],
        pre_key_message_async["keys"][B_JID][B_DID]["pre_key"],
        pre_key_message_async["payload"]
    ]

    b_sm_sync.decryptMessage(*params_sync)
    assertPromiseFulfilled(b_sm_async.decryptMessage(*params_async))

    try:
        b_sm_sync.decryptMessage(*params_sync)

        assert not expect_exception
    except KeyExchangeException as e:
        assert expect_exception
        assert e == KeyExchangeException(A_JID, A_DID, "unused")

    try:
        assertPromiseFulfilledOrRaise(b_sm_async.decryptMessage(*params_async))

        assert not expect_exception
    except KeyExchangeException as e:
        assert expect_exception
        assert e == KeyExchangeException(A_JID, A_DID, "unused")

def test_otpkPolicy_deleting():
    otpkPolicyTest(DeletingOTPKPolicy, True)

def test_otpkPolicy_keeping():
    otpkPolicyTest(KeepingOTPKPolicy, False)

def test_trustRetrieval():
    _, sm_sync, _, sm_async = createSessionManagers()
    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] }
    )

    newDeviceList(sm_sync, sm_async, B_JID, [ B_DID ])

    assert sm_sync.getTrustForDevice(B_JID, B_DID) == None
    assert assertPromiseFulfilled(sm_async.getTrustForDevice(B_JID, B_DID)) == None

    trust(sm_sync, sm_async, b_sms_sync, b_sms_async, B_JID, [ B_DID ])

    assert sm_sync.getTrustForDevice(B_JID, B_DID) == {
        "key": b_sms_sync[B_DID].public_bundle.ik,
        "trusted": True
    }

    assert assertPromiseFulfilled(sm_async.getTrustForDevice(B_JID, B_DID)) == {
        "key": b_sms_async[B_DID].public_bundle.ik,
        "trusted": True
    }

    distrust(sm_sync, sm_async, b_sms_sync, b_sms_async, B_JID, [ B_DID ])

    assert sm_sync.getTrustForDevice(B_JID, B_DID) == {
        "key": b_sms_sync[B_DID].public_bundle.ik,
        "trusted": False
    }

    assert assertPromiseFulfilled(sm_async.getTrustForDevice(B_JID, B_DID)) == {
        "key": b_sms_async[B_DID].public_bundle.ik,
        "trusted": False
    }

    assert sm_sync.getTrustForJID(B_JID) == {
        "active": {
            B_DID: {
                "key": b_sms_sync[B_DID].public_bundle.ik,
                "trusted": False
            }
        },
        "inactive": {}
    }

    assert assertPromiseFulfilled(sm_async.getTrustForJID(B_JID)) == {
        "active": {
            B_DID: {
                "key": b_sms_async[B_DID].public_bundle.ik,
                "trusted": False
            }
        },
        "inactive": {}
    }

def test_serialization():
    st_sync, sm_sync, st_async, sm_async = createSessionManagers()
    b_sms_sync, b_sms_async = createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] }
    )

    newDeviceList(sm_sync, sm_async, B_JID, [ B_DID ])
    trust(sm_sync, sm_async, b_sms_sync, b_sms_async, B_JID, [ B_DID ])

    b_sm_sync  = b_sms_sync [B_DID]
    b_sm_async = b_sms_async[B_DID]

    encrypted_sync = sm_sync.encryptRatchetForwardingMessage(
        [ B_JID ],
        { B_JID: { B_DID: b_sm_sync.public_bundle } }
    )

    encrypted_async = assertPromiseFulfilled(sm_async.encryptRatchetForwardingMessage(
        [ B_JID ],
        { B_JID: { B_DID: b_sm_async.public_bundle } }
    ))

    b_sm_sync.decryptRatchetForwardingMessage(
        A_JID,
        A_DID,
        encrypted_sync["iv"],
        encrypted_sync["keys"][B_JID][B_DID]["data"],
        encrypted_sync["keys"][B_JID][B_DID]["pre_key"],
        allow_untrusted = True
    )

    assertPromiseFulfilledOrRaise(b_sm_async.decryptRatchetForwardingMessage(
        A_JID,
        A_DID,
        encrypted_async["iv"],
        encrypted_async["keys"][B_JID][B_DID]["data"],
        encrypted_async["keys"][B_JID][B_DID]["pre_key"],
        allow_untrusted = True
    ))

    # After this code is done, there is an updated state and a session in the cache.
    # Create new SessionManagers using the storage of the old one and check, whether the
    # state and the session are still usable.
    _, sm_sync, _, sm_async = createSessionManagers(
        st_sync  = st_sync,
        st_async = st_async
    )

    encrypted_sync = sm_sync.encryptRatchetForwardingMessage(
        [ B_JID ],
        { B_JID: { B_DID: b_sm_sync.public_bundle } }
    )

    encrypted_async = assertPromiseFulfilled(sm_async.encryptRatchetForwardingMessage(
        [ B_JID ],
        { B_JID: { B_DID: b_sm_async.public_bundle } }
    ))

    b_sm_sync.decryptRatchetForwardingMessage(
        A_JID,
        A_DID,
        encrypted_sync["iv"],
        encrypted_sync["keys"][B_JID][B_DID]["data"],
        encrypted_sync["keys"][B_JID][B_DID]["pre_key"],
        allow_untrusted = True
    )

    assertPromiseFulfilledOrRaise(b_sm_async.decryptRatchetForwardingMessage(
        A_JID,
        A_DID,
        encrypted_async["iv"],
        encrypted_async["keys"][B_JID][B_DID]["data"],
        encrypted_async["keys"][B_JID][B_DID]["pre_key"],
        allow_untrusted = True
    ))

# TODO
# Default OTPKPolicy
# KeyExchangeExceptions during encryptMessage
# Inactive device cleanup
# Whole JID deletion
