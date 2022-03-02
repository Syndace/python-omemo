import asyncio
import pytest

pytestmark = pytest.mark.asyncio

import cProfile
import logging
import os
import time

logging.basicConfig(level = logging.DEBUG)

import omemo
from omemo import SessionManager
from omemo.exceptions import *

from omemo_backend_signal import BACKEND as SignalBackend

from inmemorystorage  import InMemoryStorage

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

async def getDevices(sm, jid, inactive, active):
    inactive = set(inactive)
    active   = set(active)

    devices = await sm.getDevices(jid)

    assert set(devices["inactive"].keys()) == inactive
    assert devices["active"] == active

async def newDeviceList(sm, jid, devices):
    await sm.newDeviceList(jid, devices)

async def createSessionManagers(st = None, expect = None):
    if st is None:
        st = InMemoryStorage()

    try:
        sm = await SessionManager.create(
            st,
            DeletingOTPKPolicy,
            SignalBackend,
            A_JID,
            A_DID
        )
    except Exception as e:
        assert expect is not None
        assert isinstance(e, expect)

    if expect is None:
        assert isinstance(sm,  SessionManager)

        return st, sm

async def createOtherSessionManagers(jid, dids, other_dids, otpk_policy = None):
    if otpk_policy == None:
        otpk_policy = DeletingOTPKPolicy

    sms = {}

    for did in dids:
        st = InMemoryStorage()
        sm = await SessionManager.create(st, otpk_policy, SignalBackend, jid, did)

        assert isinstance(sm, SessionManager)

        for other_jid in other_dids:
            await sm.newDeviceList(other_jid, other_dids[other_jid])

        sms[did] = sm
    
    return sms

async def trust(sm, sms, jid_to_trust, devices_to_trust):
    try:
        for device in devices_to_trust:
            ik = sms[device].public_bundle.ik

            await sm.setTrust(jid_to_trust, device, ik, True)
    except TypeError:
        ik = sms.public_bundle.ik

        await sm.setTrust(jid_to_trust, devices_to_trust, ik, True)

async def distrust(sm, sms, jid_to_trust, devices_to_trust):
    try:
        for device in devices_to_trust:
            ik = sms[device].public_bundle.ik

            await sm.setTrust(jid_to_trust, device, ik, False)
    except TypeError:
        ik = sms.public_bundle.ik

        await sm.setTrust(jid_to_trust, devices_to_trust, ik, False)

async def messageEncryption(
    pass_bundles      = None,
    trust_devices     = None,
    pass_devices      = True,
    expect_problems   = None,
    expected_problems = None,
    trust_alice       = True,
    allow_untrusted_decryption = False,
    expect_untrusted_decryption = None
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

    st, sm = await createSessionManagers()
    b_sms = await createOtherSessionManagers(
        B_JID,
        B_DIDS,
        { A_JID: [ A_DID ] }
    )

    if pass_devices:
        await sm.newDeviceList(B_JID, B_DIDS)

    await trust(sm, b_sms, B_JID, trust_devices)

    if trust_alice:
        for b_did in B_DIDS:
            await trust(b_sms[b_did], sm, A_JID, A_DID)

    bundles = {
        did: b_sms[did].public_bundle
        for did in B_DIDS
        if did in pass_bundles
    }

    problems = []

    msg = "single message".encode("UTF-8")

    try:
        encrypted = await sm.encryptMessage(
            [ B_JID ],
            msg,
            { B_JID: bundles },
            { B_JID: expect_problems }
        )
    except EncryptionProblemsException as e:
        problems = e.problems

    if expected_problems == None:
        successes = set(encrypted["keys"][B_JID].keys())

        expected_successes = set(B_DIDS) - expect_problems

        assert expected_successes == successes

        for did in expected_successes:
            try:
                # Check that the pre_key flag is set correctly
                expect_pre_key = did in bundles
                assert encrypted["keys"][B_JID][did]["pre_key"] == expect_pre_key

                # Check that the receiving chain length is None (because the session
                # doesn't exist yet)
                assert await b_sms[did].receiving_chain_length(A_JID, A_DID) is None

                decrypted = await b_sms[did].decryptMessage(
                    A_JID,
                    A_DID,
                    encrypted["iv"],
                    encrypted["keys"][B_JID][did]["data"],
                    encrypted["keys"][B_JID][did]["pre_key"],
                    encrypted["payload"],
                    allow_untrusted = allow_untrusted_decryption
                )

                assert expect_untrusted_decryption == None

                # Check that the receiving chain length is at 1 after successful
                # decryption
                assert await b_sms[did].receiving_chain_length(A_JID, A_DID) == 1
            except TrustException as e:
                assert e == TrustException(
                    A_JID,
                    A_DID,
                    sm.public_bundle.ik,
                    expect_untrusted_decryption
                )

                # Check that the receiving chain length remains None (because the session
                # wasn't created)
                assert await b_sms[did].receiving_chain_length(A_JID, A_DID) is None

            if expect_untrusted_decryption == None:
                assert decrypted == msg
    else:
        assert len(problems) == len(expected_problems)

        zipped = zip(problems, expected_problems)

        for problem, problem_expected in zipped:
            if isinstance(problem_expected, TrustException):
                problem_expected = TrustException(
                    problem_expected.bare_jid,
                    problem_expected.device,
                    sm.public_bundle.ik
                    if problem_expected.bare_jid == A_JID else
                    b_sms[problem_expected.device].public_bundle.ik,
                    problem_expected.problem
                )
                assert problem == problem_expected
            else:
                assert problem == problem_expected

async def test_create():
    st, _ = await createSessionManagers()

    # Create using the same storage with the same information
    await createSessionManagers(st)

    # Replace the device id
    await st.storeOwnData(A_JID, B_DID)

    # This time, the create call should raise an InconsistentInfoException
    await createSessionManagers(st, InconsistentInfoException)

    # Replace the jid
    await st.storeOwnData(B_JID, A_DID)

    # This time, the create call should raise an InconsistentInfoException
    await createSessionManagers(st, InconsistentInfoException)

    # Replace both the device id and the jid
    await st.storeOwnData(B_JID, B_DID)

    # This time, the create call should raise an InconsistentInfoException
    await createSessionManagers(st, InconsistentInfoException)

    # Go back to the original data
    await st.storeOwnData(A_JID, A_DID)

    # Create using the same storage with the same information
    await createSessionManagers(st)

async def test_bundle_serialization():
    _, sm = await createSessionManagers()

    bundle = sm.public_bundle

    sb = SignalBackend
    
    assert omemo.ExtendedPublicBundle.parse(sb, **bundle.serialize(sb)) == bundle

async def test_deviceList():
    _, sm = await createSessionManagers()

    await getDevices(sm, None,  [], [ A_DID ])
    await getDevices(sm, A_JID, [], [ A_DID ])
    
    await sm.newDeviceList(A_JID, A_DIDS)
    await getDevices(sm, A_JID, [], A_DIDS)
    
    await sm.newDeviceList(A_JID, A_DIDS[:2])
    await getDevices(sm, A_JID, A_DIDS[2:], A_DIDS[:2])
    
    await sm.newDeviceList(A_JID, [])
    await getDevices(sm, A_JID, set(A_DIDS) - set([ A_DID ]), [ A_DID ])

async def test_messageEncryption():
    await messageEncryption()

# This test was added due to a report that the SessionManager behaves incorrectly when
# passing an empty string in the list of recipients while encrypting. This behaviour could
# not be reproduced.
async def test_messageEncryption_emptyStringRecipient():
    # Create multiple SessionManagers for the same JID and make their device lists known
    sms = await createOtherSessionManagers(
        A_JID,
        A_DIDS,
        { A_JID: A_DIDS }
    )

    # Use the first SessionManager for the active part of the test
    sm = sms[A_DIDS[0]]

    # Make the SM trust all other devices
    for a_did in A_DIDS[1:]:
        await trust(sm, sms[a_did], A_JID, a_did)

    # Get the bundles of all devices
    bundles = { did: sms[did].public_bundle for did in A_DIDS }

    msg = "single message".encode("UTF-8")

    # Encrypt the message, passing an array containing an empty string as the list of
    # recipients. Make sure that a NoDevicesException is thrown for the empty string.
    try:
        encrypted = await sm.encryptMessage(
            [ "" ],
            msg,
            { A_JID: bundles }
        )
    except EncryptionProblemsException as e:
        assert len(e.problems) == 1
        assert isinstance(e.problems[0], NoDevicesException)
        assert e.problems[0].bare_jid == ""

async def test_messageEncryption_missingBundle():
    await messageEncryption(pass_bundles = B_DIDS[:2], expected_problems = [
        MissingBundleException(B_JID, B_DIDS[2])
    ])

async def test_messageEncryption_allBundlesMissing():
    await messageEncryption(pass_bundles = [], expected_problems = [
        MissingBundleException(B_JID, B_DIDS[0]),
        MissingBundleException(B_JID, B_DIDS[1]),
        MissingBundleException(B_JID, B_DIDS[2]),
        NoEligibleDevicesException(B_JID)
    ])

async def test_messageEncryption_untrustedDevice():
    await messageEncryption(trust_devices = B_DIDS[:2], expected_problems = [
        TrustException(B_JID, B_DIDS[2], "placeholder", "undecided") # TODO
    ])

async def test_messageEncryption_noTrustedDevices():
    await messageEncryption(trust_devices = [], expected_problems = [
        TrustException(B_JID, B_DIDS[0], "placeholder", "undecided"), # TODO
        TrustException(B_JID, B_DIDS[1], "placeholder", "undecided"), # TODO
        TrustException(B_JID, B_DIDS[2], "placeholder", "undecided"), # TODO
        NoEligibleDevicesException(B_JID)
    ])

async def test_messageEncryption_noDevices():
    await messageEncryption(pass_devices = False, expected_problems = [
        NoDevicesException(B_JID)
    ])

async def test_messageEncryption_expectProblems():
    await messageEncryption(
        pass_bundles = B_DIDS[:2],
        trust_devices = B_DIDS[1:],
        expected_problems = [
            MissingBundleException(B_JID, B_DIDS[2]),
            TrustException(B_JID, B_DIDS[0], "placeholder", "undecided") # TODO
        ]
    )

    await messageEncryption(
        pass_bundles = B_DIDS[:2],
        trust_devices = B_DIDS[1:],
        expect_problems = [ B_DIDS[0], B_DIDS[2] ]
    )

async def test_ratchetForwardingMessage():
    _, sm = await createSessionManagers()
    b_sms = await createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] }
    )

    await sm.newDeviceList(B_JID, [ B_DID ])
    # This should not require trusting the devices.
    #await trust(sm, b_sms, B_JID, [ B_DID ])

    b_sm = b_sms[B_DID]

    encrypted = await sm.encryptRatchetForwardingMessage(B_JID, B_DID, b_sm.public_bundle)

    await b_sm.decryptRatchetForwardingMessage(
        A_JID,
        A_DID,
        encrypted["iv"],
        encrypted["keys"][B_JID][B_DID]["data"],
        encrypted["keys"][B_JID][B_DID]["pre_key"],
        allow_untrusted = True
    )

async def test_messageDecryption_noTrust():
    await messageEncryption(
        trust_alice = False,
        expect_untrusted_decryption = "undecided"
    )

async def test_messageDecryption_noTrust_allowUntrusted():
    await messageEncryption(trust_alice = False, allow_untrusted_decryption = True)

async def test_messageDecryption_noSession():
    _, sm = await createSessionManagers()
    b_sms = await createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] }
    )

    await sm.newDeviceList(B_JID, [ B_DID ])
    await trust(sm, b_sms, B_JID, [ B_DID ])

    b_sm = b_sms[B_DID]

    await sm.encryptMessage(
        [ B_JID ],
        "first message".encode("UTF-8"),
        { B_JID: { B_DID: b_sm.public_bundle } }
    )

    encrypted = await sm.encryptMessage(
        [ B_JID ],
        "second message".encode("UTF-8")
    )

    try:
        decrypted = await b_sm.decryptMessage(
            A_JID,
            A_DID,
            encrypted["iv"],
            encrypted["keys"][B_JID][B_DID]["data"],
            encrypted["keys"][B_JID][B_DID]["pre_key"],
            encrypted["payload"]
        )

        assert False
    except NoSessionException as e:
        assert e == NoSessionException(A_JID, A_DID)

async def otpkPolicyTest(otpk_policy, expect_exception):
    _, sm = await createSessionManagers()
    b_sms = await createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] },
        otpk_policy = otpk_policy
    )

    await sm.newDeviceList(B_JID, [ B_DID ])

    b_sm = b_sms[B_DID]

    await trust(sm, b_sms, B_JID, [ B_DID ])
    await trust(b_sm, sm, A_JID, A_DID)

    pre_key_message = await sm.encryptMessage(
        [ B_JID ],
        "first message".encode("UTF-8"),
        { B_JID: { B_DID: b_sm.public_bundle } }
    )

    params = [
        A_JID,
        A_DID,
        pre_key_message["iv"],
        pre_key_message["keys"][B_JID][B_DID]["data"],
        pre_key_message["keys"][B_JID][B_DID]["pre_key"],
        pre_key_message["payload"]
    ]

    await b_sm.decryptMessage(*params)

    try:
        await b_sm.decryptMessage(*params)

        assert not expect_exception
    except KeyExchangeException as e:
        assert expect_exception
        assert e == KeyExchangeException(A_JID, A_DID, "unused")

async def test_otpkPolicy_deleting():
    await otpkPolicyTest(DeletingOTPKPolicy, True)

async def test_otpkPolicy_keeping():
    await otpkPolicyTest(KeepingOTPKPolicy, False)

async def test_trustRetrieval():
    _, sm = await createSessionManagers()
    b_sms = await createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] }
    )

    await sm.newDeviceList(B_JID, [ B_DID ])

    assert await sm.getTrustForDevice(B_JID, B_DID) == None

    await trust(sm, b_sms, B_JID, [ B_DID ])

    assert await sm.getTrustForDevice(B_JID, B_DID) == {
        "key": b_sms[B_DID].public_bundle.ik,
        "trusted": True
    }

    await distrust(sm, b_sms, B_JID, [ B_DID ])

    assert await sm.getTrustForDevice(B_JID, B_DID) == {
        "key": b_sms[B_DID].public_bundle.ik,
        "trusted": False
    }

    assert await sm.getTrustForJID(B_JID) == {
        "active": {
            B_DID: {
                "key": b_sms[B_DID].public_bundle.ik,
                "trusted": False
            }
        },
        "inactive": {}
    }

async def test_serialization():
    st, sm = await createSessionManagers()
    b_sms = await createOtherSessionManagers(
        B_JID,
        [ B_DID ],
        { A_JID: [ A_DID ] }
    )

    await sm.newDeviceList(B_JID, [ B_DID ])
    await trust(sm, b_sms, B_JID, [ B_DID ])

    b_sm = b_sms[B_DID]

    encrypted = await sm.encryptRatchetForwardingMessage(B_JID, B_DID, b_sm.public_bundle)

    await b_sm.decryptRatchetForwardingMessage(
        A_JID,
        A_DID,
        encrypted["iv"],
        encrypted["keys"][B_JID][B_DID]["data"],
        encrypted["keys"][B_JID][B_DID]["pre_key"],
        allow_untrusted = True
    )

    # After this code is done, there is an updated state and a session in the cache.
    # Create new SessionManagers using the storage of the old one and check, whether the
    # state and the session are still usable.
    _, sm = await createSessionManagers(st=st)

    encrypted = await sm.encryptRatchetForwardingMessage(B_JID, B_DID, b_sm.public_bundle)

    await b_sm.decryptRatchetForwardingMessage(
        A_JID,
        A_DID,
        encrypted["iv"],
        encrypted["keys"][B_JID][B_DID]["data"],
        encrypted["keys"][B_JID][B_DID]["pre_key"],
        allow_untrusted = True
    )

async def test_stresstest():
    # Create 100 random JIDs with 10 random devices each
    devices = {}
    main_jid = None
    main_did = None

    while len(devices) < 100:
        jid = generateRandomJID()

        if main_jid == None:
            main_jid = jid

        devices[jid] = set()

        while len(devices[jid]) < 10:
            did = omemo.util.generateDeviceID(devices[jid])

            if main_did == None:
                main_did = did

            devices[jid].add(did)

    sms = {}

    for jid in devices:
        sms[jid] = {}

        for did in devices[jid]:
            # Create a SessionManager for that jid+did
            sms[jid][did] = await SessionManager.create(
                InMemoryStorage(),
                DeletingOTPKPolicy,
                SignalBackend,
                jid,
                did
            )

    bundles = {}

    for jid in devices:
        bundles[jid] = {}

        for did in devices[jid]:
            bundles[jid][did] = sms[jid][did].public_bundle

    main = sms[main_jid][main_did]

    # Tell the main SessionManager about all of the other jids and devices
    for jid in devices:
        await main.newDeviceList(jid, devices[jid])

    # Tell the main SessionManager to trust all other jids and devices
    for jid in devices:
        for did in devices[jid]:
            await main.setTrust(jid, did, sms[jid][did].public_bundle.ik, True)

    # TODO
#    cProfile.runctx("""
#await main.encryptMessage(
#    list(devices.keys()),
#    "This is a stresstest!".encode("UTF-8"),
#    bundles = bundles
#)
#    """, {}, {
#        "main": main,
#        "devices": devices,
#        "bundles": bundles
#    })

    # If the code reaches this point, the stress test has passed
    assert True

def charFromByte(c):
    try:
        c = ord(c)
    except TypeError:
        pass

    c %= 26
    c += ord('a')
    return chr(c)

def generateRandomJID():
    bytes = os.urandom(16)

    return "{}@{}.im".format(
        "".join(map(charFromByte, bytes[:8])),
        "".join(map(charFromByte, bytes[8:]))
    )

# TODO
# Default OTPKPolicy
# KeyExchangeExceptions during encryptMessage
# Inactive device cleanup
# Whole JID deletion
# resetTrust method
# encryptKeyTransportMessage
