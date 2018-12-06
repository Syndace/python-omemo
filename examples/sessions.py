from __future__ import print_function

import logging

import omemo
from omemo.exceptions import KeyExchangeException

from omemo_backend_signal import BACKEND as SignalBackend

import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tests")))

from deletingotpkpolicy import DeletingOTPKPolicy
from keepingotpkpolicy  import KeepingOTPKPolicy

from asyncinmemorystorage import AsyncInMemoryStorage
from syncinmemorystorage  import SyncInMemoryStorage

# The example data file contains bare jids and device ids for four people: Alice, Bob,
# Charlie and Dave.
# OMEMO does not use the XMPP resource in any way. Instead, OMEMO uses
# (bare_jid, device_id) tuples to uniquely identify devices. For that reason, whenever
# this lib expects a jid as parameter, please pass a bare jid (name@host) without the
# resource.
# Note: To use OMEMO in a MUC, you can't use the MUC-style jids (muc@host/name) but you
# have to use the user's bare jids (name@host) aswell.
from example_data import *

logging.basicConfig(level = logging.INFO)

try:
    input = raw_input
except NameError:
    pass

use_async_storage = ""
while not use_async_storage in [ "y", "n" ]:
    use_async_storage = input(
        "Use an asynchronous implementation of the storage class? (y/n): "
    )
use_async_storage = use_async_storage == "y"

InMemoryStorage = AsyncInMemoryStorage if use_async_storage else SyncInMemoryStorage

# This part requires a bit of an explanation.
# The SessionManager has to persist certain information between runs. The way this data is
# saved is not fixed, but the user can implement the Storage interface to reflect his own
# preferences. This introduces a problem: One user may want to use synchronous technology
# to store the data, another user might want to use asynchonous technologies.
# This strongly influences the structure of the whole SessionManager class. All methods of
# the SessionManager should be synchronous if the storage is synchronous and vice versa.
# ...and this is what actually happens!
# If you pass a synchronous implementation of the Storage class to the
# SessionManager.create method, all of the SessionManagers methods are synchronous aswell.
# If you pass an asynchronous implementation instead, each method returns a
# omemo.promise.Promise object.
# Detailed information about the Promise implementation and coroutine decorators like
# promise.maybe_coroutine can be found directly in the promise.py file.
# For now, take this short summary:
"""
someSyncStorage  = SomeSyncStorage()
someAsyncStorage = SomeAsyncStorage()

# If you use a synchronous storage implementation, you can just use the return values as
# usual.
syncManager = omemo.SessionManager.create(someSyncStorage, ...)

# If you use an asynchronous storage implementation, the return value is a promise
asyncManagerPromise = omemo.SessionManager.create(someAsyncStorage, ...)

# You can use the then method of the Promise object to wait for the Promise to resolve and
# to get the result from it:
asyncManagerPromise.then(
    lambda asyncManager: print("This is the actual asyncManager:", asyncManager),
    lambda error: print("An error occured:", error)
)
"""
@omemo.promise.maybe_coroutine(lambda *args, **kwargs: use_async_storage)
def main():
    # Each device using OMEMO has to create exactly one SessionManager which handles the
    # whole OMEMO for this device.
    # In this example, imagine Alice, Bob and Charlie are all on different devices and
    # only have access to their own SessionManagers.
    alice_session_manager = yield omemo.SessionManager.create(
        InMemoryStorage(),
        DeletingOTPKPolicy,
        SignalBackend,
        ALICE_BARE_JID,
        ALICE_DEVICE_ID
    )

    bob_session_manager = yield omemo.SessionManager.create(
        InMemoryStorage(),
        DeletingOTPKPolicy,
        SignalBackend,
        BOB_BARE_JID,
        BOB_DEVICE_ID
    )

    charlie_session_manager = yield omemo.SessionManager.create(
        InMemoryStorage(),
        DeletingOTPKPolicy,
        SignalBackend,
        CHARLIE_BARE_JID,
        CHARLIE_DEVICE_ID
    )

    # In OMEMO the device lists are handled using a pep node.
    # This next part simulates getting the device list from the pep node and telling the
    # session manager about the device lists.
    yield alice_session_manager.newDeviceList(ALICE_BARE_JID, [ ALICE_DEVICE_ID ])
    yield bob_session_manager.newDeviceList(ALICE_BARE_JID, [ ALICE_DEVICE_ID ])
    yield charlie_session_manager.newDeviceList(ALICE_BARE_JID, [ ALICE_DEVICE_ID ])

    yield alice_session_manager.newDeviceList(BOB_BARE_JID, [ BOB_DEVICE_ID ])
    yield bob_session_manager.newDeviceList(BOB_BARE_JID, [ BOB_DEVICE_ID ])
    yield charlie_session_manager.newDeviceList(BOB_BARE_JID, [ BOB_DEVICE_ID ])

    yield alice_session_manager.newDeviceList(CHARLIE_BARE_JID, [ CHARLIE_DEVICE_ID ])
    yield bob_session_manager.newDeviceList(CHARLIE_BARE_JID, [ CHARLIE_DEVICE_ID ])
    yield charlie_session_manager.newDeviceList(CHARLIE_BARE_JID, [ CHARLIE_DEVICE_ID ])

    # You can get the list of (in)active devices for each jid from the session manager.
    # If you don't pass a bare jid, the method assumes your own bare jid.
    aliceDevices        = yield alice_session_manager.getDevices()
    aliceBareJIDDevices = yield alice_session_manager.getDevices(ALICE_BARE_JID)

    assert(aliceDevices["active"]          == set([ ALICE_DEVICE_ID ]))
    assert(aliceBareJIDDevices["active"]   == set([ ALICE_DEVICE_ID ]))
    assert(aliceDevices["inactive"]        == {})
    assert(aliceBareJIDDevices["inactive"] == {})

    # Send an initial message from Alice to Bob.
    # The message is built for:
    # - All devices of Bob
    # - All devices of Alice, except for the sending device
    #
    # This is the part where public bundles come into play:
    # In OMEMO, you build an encrypted session with each device of each user.
    # If such a session already exists, the encryptMessage method uses this session.
    # If no such session exists, the encryptMessage method builds the missing session,
    # which requires the public bundle of the (bare jid, device id) you want to start the
    # session with.
    #
    # In the following example, Alice wants to build a session with Bobs only device.
    # No such session exists, that means we have to pass the public bundle of Bobs device.
    # In a real XMPP scenario, Bobs device has published its public bundle to a pep node
    # and you have to download his bundle from the node first.
    # The bundle_xml file shows how to (de)serialize a public bundle to/from xml.
    initial_message = yield alice_session_manager.encryptMessage(
        BOB_BARE_JID,
        "Hey Bob!".encode("UTF-8"),
        {
            BOB_BARE_JID: {
                BOB_DEVICE_ID: bob_session_manager.public_bundle
            }
        }
    )

    # The values
    # - initial_message["iv"]
    # - initial_message["sid"]
    # - initial_message["keys"]
    # - initial_message["payload"]
    # should contain everything you need to build a stanza and send it.

    # Get the message specified for Bob on his only device
    bob_message = initial_message["keys"][BOB_BARE_JID][BOB_DEVICE_ID]

    # The initial session-building messages are called pre key messages.
    assert(bob_message["pre_key"])

    # Decrypt the initial message.
    plaintext = yield bob_session_manager.decryptMessage(
        ALICE_BARE_JID, # The jid and device id of the user who sent you this message
        ALICE_DEVICE_ID,
        initial_message["iv"],
        bob_message["data"],
        bob_message["pre_key"],
        initial_message["payload"]
    )

    assert(plaintext.decode("UTF-8") == "Hey Bob!")

    # Now, any party can send follow-up messages.
    # If the session was established before, you don't have to pass any public bundles.
    message = yield bob_session_manager.encryptMessage(
        ALICE_BARE_JID,
        "Yo Alice!".encode("UTF-8")
    )

    # Get the message specified for Alice on her only device
    alice_message = message["keys"][ALICE_BARE_JID][ALICE_DEVICE_ID]

    assert(not alice_message["pre_key"])

    plaintext = yield alice_session_manager.decryptMessage(
        BOB_BARE_JID,
        BOB_DEVICE_ID,
        message["iv"],
        alice_message["data"],
        alice_message["pre_key"],
        message["payload"]
    )

    assert(plaintext.decode("UTF-8") == "Yo Alice!")

    # You can encrypt a message for multiple recipients with just one call to
    # encryptMessage, just pass a list of bare jids instead of a single bare jid.
    # Alice already has a session with Bob but she doesn't have a session with Charlie,
    # that's why we have to pass Charlies public bundle.
    muc_message = yield alice_session_manager.encryptMessage(
        [ BOB_BARE_JID, CHARLIE_BARE_JID ],
        "Hey Bob and Charlie!".encode("UTF-8"),
        {
            CHARLIE_BARE_JID: {
                CHARLIE_DEVICE_ID: charlie_session_manager.public_bundle
            }
        }
    )

    # Get the message specified for Bob on his only device
    bob_message = muc_message["keys"][BOB_BARE_JID][BOB_DEVICE_ID]

    assert(not bob_message["pre_key"])

    # Get the message specified for Charlie on his/her only device
    charlie_message = muc_message["keys"][CHARLIE_BARE_JID][CHARLIE_DEVICE_ID]

    assert(charlie_message["pre_key"])

    plaintext = yield bob_session_manager.decryptMessage(
        ALICE_BARE_JID,
        ALICE_DEVICE_ID,
        muc_message["iv"],
        bob_message["data"],
        bob_message["pre_key"],
        muc_message["payload"]
    )

    assert(plaintext.decode("UTF-8") == "Hey Bob and Charlie!")

    plaintext = yield charlie_session_manager.decryptMessage(
        ALICE_BARE_JID,
        ALICE_DEVICE_ID,
        muc_message["iv"],
        charlie_message["data"],
        charlie_message["pre_key"],
        muc_message["payload"]
    )

    assert(plaintext.decode("UTF-8") == "Hey Bob and Charlie!")

    #################
    # OTPK handling #
    #################

    # This section gives an insight into the one-time pre key management.
    # One-time pre keys are part of the key exchange protocol used by OMEMO, called X3DH
    # or extended triple diffie hellman. This protocol requires you to generate a list of
    # keys and publish them somehow, the so-called public bundle.
    # Every time you handshake with someone else, you select one of his published keys and
    # use it to derive a shared secret.
    # After one of these one-time pre keys is used, the specification tells you to delete
    # the corresponding private key. But there is one problem: The specification does
    # neither account for lost or delayed packets, nor for the case of two packets in a
    # row without a response in between. For that reason, there is a major usability
    # drawback if all keys get deleted instantly after the first use.
    #
    # This is where the OTPK policy comes in: Instead of deleting the keys instantly, you
    # can override the OTPKPolicy class and use it to decide yourself whether to delete
    # the key or not.
    #
    # Let's look at the simplest implementation of the OTPKPolicy: The implementation
    # that simply always deletes the keys, no matter what. This behaviour is implemented
    # by the DeletingOTPKPolicy class.
    #
    # To see how it works, we try to initiate a session two times using the same OTPK.
    # This should result in an exception on the second initiation, because the policy
    # deleted the key after its first use.

    # Tell Alice' and Bobs session managers about Dave and his device
    yield alice_session_manager.newDeviceList(DAVE_BARE_JID, [ DAVE_DEVICE_ID ])
    yield bob_session_manager.newDeviceList(DAVE_BARE_JID, [ DAVE_DEVICE_ID ])

    # Create a session manager for Dave that uses the DeletingOTPKPolicy class
    dave_session_manager = yield omemo.SessionManager.create(
        InMemoryStorage(),
        DeletingOTPKPolicy,
        SignalBackend,
        DAVE_BARE_JID,
        DAVE_DEVICE_ID
    )

    yield dave_session_manager.newDeviceList(ALICE_BARE_JID, [ ALICE_DEVICE_ID ])

    # Create an initial message from Alice to Dave
    initial_message = yield alice_session_manager.encryptMessage(
        DAVE_BARE_JID,
        "DeletingOTPKPolicy example".encode("UTF-8"),
        {
            DAVE_BARE_JID: {
                DAVE_DEVICE_ID: dave_session_manager.public_bundle
            }
        }
    )

    # Get the message specified for Dave on his only device
    dave_message = initial_message["keys"][DAVE_BARE_JID][DAVE_DEVICE_ID]

    assert(dave_message["pre_key"])

    # Let Dave initialize the session for the first time, this should work fine
    plaintext = yield dave_session_manager.decryptMessage(
        ALICE_BARE_JID,
        ALICE_DEVICE_ID,
        initial_message["iv"],
        dave_message["data"],
        dave_message["pre_key"],
        initial_message["payload"]
    )

    assert(plaintext.decode("UTF-8") == "DeletingOTPKPolicy example")

    # Whenever the public bundle somehow changes, for example because one of the one-time
    # pre keys was used, the republish_bundle flag is set:
    assert(dave_session_manager.republish_bundle)
    assert(len(dave_session_manager.public_bundle.otpks) == 99)
    # You should check the republish_bundle flag after every OMEMO usage and re-publish
    # your bundle if the flag is set. The flag clears itself after reading it.

    # Now, try the same thing a second time. This sould raise an exception
    try:
        plaintext = yield dave_session_manager.decryptMessage(
            ALICE_BARE_JID,
            ALICE_DEVICE_ID,
            initial_message["iv"],
            dave_message["data"],
            dave_message["pre_key"],
            initial_message["payload"]
        )

        assert(False) # This line should not execute
    except KeyExchangeException as e:
        assert(e == KeyExchangeException(ALICE_BARE_JID, ALICE_DEVICE_ID, "woops!"))

    # Finally, let's do the same thing but using a policy that never deletes keys instead
    # of always.

    # Create a session manager for Dave that uses the KeepingOTPKPolicy class
    dave_session_manager = yield omemo.SessionManager.create(
        InMemoryStorage(),
        KeepingOTPKPolicy,
        SignalBackend,
        DAVE_BARE_JID,
        DAVE_DEVICE_ID
    )

    yield dave_session_manager.newDeviceList(ALICE_BARE_JID, [ ALICE_DEVICE_ID ])

    # Create an initial message from Bob to Dave
    initial_message = yield bob_session_manager.encryptMessage(
        DAVE_BARE_JID,
        "DeletingOTPKPolicy example".encode("UTF-8"),
        {
            DAVE_BARE_JID: {
                DAVE_DEVICE_ID: dave_session_manager.public_bundle
            }
        }
    )

    # Get the message specified for Dave on his only device
    dave_message = initial_message["keys"][DAVE_BARE_JID][DAVE_DEVICE_ID]

    assert(dave_message["pre_key"])

    # Let Dave initialize the session for the first time, this should work fine
    plaintext = yield dave_session_manager.decryptMessage(
        BOB_BARE_JID,
        BOB_DEVICE_ID,
        initial_message["iv"],
        dave_message["data"],
        dave_message["pre_key"],
        initial_message["payload"]
    )

    assert(plaintext.decode("UTF-8") == "DeletingOTPKPolicy example")

    # Daves public bundle should have the "republish_bundle" flag set and it should not
    # contain the used pre key any more.
    assert(dave_session_manager.republish_bundle)
    assert(len(dave_session_manager.public_bundle.otpks) == 99)

    # Now, the second try should work aswell, because the policy decided to keep the OTPK
    plaintext = yield dave_session_manager.decryptMessage(
        BOB_BARE_JID,
        BOB_DEVICE_ID,
        initial_message["iv"],
        dave_message["data"],
        dave_message["pre_key"],
        initial_message["payload"]
    )

    assert(plaintext.decode("UTF-8") == "DeletingOTPKPolicy example")

    omemo.promise.returnValue("Done!")

if __name__ == "__main__":
    print(main())
