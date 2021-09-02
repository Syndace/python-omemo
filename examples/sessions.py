import asyncio
import logging

import omemo
from omemo.exceptions import KeyExchangeException

from omemo_backend_signal import BACKEND as SignalBackend

import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tests")))

from deletingotpkpolicy import DeletingOTPKPolicy
from keepingotpkpolicy  import KeepingOTPKPolicy

from inmemorystorage import InMemoryStorage

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

async def main():
    # Each device using OMEMO has to create exactly one SessionManager which handles the
    # whole OMEMO for this device.
    # In this example, imagine Alice, Bob and Charlie are all on different devices and
    # only have access to their own SessionManagers.
    alice_session_manager = await omemo.SessionManager.create(
        InMemoryStorage(),
        omemo.DefaultOTPKPolicy(),
        SignalBackend,
        ALICE_BARE_JID,
        ALICE_DEVICE_ID
    )

    bob_session_manager = await omemo.SessionManager.create(
        InMemoryStorage(),
        omemo.DefaultOTPKPolicy(),
        SignalBackend,
        BOB_BARE_JID,
        BOB_DEVICE_ID
    )

    charlie_session_manager = await omemo.SessionManager.create(
        InMemoryStorage(),
        omemo.DefaultOTPKPolicy(),
        SignalBackend,
        CHARLIE_BARE_JID,
        CHARLIE_DEVICE_ID
    )

    # Make everybody trust each other. In a client you would somehow make the user compare
    # fingerprints, using a QR code for example.
    await alice_session_manager.setTrust(
        BOB_BARE_JID,
        BOB_DEVICE_ID,
        bob_session_manager.public_bundle.ik,
        True
    )

    await alice_session_manager.setTrust(
        CHARLIE_BARE_JID,
        CHARLIE_DEVICE_ID,
        charlie_session_manager.public_bundle.ik,
        True
    )

    await bob_session_manager.setTrust(
        ALICE_BARE_JID,
        ALICE_DEVICE_ID,
        alice_session_manager.public_bundle.ik,
        True
    )

    # In OMEMO the device lists are handled using a pep node.
    # This next part simulates getting the device list from the pep node and telling the
    # session manager about the device lists.
    await alice_session_manager.newDeviceList(ALICE_BARE_JID, [ ALICE_DEVICE_ID ])
    await bob_session_manager.newDeviceList(ALICE_BARE_JID, [ ALICE_DEVICE_ID ])
    await charlie_session_manager.newDeviceList(ALICE_BARE_JID, [ ALICE_DEVICE_ID ])

    await alice_session_manager.newDeviceList(BOB_BARE_JID, [ BOB_DEVICE_ID ])
    await bob_session_manager.newDeviceList(BOB_BARE_JID, [ BOB_DEVICE_ID ])
    await charlie_session_manager.newDeviceList(BOB_BARE_JID, [ BOB_DEVICE_ID ])

    await alice_session_manager.newDeviceList(CHARLIE_BARE_JID, [ CHARLIE_DEVICE_ID ])
    await bob_session_manager.newDeviceList(CHARLIE_BARE_JID, [ CHARLIE_DEVICE_ID ])
    await charlie_session_manager.newDeviceList(CHARLIE_BARE_JID, [ CHARLIE_DEVICE_ID ])

    # You can get the list of (in)active devices for each jid from the session manager.
    # If you don't pass a bare jid, the method assumes your own bare jid.
    aliceDevices        = await alice_session_manager.getDevices()
    aliceBareJIDDevices = await alice_session_manager.getDevices(ALICE_BARE_JID)

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
    initial_message = await alice_session_manager.encryptMessage(
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
    plaintext = await bob_session_manager.decryptMessage(
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
    message = await bob_session_manager.encryptMessage(
        ALICE_BARE_JID,
        "Yo Alice!".encode("UTF-8")
    )

    # Get the message specified for Alice on her only device
    alice_message = message["keys"][ALICE_BARE_JID][ALICE_DEVICE_ID]

    assert(not alice_message["pre_key"])

    plaintext = await alice_session_manager.decryptMessage(
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
    muc_message = await alice_session_manager.encryptMessage(
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

    plaintext = await bob_session_manager.decryptMessage(
        ALICE_BARE_JID,
        ALICE_DEVICE_ID,
        muc_message["iv"],
        bob_message["data"],
        bob_message["pre_key"],
        muc_message["payload"]
    )

    assert(plaintext.decode("UTF-8") == "Hey Bob and Charlie!")

    plaintext = await charlie_session_manager.decryptMessage(
        ALICE_BARE_JID,
        ALICE_DEVICE_ID,
        muc_message["iv"],
        charlie_message["data"],
        charlie_message["pre_key"],
        muc_message["payload"],

        # This flag is required because Charlie does not trust Alice yet.
        allow_untrusted = True
    )

    assert(plaintext.decode("UTF-8") == "Hey Bob and Charlie!")

    # In case something goes badly wrong, you can reset a broken session and replace it
    # with a new one. Assume Alice can't decrypt messages coming from Bob any more. She
    # proceeds to replace her session with Bob with a new one and tells him by sending
    # a RatchetForwardingMessage.
    await alice_session_manager.deleteSession(BOB_BARE_JID, BOB_DEVICE_ID)

    message = await alice_session_manager.encryptRatchetForwardingMessage(
        BOB_BARE_JID,
        {
            BOB_BARE_JID: {
                BOB_DEVICE_ID: bob_session_manager.public_bundle
            }
        }
    )

    # Get the message specified for Bob on his only device
    bob_message = message["keys"][BOB_BARE_JID][BOB_DEVICE_ID]

    # This message is a pre key message, because it initiates a completely new session
    assert(bob_message["pre_key"])

    await bob_session_manager.decryptRatchetForwardingMessage(
        ALICE_BARE_JID,
        ALICE_DEVICE_ID,
        message["iv"],
        bob_message["data"],
        bob_message["pre_key"]
    )

    # Now both parties can send each other messages again!
    # Bob to Alice:
    message = await bob_session_manager.encryptMessage(
        ALICE_BARE_JID,
        "Encrypting via the new session!".encode("UTF-8")
    )

    # Get the message specified for Alice on her only device
    alice_message = message["keys"][ALICE_BARE_JID][ALICE_DEVICE_ID]

    assert(not alice_message["pre_key"])

    plaintext = await alice_session_manager.decryptMessage(
        BOB_BARE_JID,
        BOB_DEVICE_ID,
        message["iv"],
        alice_message["data"],
        alice_message["pre_key"],
        message["payload"]
    )

    assert(plaintext.decode("UTF-8") == "Encrypting via the new session!")

    # ...and Alice to Bob.
    message = await alice_session_manager.encryptMessage(
        BOB_BARE_JID,
        "Hey Bob!".encode("UTF-8")
    )

    bob_message = message["keys"][BOB_BARE_JID][BOB_DEVICE_ID]

    assert(not alice_message["pre_key"])

    plaintext = await bob_session_manager.decryptMessage(
        ALICE_BARE_JID,
        ALICE_DEVICE_ID,
        message["iv"],
        bob_message["data"],
        bob_message["pre_key"],
        message["payload"]
    )

    assert(plaintext.decode("UTF-8") == "Hey Bob!")

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
    await alice_session_manager.newDeviceList(DAVE_BARE_JID, [ DAVE_DEVICE_ID ])
    await bob_session_manager.newDeviceList(DAVE_BARE_JID, [ DAVE_DEVICE_ID ])

    # Create a session manager for Dave that uses the DeletingOTPKPolicy class
    dave_session_manager = await omemo.SessionManager.create(
        InMemoryStorage(),
        DeletingOTPKPolicy,
        SignalBackend,
        DAVE_BARE_JID,
        DAVE_DEVICE_ID
    )

    await dave_session_manager.newDeviceList(ALICE_BARE_JID, [ ALICE_DEVICE_ID ])

    await alice_session_manager.setTrust(
        DAVE_BARE_JID,
        DAVE_DEVICE_ID,
        dave_session_manager.public_bundle.ik,
        True
    )

    await dave_session_manager.setTrust(
        ALICE_BARE_JID,
        ALICE_DEVICE_ID,
        alice_session_manager.public_bundle.ik,
        True
    )

    # Create an initial message from Alice to Dave
    initial_message = await alice_session_manager.encryptMessage(
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
    plaintext = await dave_session_manager.decryptMessage(
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
        plaintext = await dave_session_manager.decryptMessage(
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
    dave_session_manager = await omemo.SessionManager.create(
        InMemoryStorage(),
        KeepingOTPKPolicy,
        SignalBackend,
        DAVE_BARE_JID,
        DAVE_DEVICE_ID
    )

    await dave_session_manager.newDeviceList(ALICE_BARE_JID, [ ALICE_DEVICE_ID ])

    await bob_session_manager.setTrust(
        DAVE_BARE_JID,
        DAVE_DEVICE_ID,
        dave_session_manager.public_bundle.ik,
        True
    )

    await dave_session_manager.setTrust(
        BOB_BARE_JID,
        BOB_DEVICE_ID,
        bob_session_manager.public_bundle.ik,
        True
    )

    # Create an initial message from Bob to Dave
    initial_message = await bob_session_manager.encryptMessage(
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
    plaintext = await dave_session_manager.decryptMessage(
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
    plaintext = await dave_session_manager.decryptMessage(
        BOB_BARE_JID,
        BOB_DEVICE_ID,
        initial_message["iv"],
        dave_message["data"],
        dave_message["pre_key"],
        initial_message["payload"]
    )

    assert(plaintext.decode("UTF-8") == "DeletingOTPKPolicy example")

    return "Done!"

if __name__ == "__main__":
    print(asyncio.run(main()))
