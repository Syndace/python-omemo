from __future__ import print_function

import logging
import omemo
import x3dh

from deletingotpkpolicy import DeletingOTPKPolicy
from example_data import *
from inmemorystorage import InMemoryStorage

logging.basicConfig(level = logging.DEBUG)

try:
    input = raw_input
except NameError:
    pass

use_alternative = ""
while not use_alternative in [ "y", "n" ]:
    use_alternative = input("Initialize sessions using empty KeyTransportMessages? (y/n): ")
use_alternative = use_alternative == "y"

# Each party has to create a SessionManager
alice_session_manager   = omemo.SessionManager(ALICE_JID, InMemoryStorage(), DeletingOTPKPolicy, ALICE_DEVICE_ID)
bob_session_manager     = omemo.SessionManager(BOB_JID, InMemoryStorage(), DeletingOTPKPolicy, BOB_DEVICE_ID)
charlie_session_manager = omemo.SessionManager(CHARLIE_JID, InMemoryStorage(), DeletingOTPKPolicy, CHARLIE_DEVICE_ID)

try:
    # You have to provide a device id for the first creation of the SessionManager.
    # From then on, the session manager retrieves the id from the storage.
    omemo.SessionManager("exception", InMemoryStorage(), DeletingOTPKPolicy)
    assert(False)
except omemo.exceptions.SessionManagerException:
    pass

# In OMEMO the device lists are handled using a pep node.
# This next part simulates getting the device list from the pep node and telling the session manager about the device lists.
alice_session_manager.newDeviceList([ ALICE_DEVICE_ID ], ALICE_JID)
bob_session_manager.newDeviceList([ ALICE_DEVICE_ID ], ALICE_JID)
charlie_session_manager.newDeviceList([ ALICE_DEVICE_ID ], ALICE_JID)

alice_session_manager.newDeviceList([ BOB_DEVICE_ID ], BOB_JID)
bob_session_manager.newDeviceList([ BOB_DEVICE_ID ], BOB_JID)
charlie_session_manager.newDeviceList([ BOB_DEVICE_ID ], BOB_JID)

alice_session_manager.newDeviceList([ CHARLIE_DEVICE_ID ], CHARLIE_JID)
bob_session_manager.newDeviceList([ CHARLIE_DEVICE_ID ], CHARLIE_JID)
charlie_session_manager.newDeviceList([ CHARLIE_DEVICE_ID ], CHARLIE_JID)

assert(alice_session_manager.getDevices()["active"] == set([ ALICE_DEVICE_ID ]))
assert(alice_session_manager.getDevices(ALICE_JID)["active"] == set([ ALICE_DEVICE_ID ]))

bundles = {
    ALICE_JID: {
        ALICE_DEVICE_ID: alice_session_manager.state.getPublicBundle()
    },
    BOB_JID: {
        BOB_DEVICE_ID: bob_session_manager.state.getPublicBundle()
    },
    CHARLIE_JID: {
        CHARLIE_DEVICE_ID: charlie_session_manager.state.getPublicBundle()
    }
}

# Send an initial message from Alice to Bob
# The message is built for:
# - All devices of Bob
# - All devices of Alice, except for the sending device
# NOTE: You have to pass all public bundles that might be required to build the sessions
if not use_alternative:
    initial_message = alice_session_manager.encryptMessage(BOB_JID, "Hey Bob!".encode("UTF-8"), bundles)

# Alternatively, you can use the buildSession method to initiate a session with a device directly, by sending an empty KeyTransportMessage to it:
else:
    initial_message = alice_session_manager.buildSession(BOB_JID, BOB_DEVICE_ID, bob_session_manager.state.getPublicBundle())

# The values
# - initial_message["iv"]
# - initial_message["messages"]
# - initial_message["payload"]
# should contain everything you need to build a stanza and send it.

# Get the message specified for Bob on his only device
bob_message = [ x for x in initial_message["messages"] if x["rid"] == BOB_DEVICE_ID ][0]

assert(bob_message["pre_key"])

# Decrypt the initial message.
# This function returns two values:
#     - An AES object, if the message is a KeyTransportElement, otherwise None
#     - The plaintext, if the message is a normal message, otherwise None
# Both values are never set at the same time.

if not use_alternative:
    # The parameters should be straight forward except for the False: This parameter is used to indicate, whether this pre key message was received directly or from a storage mechanism e.g. MAM.
    cipher, plaintext = bob_session_manager.decryptPreKeyMessage(ALICE_JID, ALICE_DEVICE_ID, initial_message["iv"], bob_message["message"], False, initial_message["payload"])

    assert(cipher == None)
    assert(plaintext.decode("UTF-8") == "Hey Bob!")

# For the alternative way using an empty KeyTransportMessage, the initializaion looks like this:
else:
    cipher, plaintext = bob_session_manager.decryptPreKeyMessage(ALICE_JID, ALICE_DEVICE_ID, initial_message["iv"], bob_message["message"], False)

    assert(cipher)
    assert(plaintext == None)

# Now, any party can send follow-up messages
# If the session was established before, you don't have to pass the bundle of the other party.
message = bob_session_manager.encryptMessage(ALICE_JID, "Yo Alice!".encode("UTF-8"), bundles)

# Get the message specified for Alice on her only device
alice_message = [ x for x in message["messages"] if x["rid"] == ALICE_DEVICE_ID ][0]

assert(not alice_message["pre_key"])

cipher, plaintext = alice_session_manager.decryptMessage(BOB_JID, BOB_DEVICE_ID, message["iv"], alice_message["message"], message["payload"])

assert(cipher == None)
assert(plaintext.decode("UTF-8") == "Yo Alice!")

# You can encrypt a message for multiple recipients with just one call to encrypt*, just pass a list of jids instead of a single jid:
muc_message = alice_session_manager.encryptMessage([ BOB_JID, CHARLIE_JID ], "Hey Bob and Charlie!".encode("UTF-8"), bundles)

# Get the message specified for Bob on his only device
bob_message = [ x for x in muc_message["messages"] if x["rid"] == BOB_DEVICE_ID ][0]

assert(not bob_message["pre_key"])

# Get the message specified for Charlie on his/her only device
charlie_message = [ x for x in muc_message["messages"] if x["rid"] == CHARLIE_DEVICE_ID ][0]

assert(charlie_message["pre_key"])

cipher, plaintext = bob_session_manager.decryptMessage(ALICE_JID, ALICE_DEVICE_ID, muc_message["iv"], bob_message["message"], muc_message["payload"])

assert(cipher == None)
assert(plaintext.decode("UTF-8") == "Hey Bob and Charlie!")

cipher, plaintext = charlie_session_manager.decryptPreKeyMessage(ALICE_JID, ALICE_DEVICE_ID, muc_message["iv"], charlie_message["message"], False, muc_message["payload"])

assert(cipher == None)
assert(plaintext.decode("UTF-8") == "Hey Bob and Charlie!")

#################
# OTPK handling #
#################

# This section gives an insight into the one-time pre key management.
# One-time pre key are part of the handshake protocol used by OMEMO, called X3DH or extended triple diffie hellman.
# This protocol requires you to generate a list of keys and publish them somehow, the so-called public bundle.
# Every time you handshake with someone else, you select one of his published keys and use it to derive a shared secret.
# After one of these one-time pre keys is used, the specification tells you to delete the corresponding private key.
# But there is one problem: The specification does neither account for lost or delayed packet, nor for the case of two packets in a row without a response in between.
# For that reason, there is a major usability drawback if all keys get deleted instantly after the first use.

# This is where the OTPK policy comes in: Instead of deleting the keys instantly, you can override the OTPKPolicy class and use it to decide yourself, whether to delete the key or not.

# Let's look at the simplest implementation of the OTPKPolicy: The implementation, that simply always deletes the keys, no matter what. Look at the DeletingOTPKPolicy class for this implementation.

# To see how it works, we try to initiate a session two times using the same OTPK. This should result in an exception on the second initiation, because the policy deleted the key after its first use.

# Tell Alice' and Bobs session managers about Dave and his device
alice_session_manager.newDeviceList([ DAVE_DEVICE_ID ], DAVE_JID)
bob_session_manager.newDeviceList([ DAVE_DEVICE_ID ], DAVE_JID)

# Create a session manager for Dave that uses the DeletingOTPKPolicy class
dave_session_manager = omemo.SessionManager(DAVE_JID, InMemoryStorage(), DeletingOTPKPolicy, DAVE_DEVICE_ID)
dave_session_manager.newDeviceList([ ALICE_DEVICE_ID ], ALICE_JID)

# Create an initial message from Alice to Dave
initial_message = alice_session_manager.buildSession(DAVE_JID, DAVE_DEVICE_ID, dave_session_manager.state.getPublicBundle())

# Get the message specified for Dave on his only device
dave_message = [ x for x in initial_message["messages"] if x["rid"] == DAVE_DEVICE_ID ][0]

assert(dave_message["pre_key"])

# Let Dave initialize the session for the first time, this should work fine
cipher, plaintext = dave_session_manager.decryptPreKeyMessage(ALICE_JID, ALICE_DEVICE_ID, initial_message["iv"], dave_message["message"], False)

assert(cipher)
assert(plaintext == None)

# Daves public bundle should have the "changed" flag set and it should not contain the used pre key any more
assert(dave_session_manager.state.changed)
assert(len(dave_session_manager.state.getPublicBundle().otpks) == 99)

# Now, try the same thing a second time. This sould raise an exception
try:
    cipher, plaintext = dave_session_manager.decryptPreKeyMessage(ALICE_JID, ALICE_DEVICE_ID, initial_message["iv"], dave_message["message"], False)
    assert(False) # This line should not execute
except x3dh.exceptions.SessionInitiationException:
    pass

# Finally, let's do the same thing but using a policy that never deletes keys instead of always:
class KeepingOTPKPolicy(omemo.OTPKPolicy):
    @staticmethod
    def decideOTPK(data):
        return True

# Create a session manager for Dave that uses the KeepingOTPKPolicy class
dave_session_manager = omemo.SessionManager(DAVE_JID, InMemoryStorage(), KeepingOTPKPolicy, DAVE_DEVICE_ID)
dave_session_manager.newDeviceList([ BOB_DEVICE_ID ], BOB_JID)

# Create an initial message from Bob to Dave
initial_message = bob_session_manager.buildSession(DAVE_JID, DAVE_DEVICE_ID, dave_session_manager.state.getPublicBundle())

# Get the message specified for Dave on his only device
dave_message = [ x for x in initial_message["messages"] if x["rid"] == DAVE_DEVICE_ID ][0]

assert(dave_message["pre_key"])

# Let Dave initialize the session for the first time, this should work fine
cipher, plaintext = dave_session_manager.decryptPreKeyMessage(BOB_JID, BOB_DEVICE_ID, initial_message["iv"], dave_message["message"], False)

assert(cipher)
assert(plaintext == None)

# Daves public bundle should have the "changed" flag set and it should not contain the used pre key any more
assert(dave_session_manager.state.changed)
assert(len(dave_session_manager.state.getPublicBundle().otpks) == 99)

# Now, the second try should work aswell, because the policy decided to keep the OTPK
cipher, plaintext = dave_session_manager.decryptPreKeyMessage(BOB_JID, BOB_DEVICE_ID, initial_message["iv"], dave_message["message"], False)

assert(cipher)
assert(plaintext == None)
