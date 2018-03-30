import omemo

try:
    input = raw_input
except NameError:
    pass

use_alternative = ""
while not use_alternative in [ "y", "n" ]:
    use_alternative = input("Initialize sessions using empty KeyTransportMessages? (y/n): ")
use_alternative = use_alternative == "y"

class InMemoryStorage(omemo.Storage):
    def __init__(self):
        self.__state = None
        self.__bundles = {}
        self.__sessions = {}
        self.__devices = {}

    def loadState(self):
        return self.__state

    def storeState(self, state):
        self.__state = state

    def loadSession(self, jid, device_id):
        return self.__sessions.get(jid, {}).get(device_id, None)

    def storeSession(self, jid, device_id, session):
        self.__sessions[jid] = self.__sessions.get(jid, {})
        self.__sessions[jid][device_id] = session

    def loadActiveDevices(self, jid):
        try:
            return self.__devices[jid]["active"]
        except KeyError:
            return []

    def loadInactiveDevices(self, jid):
        try:
            return self.__devices[jid]["inactive"]
        except KeyError:
            return []

    def storeActiveDevices(self, jid, devices):
        self.__devices[jid] = self.__devices.get(jid, {})
        self.__devices[jid]["active"] = devices

    def storeInactiveDevices(self, jid, devices):
        self.__devices[jid] = self.__devices.get(jid, {})
        self.__devices[jid]["inactive"] = devices

# These values can be retreived from the OMEMO stanzas
ALICE_JID = "alice@alice.alice"
ALICE_DEVICE_ID = 42
ALICE_STORAGE = InMemoryStorage()

BOB_JID = "bob@bob.bob"
BOB_DEVICE_ID = 1337
BOB_STORAGE = InMemoryStorage()

CHARLIE_JID = "charlie@charlie.charlie"
CHARLIE_DEVICE_ID = 935
CHARLIE_STORAGE = InMemoryStorage()

# Each party has to create a SessionManager
alice_session_manager   = omemo.SessionManager(ALICE_JID, ALICE_DEVICE_ID, ALICE_STORAGE)
bob_session_manager     = omemo.SessionManager(BOB_JID, BOB_DEVICE_ID, BOB_STORAGE)
charlie_session_manager = omemo.SessionManager(CHARLIE_JID, CHARLIE_DEVICE_ID, CHARLIE_STORAGE)

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
# - All devices of the Bob
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
bob_message = initial_message["messages"][BOB_JID][BOB_DEVICE_ID]

assert(bob_message["pre_key"])

# Decrypt the initial message.
# This function returns two values:
#     - An AES object, if the message is a KeyTransportElement, otherwise None
#     - The plaintext, if the message is a normal message, otherwise None
# Both values are never set at the same time.

if not use_alternative:
    cipher, plaintext = bob_session_manager.decryptPreKeyMessage(ALICE_JID, ALICE_DEVICE_ID, initial_message["iv"], bob_message["message"], initial_message["payload"])

    assert(cipher == None)
    assert(plaintext.decode("UTF-8") == "Hey Bob!")

# For the alternative way using an empty KeyTransportMessage, the initializaion looks like this:
else:
    cipher, plaintext = bob_session_manager.decryptPreKeyMessage(ALICE_JID, ALICE_DEVICE_ID, initial_message["iv"], bob_message["message"])

    assert(cipher)
    assert(plaintext == None)

# Now, any party can send follow-up messages
# If the session was established before, you don't have to pass the bundle of the other party.
# NOTE: You have to pass all public bundles that might be required to build the sessions
message = bob_session_manager.encryptMessage(ALICE_JID, "Yo Alice!".encode("UTF-8"), bundles)

# Get the message specified for Alice on her only device
alice_message = message["messages"][ALICE_JID][ALICE_DEVICE_ID]

assert(not alice_message["pre_key"])

cipher, plaintext = alice_session_manager.decryptMessage(BOB_JID, BOB_DEVICE_ID, message["iv"], alice_message["message"], message["payload"])

assert(cipher == None)
assert(plaintext.decode("UTF-8") == "Yo Alice!")

# You can encrypt a message for multiple recipients with just one call to encrypt*, just pass a list of jids instead of a single jid:
muc_message = alice_session_manager.encryptMessage([ BOB_JID, CHARLIE_JID ], "Hey Bob and Charlie!".encode("UTF-8"), bundles)

# Get the message specified for Bob on his only device
bob_message = muc_message["messages"][BOB_JID][BOB_DEVICE_ID]

assert(not bob_message["pre_key"])

# Get the message specified for Charlie on his/her only device
charlie_message = muc_message["messages"][CHARLIE_JID][CHARLIE_DEVICE_ID]

assert(charlie_message["pre_key"])

cipher, plaintext = bob_session_manager.decryptMessage(ALICE_JID, ALICE_DEVICE_ID, muc_message["iv"], bob_message["message"], muc_message["payload"])

assert(cipher == None)
assert(plaintext.decode("UTF-8") == "Hey Bob and Charlie!")

cipher, plaintext = charlie_session_manager.decryptPreKeyMessage(ALICE_JID, ALICE_DEVICE_ID, muc_message["iv"], charlie_message["message"], muc_message["payload"])

assert(cipher == None)
assert(plaintext.decode("UTF-8") == "Hey Bob and Charlie!")
