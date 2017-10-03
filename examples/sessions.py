import omemo

# These values can be retreived from the OMEMO stanzas
ALICE_JID = "alice@alice.alice"
ALICE_DEVICE_ID = 42

BOB_JID = "bob@bob.bob"
BOB_DEVICE_ID = 1337

# Each party has to create a SessionManager
alice_session_manager = omemo.SessionManager(ALICE_JID, ALICE_DEVICE_ID)
bob_session_manager   = omemo.SessionManager(BOB_JID, BOB_DEVICE_ID)

# Store the public bundles of the respective parties
alice_session_manager.setPublicBundle(BOB_JID, BOB_DEVICE_ID, bob_session_manager.getPublicBundle())
bob_session_manager.setPublicBundle(ALICE_JID, ALICE_DEVICE_ID, alice_session_manager.getPublicBundle())

# Send an initial message from Alice to Bob
# The message is built for:
# - All devices of the Bob
# - All devices of Alice, except for the sending device
initial_message = alice_session_manager.encryptMessage(BOB_JID, "Hey Bob!".encode("UTF-8"))

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
cipher, plaintext = bob_session_manager.decryptPreKeyMessage(ALICE_JID, ALICE_DEVICE_ID, initial_message["iv"], bob_message["message"], initial_message["payload"])

assert(cipher == None)
assert(plaintext.decode("UTF-8") == "Hey Bob!")

# Now, any party can send follow-up messages
# If the session was established before, you don't have to pass the bundle of the other party.
message = bob_session_manager.encryptMessage(ALICE_JID, "Yo Alice!".encode("UTF-8"))

# Get the message specified for Alice on her only device
alice_message = message["messages"][ALICE_JID][ALICE_DEVICE_ID]

assert(not alice_message["pre_key"])

cipher, plaintext = alice_session_manager.decryptMessage(BOB_JID, BOB_DEVICE_ID, message["iv"], alice_message["message"], message["payload"])

assert(cipher == None)
assert(plaintext.decode("UTF-8") == "Yo Alice!")
