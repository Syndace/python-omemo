from __future__ import print_function

import omemo

import json
import pickle
import time
import traceback

from util import nonThrowingMakedirs

try:
    input = raw_input
except NameError:
    pass

deferred = {
    "a": [],
    "b": []
}

def loop(alice_dr, bob_dr, use_wireformat = False):
    global deferred

    print("a: Write a message from Alice to Bob")
    print("b: Write a message from Bob to Alice")
    print("da: Send a deferred message from Alice to Bob")
    print("db: Send a deferred message from Bob to Alice")
    print("q: Quit")

    action = input("Action: ")

    if action == "a":
        sender = "Alice"
        receiver = "Bob"
        sender_dr = alice_dr
        receiver_dr = bob_dr

    if action == "b":
        sender = "Bob"
        receiver = "Alice"
        sender_dr = bob_dr
        receiver_dr = alice_dr

    if action in ["a", "b"]:
        # Ask for the message to send
        msg = input(sender + " to " + receiver + ": ")

        # Encrypt the message for the receiver
        message = sender_dr.encryptMessage(msg.encode("UTF-8"))

        if use_wireformat:
            message = omemo.wireformat.message_header.toWire(
                message["ciphertext"]["ciphertext"],
                message["header"],
                message["ciphertext"]["ad"],
                message["ciphertext"]["authentication_key"]
            )
            # Send to the receiver...
        else:
            message["ciphertext"] = message["ciphertext"]["ciphertext"]

        while True:
            send_or_defer = input("Send the message or defer it for later? (s or d): ")
            if send_or_defer in ["s", "d"]:
                break

        if send_or_defer == "s":
            print("Sending the message to " + receiver)

            if use_wireformat:
                message_decoded = omemo.wireformat.message_header.fromWire(message)
            else:
                message_decoded = message

            # Now the receiver can decrypt the message
            plaintext = receiver_dr.decryptMessage(
                message_decoded["ciphertext"],
                message_decoded["header"]
            )

            if use_wireformat:
                # Check the authentication
                omemo.wireformat.message_header.checkAuthentication(
                    message_decoded["mac"],
                    message_decoded["auth_data"],
                    plaintext["ad"],
                    plaintext["authentication_key"]
                )

            print(receiver + " received:", plaintext["plaintext"].decode("UTF-8"))

        if send_or_defer == "d":
            print("Saving the message for later")
            deferred[action].append({ "plaintext": msg, "ciphertext_header": message })

    if action == "da":
        receiver = "Bob"
        receiver_dr = bob_dr

    if action == "db":
        receiver = "Alice"
        receiver_dr = alice_dr

    if action in ["da", "db"]:
        deferred_local = deferred[action[1:]]

        if len(deferred_local) == 0:
            print(
                "No messages deferred. " +
                "Create a message first using a or b and select to defer it when asked."
            )
        else:
            print("Select a message that was deferred earlier:")

            counter = 0
            for msg in deferred_local:
                print(str(counter) + ": " + msg["plaintext"])
                counter += 1

            while True:
                msg_index = int(input("Message index: "))
                if msg_index >= 0 and msg_index < len(deferred_local):
                    break

            message = deferred_local.pop(msg_index)["ciphertext_header"]

            if use_wireformat:
                message_decoded = omemo.wireformat.message_header.fromWire(message)
            else:
                message_decoded = message

            print("Sending the message to " + receiver)

            # Now the receiver can decrypt the message
            plaintext = receiver_dr.decryptMessage(
                message_decoded["ciphertext"],
                message_decoded["header"]
            )

            if use_wireformat:
                # Check the authentication
                omemo.wireformat.message_header.checkAuthentication(
                    message_decoded["mac"],
                    message_decoded["auth_data"],
                    plaintext["ad"],
                    plaintext["authentication_key"]
                )

            print(receiver + " received:", plaintext["plaintext"].decode("UTF-8"))

    return action != "q"

def mainLoop(alice_dr, bob_dr, use_wireformat = False):
    while True:
        try:
            if not loop(alice_dr, bob_dr, use_wireformat):
                break
        except Exception:
            print("Exception raised while processing:")
            traceback.print_exc()
            time.sleep(0.5)

        print("")
        print("")

# The shared secret and associated data must be negotiated before starting the
# ratcheting session, using X3DH in case of OMEMO.
def main(shared_secret, associated_data):
    global deferred

    nonThrowingMakedirs("dr_chat")

    try:
        # Look for stored ratchets and deferred messages
        with open("dr_chat/bob_dr.json") as f:
            bob_dr = omemo.doubleratchet.DoubleRatchet.fromSerialized(json.load(f))

        with open("dr_chat/alice_dr.json") as f:
            alice_dr = omemo.doubleratchet.DoubleRatchet.fromSerialized(json.load(f))

        with open("dr_chat/deferred.pickle", "rb") as f:
            deferred = pickle.load(f)
    except IOError:
        print("Loading failed, creating fresh data...")

        # Create Bob's DoubleRatchet with just the shared secret.
        bob_dr = omemo.doubleratchet.DoubleRatchet(associated_data, shared_secret)

        # Create Alice's DoubleRatchet, passing Bob's encryption key to the initializer.
        alice_dr = omemo.doubleratchet.DoubleRatchet(
            associated_data,
            shared_secret,
            other_enc = bob_dr.enc
        )

    # Now Alice is set up to send a first message to Bob,
    # while Bob is not yet initialized and cannot send Alice any message.
    mainLoop(alice_dr, bob_dr)

    # Store the ratchets for later
    with open("dr_chat/bob_dr.json", "w") as f:
        json.dump(bob_dr.serialize(), f)

    with open("dr_chat/alice_dr.json", "w") as f:
        json.dump(alice_dr.serialize(), f)

    with open("dr_chat/deferred.pickle", "wb") as f:
        pickle.dump(deferred, f)
    
if __name__ == "__main__":
    main(b"\x42" * 42, {
        "IK_own"   : b"\x13\x37" * 16,
        "IK_other" : b"\x09\x35" * 16
    })
