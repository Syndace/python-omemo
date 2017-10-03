import omemo
from omemo import wireformat

import sys

from dr_chat import mainLoop

try:
    input = raw_input
except NameError:
    pass

def main(who, use_wireformat = False):
    alice_state = omemo.X3DHDoubleRatchet()
    bob_state = omemo.X3DHDoubleRatchet()

    alice_public_bundle = alice_state.getPublicBundle()
    bob_public_bundle = bob_state.getPublicBundle()

    if use_wireformat:
        # Ask for the initial message to send
        initial_message = input("Initial message: ")

    if who == "a":
        # Prepare the session init data and the DoubleRatchet from the active part
        session_init_data = alice_state.initSessionActive(bob_public_bundle)
        alice_dr = session_init_data["dr"]
        session_init_data = session_init_data["to_other"]

        if use_wireformat:
            # Encrypt the initial message
            initial_message_encrypted = alice_dr.encryptMessage(initial_message.encode("UTF-8"))

            # Prepare the message
            initial_message_serialized = wireformat.message_header.toWire(
                initial_message_encrypted["ciphertext"],
                initial_message_encrypted["header"],
                initial_message_encrypted["ad"],
                initial_message_encrypted["authentication_key"]
            )

            # Bundle the session init data and the initial message into a pre_key packet
            initial_pre_key_message_serialized = wireformat.pre_key_message_header.toWire(session_init_data, initial_message_serialized)

            # Send to the receiver...

            # Unpack the session init data into the initial message
            initial_pre_key_message = wireformat.pre_key_message_header.fromWire(initial_pre_key_message_serialized)
            initial_message_serialized = initial_pre_key_message["message"]

            # Unpack the contained message
            initial_message_encrypted = wireformat.message_header.fromWire(initial_message_serialized)

            # Create the session for the passive part
            bob_dr = bob_state.initSessionPassive(initial_pre_key_message["session_init_data"])
            
            # Decrypt the initial message
            initial_message = bob_dr.decryptMessage(initial_message_encrypted["ciphertext"], initial_message_encrypted["header"])

            # Authenticate the data
            wireformat.message_header.checkAuthentication(initial_message_serialized, initial_message["ad"], initial_message["authentication_key"])

            initial_message_plaintext = initial_message["plaintext"].decode("UTF-8")
        else:
            # Otherwise, just initialize the passive session directly
            bob_dr = bob_state.initSessionPassive(session_init_data)

    if who == "b":
        session_init_data = bob_state.initSessionActive(alice_public_bundle)
        bob_dr = session_init_data["dr"]
        session_init_data = session_init_data["to_other"]

        if use_wireformat:
            # Encrypt the initial message
            initial_message_encrypted = bob_dr.encryptMessage(initial_message.encode("UTF-8"))

            # Prepare the message
            initial_message_serialized = wireformat.message_header.toWire(
                initial_message_encrypted["ciphertext"],
                initial_message_encrypted["header"],
                initial_message_encrypted["ad"],
                initial_message_encrypted["authentication_key"]
            )

            # Bundle the session init data and the initial message into a pre_key packet
            initial_pre_key_message_serialized = wireformat.pre_key_message_header.toWire(session_init_data, initial_message_serialized)

            # Send to the receiver...

            # Unpack the session init data into the initial message
            initial_pre_key_message = wireformat.pre_key_message_header.fromWire(initial_pre_key_message_serialized)
            initial_message_serialized = initial_pre_key_message["message"]

            # Unpack the contained message
            initial_message_encrypted = wireformat.message_header.fromWire(initial_message_serialized)

            # Create the session for the passive part
            alice_dr = alice_state.initSessionPassive(initial_pre_key_message["session_init_data"])
            
            # Decrypt the initial message
            initial_message = alice_dr.decryptMessage(initial_message_encrypted["ciphertext"], initial_message_encrypted["header"])

            # Authenticate the data
            wireformat.message_header.checkAuthentication(initial_message_serialized, initial_message["ad"], initial_message["authentication_key"])

            initial_message_plaintext = initial_message["plaintext"].decode("UTF-8")
        else:
            # Otherwise, just initialize the passive session directly
            alice_dr = alice_state.initSessionPassive(session_init_data)

    if use_wireformat:
        print("Initial message received: " + initial_message_plaintext)

    mainLoop(alice_dr, bob_dr, use_wireformat)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        while True:
            who = input("Who should actively initialize the session? (a or b): ")
            if who in ["a", "b"]:
                break

        while True:
            use_wireformat = input("Use the wireformat? (y or n): ")
            if use_wireformat in ["y", "n"]:
                break
    else:
        who = sys.argv[1]
        use_wireformat = sys.argv[2]

    main(who, use_wireformat == "y")
