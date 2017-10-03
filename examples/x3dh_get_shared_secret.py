from __future__ import print_function

import omemo

import pickle
import sys

from util import nonThrowingMakedirs

try:
    input = raw_input
except NameError:
    pass

def main(who):
    nonThrowingMakedirs("x3dh_get_shared_secret")

    try:
        # Look for stored ratchets and deferred messages
        state_alice = pickle.load(open("x3dh_get_shared_secret/state_alice.pickle", "rb"))
        state_bob = pickle.load(open("x3dh_get_shared_secret/state_bob.pickle", "rb"))
    except IOError:
        state_alice = omemo.x3dh.State()
        state_bob = omemo.x3dh.State()

    alice_public_bundle = state_alice.getPublicBundle()
    bob_public_bundle = state_bob.getPublicBundle()

    print("Alice SPK id:", alice_public_bundle.spk["id"])
    print("Alice first OTPK id:", alice_public_bundle.otpks[0]["id"])

    print("Bob SPK id:", bob_public_bundle.spk["id"])
    print("Bob first OTPK id:", bob_public_bundle.otpks[0]["id"])

    if who == "a":
        session_init_data = state_alice.initSessionActive(bob_public_bundle)
        other_session_data = state_bob.initSessionPassive(session_init_data["to_other"])

    if who == "b":
        session_init_data = state_bob.initSessionActive(alice_public_bundle)
        other_session_data = state_alice.initSessionPassive(session_init_data["to_other"])

    if session_init_data["sk"] == other_session_data["sk"] and session_init_data["ad"] == other_session_data["ad"]:
        print("Alice and Bob derived the same secrets and ads! Success!")
    else:
        print("Alice and Bob derived different secrets or different ads. Failure.")

    pickle.dump(state_alice, open("x3dh_get_shared_secret/state_alice.pickle", "wb"), pickle.HIGHEST_PROTOCOL)
    pickle.dump(state_bob, open("x3dh_get_shared_secret/state_bob.pickle", "wb"), pickle.HIGHEST_PROTOCOL)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        while True:
            who = input("Who should actively initialize the session? (a or b): ")
            if who in ["a", "b"]:
                break
    else:
        who = sys.argv[1]

    main(who)
