[![PyPI](https://img.shields.io/pypi/v/OMEMO.svg)](https://pypi.org/project/OMEMO/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/OMEMO.svg)](https://pypi.org/project/OMEMO/)

# python-omemo
#### A Python implementation of the OMEMO Multi-End Message and Object Encryption protocol.

This python library offers an open implementation of the OMEMO Multi-End Message and Object Encryption protocol as specified [here](https://xmpp.org/extensions/xep-0384.html).

Goals of this implementation are:
- Do not use libsignal but offer a solid alternative to it
- Stay away from GPL (not possible until we move away from libsignals wireformat)
- Be flexible to changes that might happen to the OMEMO protocol
- Keep the structure close to the spec
- Provide the parts of the protocol (X3DH, Double Ratchet) as own repositories
- Perhaps serve as the reference implementation for XEP-0384 in the future

This library uses the [X3DH](https://github.com/Syndace/python-x3dh) and [DoubleRatchet](https://github.com/Syndace/python-doubleratchet) libraries, configures them with the parameters that OMEMO uses and offers a set of utility functions to work with the OMEMO wire format.

The current OMEMO standard copies its parameters from libsignal.
The libsignal conforming implementation can be found in the submodule signal, it is set as default currently.
The default might get swapped in a future version to seamlessly update software using this library to a newer protocol standard (except for updates to the wire format probably).

This library does NOT manage XML/stanzas.

## Quick start / basic usage

### Overview

There are two big parts in the protocol:
- Session creation/key exchange using X3DH
- Message en-/ decryption using DoubleRatchet

### Session creation / X3DH
_Note_: A basic example can be found in `examples/x3dh_get_shared_secret.py`, a more complete one including en-/ decryption in `examples/x3dh_double_ratchet.py`.

Each device publishes a so-called "public bundle", which can be used by other devices to initiate a session.

#### Creating my public bundle

The public bundle is managed by the `x3dh.State` class, which is implemented by the `X3DHDoubleRatchet` class.
The `X3DHDoubleRatchet` class is the core class of OMEMO, combining all lose parts.

```Python
import omemo

state = omemo.X3DHDoubleRatchet()
```

The `X3DHDoubleRatchet` class itself does not offer ways to serialize itself, use the `pickle` module to conveniently dump and load the whole object:

```Python
import pickle

# To store a state to a file called "state.pickle"
pickle.dump(state, open("state.pickle", "wb"), pickle.HIGHEST_PROTOCOL)

# To load a state that was stored to "state.pickle" before
state = pickle.load(open("state.pickle", "rb"))
```

#### Getting my public bundle
To get the public bundle (e.g. to publish it to your devices pubsub node), the `getPublicBundle` returns the bundle as an instance of the `x3dh.PublicBundle` class.

#### Detecting changes to the bundle
If the public bundle was changed, e.g. after a new session was initiated, the changed bundle must be republished.
The `State` class offers a convenient way to detect such changes: A read-only flag called `changed`, which clears itself as soon as it's read.

### The easy way

There is a `SessionManager` class, which does most of the work for you.
Find a commented example in the `examples/sessions.py` file, which should be all you need.

### The not so easy way

To understand, what the `SessionManager` does, this next section contains a summary of the classes/modules that OMEMO consists of.

#### Initiating a session

```Python
# Actively initiate a session, using the public bundle of the device you want to crypt-chat with
active_session_data = active_state.initSessionActive(other_public_bundle)

# The DoubleRatchet for the sender is already initialized:
active_double_ratchet = active_session_data["dr"]

# Now send the active_session_data["to_other"] to the target device, along the first encrypted message

# Passively initiate a session, using the session initialization data provided by the active device
# The call on the passive side returns the DoubleRatchet directly
passive_double_ratchet = passive_state.initSessionPassive(active_session_data["to_other"])

# As a result, both calls initiate their respective DoubleRatchets, which can now be used to exchange encrypted data between both devices
```

### Encrypted data exchange
_Note_: A basic code example can be found in `examples/dr_chat.py`, a more complete one including key exchange in `examples/x3dh_double_ratchet.py`.

The exchange of encrypted data is handled by the `doubleratchet.ratchets.DoubleRatchet` class.

#### Encrypting data
Encrypting a message is as simple as:
```Python
message = sender_dr.encryptMessage(msg)

# Use the associated data and the authentication key to authenticate the data
associated_data = message["ad"]
authentication_key = message["authentication_key"]

# Send the ciphertext and the header:
ciphertext = message["ciphertext"]
header = message["header"]
```

#### Decrypting data
Decryption is just as simple:
```Python
message = receiver_dr.decryptMessage(ciphertext, header)

# Use the associated data and the authentication key to authenticate the data
associated_data = message["ad"]
authentication_key = message["authentication_key"]

# Get the plaintext
plaintext = message["plaintext"]
```

The DoubleRatchet internally cares about lost/delayed messages and stores keys of missing messages for later (up to a configurable amount of messages).
The header contains all information required for synchronization between the senders and the receivers ratchets.

### Wireformat
The current OMEMO standard uses Google Protobuf (and base64) to transfer:
- The session initialization data
- The message headers
- The encrypted message

The `omemo.wireformat` module contains helpers to interact with these formats.

There are two message types in the OMEMO protocol:
- SignalMessage
- PreKeySignalMessage

#### SignalMessage
A SignalMessage contains the message header required to synchronize the DoubleRatchets aswell as to decrypt the message payload.
It is the type of message that you receive whenever an OMEMO encrypted message is sent to you.

The `omemo.wireformat.message_header` file offers the `toWire` and `fromWire` functions:
```Python
from omemo import wireformat

# For the sender:
message = sender_dr.encryptMessage(msg)

data = wireformat.message_header.toWire(message["ciphertext"], message["header"], message["ad"], message["authentication_key"])

# For the receiver:
message = wireformat.message_header.fromWire(data)

decrypted = receiver_dr.decryptMessage(message["ciphertext"], message["header"])

wireformat.message_header.checkAuthentication(data, decrypted["ad"], decrypted["authentication_key"])

plaintext = decrypted["plaintext"]
```

#### PreKeySignalMessage
This message type is basically a combination of a SignalMessage and the session initialization data.
This message type is used to transparently build sessions with the first exchanged message.

The `toWire` and `fromWire` helpers can be found in the `omemo.wireformat.pre_key_message_header` file.

```Python
from omemo import wireformat

# For the sender:
active_session_data = active_state.initSessionActive(other_public_bundle)

# Encrypt an initial message and create a SignalMessage as described in the previous section

data = wireformat.pre_key_message_header.toWire(active_session_data["to_other"], signal_message)

# For the receiver
message_and_init_data = wireformat.pre_key_message_header.fromWire(data)

passive_dr = passive_state.initSessionPassive(message_and_init_data["session_init_data"])

# Unpack the SignalMessage found in message_and_init_data["message"] as described in the previous section
```

And that's about all you need!

## Contributing

Generally, I am happy about anyone reading/using my code, opening issues, creating pull requests and all of that good stuff GitHub offers.

But there are a few more specific things I'd like a little help with:
- Check the licensing. I really don't want to violate any of the licenses, all these awesome open source creators shall be paid respect. The REQUIREMENTS file contains all of the used libraries and their respective licenses.
- Check the cryptography. I am not a cryptographer, I have never created a security-critical library like this before. Please check through the code and help this library to become a little more secure.
- DevOps. I have never done DevOps like CI / automated tests / advanced build system before, I think there are a few things that make a lot of sense though and I need a little help to set it all up and to decide what is useful.

## Notice
This library is currently in a very early state, most of the code has not been tested at all, there are probably bugs.
