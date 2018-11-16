[![PyPI](https://img.shields.io/pypi/v/OMEMO.svg)](https://pypi.org/project/OMEMO/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/OMEMO.svg)](https://pypi.org/project/OMEMO/)
[![Build Status](https://travis-ci.org/Syndace/python-omemo.svg?branch=master)](https://travis-ci.org/Syndace/python-omemo)

# python-omemo
#### A Python implementation of the OMEMO Multi-End Message and Object Encryption protocol.

This python library offers an open implementation of the OMEMO Multi-End Message and Object Encryption protocol as specified [here](https://xmpp.org/extensions/xep-0384.html).

Goals of this implementation are:
- Do not depend on libsignal but offer a solid alternative to it
- Stay away from GPL (this repo will soon switch to MIT)
- Be flexible to changes that might happen to the OMEMO protocol
- Keep the structure close to the spec
- Provide the parts of the protocol (X3DH, Double Ratchet) as own projects

This library uses the [X3DH](https://github.com/Syndace/python-x3dh) and [DoubleRatchet](https://github.com/Syndace/python-doubleratchet) libraries, configures them with the parameters that OMEMO uses and manages all encryption sessions for you.

This library does NOT manage XML/stanzas.

## Usage

#### Choose a backend

To use this library you have to choose a backend first. Currently, you don't have a lot of choice: The only available backend is a backend offering libsignal compatibility, found [here](https://github.com/Syndace/python-omemo-backend-signal). Install your backend of choice and proceed to the next step.

#### Implement the Storage interface

The library has a lot of state/data that it has to persist between runs. To be as flexible as possible the library leaves it open for you to decide how to store the data. Simply implement the `Storage` interface found in `storage.py`. The file contains more info about how to implement the interface.

#### Decide on a one-time pre key policy

This part is kind of tricky as it requires a lot of knowledge about how the protocol works. Basically the key exchange mechanism used by the protocol assumes guaranteed message delivery and a response to the first message before another message is sent. Both conditions are not quite given in all environments, especially not in XMPP, which is the main use-case for this library. For that reason the library has to "relax" some of the protocols rules. Instead of always instantly deleting the keys used in the key exchange, it is now up to you to decide whether to keep keys or not. To do so, implement the `OTPKPolicy` interface found in `otpkpolicy.py`. The file contains more info about how to implement the interface.

Note: One of the following releases will contain a default policy that tries to find a good balance between security and usability.

#### Create a SessionManager

Now that you have selected a backend, decided on how to store the data and when to delete the key exchange keys, it's time to create an instance of the core class of this library: the SessionManager.

The SessionManager handles message en- and decryption with all your contacts, trying to make it as easy as possible for you. The file `examples/sessions.py` contains a lot of well-commented code that shows how to create and use a SessionManager.
