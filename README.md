[![PyPI](https://img.shields.io/pypi/v/OMEMO.svg)](https://pypi.org/project/OMEMO/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/OMEMO.svg)](https://pypi.org/project/OMEMO/)
[![Build Status](https://travis-ci.org/Syndace/python-omemo.svg?branch=master)](https://travis-ci.org/Syndace/python-omemo)

# python-omemo
#### A Python implementation of the OMEMO Multi-End Message and Object Encryption protocol.

This python library offers an open implementation of the OMEMO Multi-End Message and Object Encryption protocol as specified [here](https://xmpp.org/extensions/xep-0384.html).

Goals of this implementation are:
- Do not depend on libsignal but offer a solid alternative to it
- Stay away from GPL
- Be flexible to changes that might happen to the OMEMO protocol
- Keep the structure close to the spec
- Provide the parts of the protocol (X3DH, Double Ratchet) as own projects

This library uses the [X3DH](https://github.com/Syndace/python-x3dh) and [DoubleRatchet](https://github.com/Syndace/python-doubleratchet) libraries, configures them with the parameters that OMEMO uses and manages all encryption sessions for you.

This library does NOT manage XML/stanzas.

## Installation

### pip

You can install this library and all of its dependencies via pip:

```Bash
$ pip install OMEMO
```

### AUR

Ppjet6 kindly maintains AUR packages of both the current master and the latest release:

| Release/Branch | Link                                                                         |
|:-------------- |:----------------------------------------------------------------------------:|
| current master | [*\*click\**](https://aur.archlinux.org/packages/python-omemo-syndace/)      |
| latest release | [*\*click\**](https://aur.archlinux.org/packages/python-omemo-syndace-git/)  |

## Usage

### Choose a backend

To use this library you have to choose a backend first. Currently, you don't have a lot of choice: The only available backend is a backend offering libsignal compatibility, found [here](https://github.com/Syndace/python-omemo-backend-signal). Install your backend of choice and proceed to the next step.

### Implement the Storage interface

The library has a lot of state/data that it has to persist between runs. To be as flexible as possible the library leaves it open for you to decide how to store the data. Simply implement the `Storage` interface found in `storage.py`. The file contains more info about how to implement the interface.

### Decide on a one-time pre key policy

This part is kind of tricky as it requires a lot of knowledge about how the protocol works. Basically the key exchange mechanism used by the protocol assumes guaranteed message delivery and a response to the first message before another message is sent. Both conditions are not quite given in all environments, especially not in XMPP, which is the main use-case for this library. For that reason the library has to "relax" some of the protocols rules. Instead of always instantly deleting the keys used in the key exchange, it is now up to you to decide whether to keep keys or not. To do so, implement the `OTPKPolicy` interface found in `otpkpolicy.py` or use the default implementation `DefaultOTPKPolicy`. If you decide to implement the interface yourself, the `otpkpolicy.py` file contains more information on how to implement the interface.

### Create a SessionManager

Now that you have selected a backend, decided on how to store the data and when to delete the key exchange keys, it's time to create an instance of the core class of this library: the SessionManager.

The SessionManager handles message en- and decryption with all your contacts, trying to make it as easy as possible for you. The file `examples/sessions.py` contains a lot of well-commented code that shows how to create and use a SessionManager.

## Specific information for usage in XMPP/Jabber

### 1. Device list management

#### 1.1. Device lists of your contacts

The first thing you have to set up is the device list management. To do so, subscribe to (or in [XEP-0163](https://xmpp.org/extensions/xep-0163.html) speak: announce interest in) the "eu.siacs.conversations.axolotl.devicelist" node. You will now receive updates to the device lists of all your OMEMO-enabled contacts. Upon receiving such an update, pass the contained list into the "newDeviceList" method of your SessionManager. Some pseudocode:
```Python
DEVICELIST_NODE = "eu.siacs.conversations.axolotl.devicelist"

def __init__():
    xep0163.announce_interest(DEVICELIST_NODE)

def onPEPUpdate(node, item, sender_jid):
    if node == DEVICELIST_NODE:
        devices = unpackDeviceList(item)
        sessionMgr.newDeviceList(devices, sender_jid)
```
The SessionManager takes care of caching the device list and also remembers inactive devices for you. You can ask the SessionManager for stored device lists using the "getDevices" method.

#### 1.2. Your own device list

The next thing to set up is the management of you own device list. The rule is quite simple: always make sure, that your own device id is contained in your device list. Whenever you load your OMEMO-using software, download the device list of your own jid and make sure your own device id is contained. After following the steps in 1.1., you will now also receive PEP updates about changes to your own device list. Use these updates to assert that your own device id is still contained in the list. Some more pseudocode:
```Python
def __init__():
    own_device_list = xep0163.load_latest_entry(own_jid, DEVICELIST_NODE)
    manageOwnDeviceList(own_device_list)
    sessionMgr.newDeviceList(own_device_list, own_jid)

def onPEPUpdate(node, item, sender_jid):
    if node == DEVICELIST_NODE:
        devices = unpackDeviceList(item)
        
        if sender_jid == own_jid:
            manageOwnDeviceList(devices)
        
        sessionMgr.newDeviceList(devices, sender_jid)
            
def manageOwnDeviceList(devices):
    if not own_device in devices:
        devices.append(own_device)
        
        item = packDeviceList(devices)
        
        xep0163.publish(DEVICELIST_NODE, item)
```

### 2. Bundle management

The next thing you need to manager are the bundles used for the X3DH key exchange. Each device publishes its own bundle to a unique PEP node.

**WIP**

### 3. Decryption

### 4. Encryption

### 5. A note about trust management

### 6. A note about fingerprints

Fingerprints initially were part of the library but I decided to remove them. Fingerprints are not specified at all, that's why I leave it open for the client dev to decide on a way to build and show fingerprints. Some implementations simply take the public part of the identity key and show it as a QR-code or encoded as hex bytes. Pseudocode:
```Python
# Get the ik public part from some bundle
ik_pub = some_bundle.ik

# Show a qr code somehow...
showQRCode(ik_pub)

# ...or create a hex byte representation
# Wanted format: 01:23:45:67:89:ab:cd:ef
ik_pub_hex = ":".join("{:02X}".format(octet) for octet in ik_pub)
```

### 7. A note about asynchronism
