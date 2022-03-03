# Functionality/Use Cases

- [x] the maximum number of skipped message keys to keep around per session is configurable
    - [x] the default is set to 1000
    - [x] the value is limited neither upwards nor downwards
    - [x] skipped message keys are deleted following LRU once the limit is reached
    - [ ] TODO: think of a more sophisticated deletection policy based on deterministic events

- [x] the maximum number of skipped message keys in a single message is configurable
    - [x] the default is set to the maximum number of skipped message keys per session
    - [x] the value is not limited downwards, altough a value of 0 is forbidden if the maximum number of skipped message keys per session is non-zero
    - [x] the value is limited upwards to be lower than or equal to the maximum number of skipped message keys per session

- [x] device lists are managed
    - [x] PEP updates to device lists are handled
        - [x] a function is provided to feed PEP updates to device lists into the library
        - [x] a PEP downloading mechanism must be provided by the application to download device lists from PEP
    - [x] the own device list is managed
        - [x] the own device is added to the list if it isn't included
        - [x] a label for the own device can optionally be provided
        - [x] a PEP publishing mechanism must be provided by the application to update the device list in PEP
    - [x] the most recent version of all device lists is cached
    - [x] a convenience method is provided to manually trigger the refresh of a device list
    - [x] devices that are removed from the device list are marked as "inactive", while devices on the list are marked as "active"
    - [x] only active devices are considered during encryption
    - [x] a device becoming inactive has no other effect than it being omitted during encryption, i.e. the data corrsponding to the device is never (automatically) deleted
    - [x] device lists of different backends are merged. it is assumed that device ids are unique even across backends. the same device id in multiple lists is assumed to represent the same device.
    - [x] the backends supported by each device are indicated together with the device id

- [x] the own public bundle is managed
    - [x] the identity key is managed
    - [x] the signed pre key is managed
        - [x] the signed pre key is rotated periodically
        - [x] the rotation period is configurable
        - [x] a default rotation period of between one week and one month is provided
        - [x] the signed pre key of the previous rotation is kept around for the next full period to account for delayed messages
        - [x] to account for delayed messages and offline periods of the client, the signed pre key is only ever rotated after any offline message catch-up is done
    - [x] the pre keys are managed
        - [x] the number of pre keys is capped to 100
        - [x] the threshold for when to generate new pre keys is configurable
        - [x] the threshold can not be configured lower than 25
        - [x] the default threshold is 99, which means that every used pre key is replaced right away
    - [x] a PEP publishing mechanism must be provided by the application to update the public bundle in PEP
    - [x] a PEP downloading mechanism must be provided by the application to download the public bundle from PEP
    - [x] one bundle is managed per backend, only the identity key is shared between all backends/bundles
        - [x] care is taken to provide the identity key to each backend in the format required by the backend (i.e. Ed25519 or Curve25519)

- [x] the own device id is generated
    - [x] the device id is shared across all backends
    - [x] the current device lists are consulted prior to device id generation to avoid the very unlikely case of a collision
        - [x] no efforts are made to detect clashes or avoid races (even on protocol level), due to the very low likeliness of a collision
        - [x] this mechanism can not prevent collisions with new backends if backends are added after the device id has been generated
    - [x] it is assumed that other clients also share device ids and identity keys across backends

- [x] trust is managed
    - [x] custom trust levels are supported, allowing for different trust systems like BTBV
    - [x] a callback must be implemented to translate custom trust levels into core trust levels understood by the library
    - [x] the default trust level to assign to new devices must be specified
    - [x] trust decisions are always requested in bulk, such that applications can e.g. show one decision dialog for all outstanding trust decisions
    - [x] trust is shared across backends
    - [x] trust is applied to pairs of identity key and bare JID, device ids are not part of trust

- [x] sessions can be built
    - [x] transparently when sending or receiving encrypted messages
    - [x] explicit session building APIs are not provided
    - [x] requires own public bundle management
    - [x] sessions are per-backend
    - [x] a PEP downloading mechanism must be provided by the application to download public bundles from PEP

- [x] messages can be encrypted
    - [x] requires session building, device list management and trust management
    - [x] multiple recipients are supported
    - [x] own devices are automatically added to the list of recipients, the sending device is removed from the list
    - [x] messages are only encrypted for devices whose trust level evaluates to "trusted"
    - [x] the message is not automatically sent, but a structure containing the encrypted payload and the headers is returned
        - [x] this allows implementation of e.g. KeyTransportMessages of legacy OMEMO
    - [x] the backend to encrypt the message with can be selected explicitly or implicitly
        - [x] in the implicit selection, a list of backends is given of which the order decides priority
        - [x] in the implicit selection, support for each backend by the recipient is detected by looking for the presence of respective bundles on the server
        - [x] the type of the message parameter to the encryption methods is generic, and each backend provides a method to serialize the type into a byte string
            - [x] this is necessary because different backends require different inputs to message encryption. For example, omemo:1 requires stanzas for SCE and legacy OMEMO requires just text
            - [x] when multiple backends are used together, the generic type can be chosen as the lowest common denominator between all backend input types, and implement the serialization methods accordingly
        - [x] implicit selection is the default, with the priority order taken from the order of the backends as passed to the constructor

- [x] empty OMEMO messages can be sent
    - [x] transparently when required by the protocol
    - [x] explicit APIs for empty OMEMO messages are not provided (KeyTransportMessages for legacy OMEMO are a different topic)
    - [x] a mechanism must be provided by the application to send empty OMEMO messages
    - [x] trust is circumvented for empty OMEMO messages

- [x] messages can be decrypted
    - [x] requires session building and trust management
    - [x] the whole OMEMO-encrypted message can be passed to the library, it will select the correct header corresponding the the device
    - [x] the type of the decrypted message is generic, each backend provides a method to deserialize the decrypted message body from a byte string into its respective type
        - [x] this is necessary because different backends produce different outputs from message decryption. For example, omemo:1 produces stanzas from SCE and legacy OMEMO produces just text
        - [x] when multiple backends are used together, the generic type can be chosen as the lowest common denominator between all backend output types, and implement the deserialization methods accordingly
    - [x] device lists are automatically refreshed when encountering a message by a device that is not cached
    - [x] the backend to decrypt the message with is implicitly selected by looking at the type of the message structure
    - [x] in case there is no session with the sending device, a new session is transparently initiated
        - [x] requires empty OMEMO messages
    - [x] whether messages of devices with undecided trust are decrypted is configurable
        - [x] it is detectable in case the message of an undecided device was decrypted
    - [x] duplicate messages are not detected, that task is up to the application

- [x] opt-out is not handled

- [x] MUC participant list management is not provided
    - [x] message encryption to multiple recipients is supported though

- [x] passive session initiations are automatically completed
    - [x] requires empty OMEMO messages

- [x] message catch-up is handled
    - [x] methods are provided to notify the library about start and end of message catch-up
    - [x] the library automatically enters catch-up mode when loaded
    - [x] pre keys are retained during catch-up and deleted when the catch-up is done
    - [x] if the signed pre key is due for rotation, rotation is performed when exiting catch-up mode
    - [x] delays automated staleness prevention responses
    - [x] requires automatic completion of passive session initiations

- [x] manual session replacement is provided
    - [x] per-device session replacement is not provided
    - [x] per-JID session replacement is provided, where all sessions with a bare JID are replaced across all backends
    - [x] requires empty OMEMO messages
    - [ ] TODO: is a global reset provided?

- [x] own staleness is prevented
    - [x] received messages with a ratchet counter of 53 or higher trigger an automated response
    - [x] automated responses are delayed until after catch-up is done and only one message is sent per stale session afterwards
    - [x] requires empty OMEMO messages

- [ ] stale devices are detected
    - [ ] the metrics for when a device is to be considered stale are configurable
    - [ ] one metric is the sending chain length TODO: default?
    - [ ] other metrics are WIP TODO: e.g. track timestamp of last activity?

- [x] account purging is supported
    - [x] removes all data related to a bare JID across all backends
    - [x] useful e.g. to remove all OMEMO-related data corresponding to an XMPP account that was blocked by the user

- [x] a convenience method to get the identity key fingerprint of a device is provided
    - [x] independent of the backend

- [ ] methods are provided to retrieve information about devices
    - [x] information for all devices of a bare JID can be retrieved in bulk
    - [ ] includes device id, label, identity key, trust information, corresponding backend, staleness information (including a boolean "stale" flag and the metrics playing into staleness)
    - [x] independent of the backend

- [x] backends can be provided for different versions of the OMEMO protocol
    - [x] the protocol version a backend implements is identified by its namespace

- [ ] data storage has to be provided by the application
    - [x] an asyncio-based storage interface has to be implemented
        - [x] this interface transparently handles caching
        - [x] the interface represents generic key-value storage with opaque keys and values
    - [ ] automatic migrations between storage format versions are provided
        - [ ] a legacy python-omemo to modern python-omemo migration tool is provided
        - [ ] a libsignal to python-omemo migration tool will be provided in the future(, as part of the legacy backend?)
    - [ ] a default implementation using json files and directories on the file system is provided
    - [ ] storage consistency is guaranteed
        - [x] write operations MUST NOT cache but perform the writing operation right away
        - [ ] when decrypting, changes to the state are only saved on success
        - [ ] when encrypting, changes to the state are saved before they are used for any further operation

- [ ] a convenience method to verify consistency (and fix) of the server-side data with the local data is provided
    - [ ] whether these consistency checks are ran automatically, e.g. once during library startup/once per day etc. is WIP

# Part of the respective backends

- [ ] convenience functions for XML (de)serialization is provided using the ElementTree API
    - [ ] this part is fully optional, the application may take care of (de)serialization itself
    - [ ] installed only when doing `pip install python-omemo-backend-foo[xml]`
