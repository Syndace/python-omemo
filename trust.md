# Trust #

Each XMPP account has a pool of identity keys. Each device is assigned one identity key from the pool. Theoretically, this concept allows for one identity key to be assigned to multiple devices, however, the security implications of doing so have not been addressed in the XEP, thus it is not recommended and not supported by this library.

Trust levels are assigned to identity keys, not devices. I.e. devices are not directly trusted, only implicitly by trusting the identity key assigned to them.

The library works with two types of trust levels: custom trust levels and core trust levels. Custom trust levels are assigned to identity keys and can be any Python string. There is no limitation on the number of custom trust levels. Custom trust levels are not used directly by the library for decisions requiring trust (e.g. during message encryption), instead they are translated to one of the three core trust levels first: Trusted, Distrusted, Undecided. The translation from custom trust levels to core trust levels has to be supplied by implementing the `SessionManager._evaluate_custom_trust_level` method.
