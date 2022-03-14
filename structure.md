## Backend API ##

python-omemo only ships the core functionality common to all versions of [XEP-0384]() and relies on backends to implement the details of each version. Each backend is uniquely identified by the namespace it implements. The core of python-omemo does not contain any code specific to any of the backends.

## Compatibility Between the Backends ##

Only the identity key used by X3DH is relevant for compatibility between the backends, and all versions of the OMEMO specification ensure compatibility of the identity key. Other parts of the X3DH bundle and Double Ratchet sessions are specific to the backend and compatibility is neither possible nor required. Thus, the identity key is managed by the core library, while everything else is managed by the backends.

## Public APIs and Backends ##

Backends differ in many aspects, from the wire format of the transferred data to the internal cryptographic primitves used. Thus, most parts of the public API take a parameter that specifies the backend to use for the given operation. The core transparently handles all things common to backends and forwards the backend-specific parts to the corresponding backend.
