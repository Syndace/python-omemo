## Backend API ##

python-omemo only ships the core functionality common to all versions of [XEP-0384]() and relies on backends to implement the details of each version. Each backend is uniquely identified by the namespace it implements. The core of python-omemo does not contain any code specific to any of the backends.

## Compatibility Between the Backends ##

Only the identity key used by X3DH is relevant for compatibility between the backends. Other parts of the X3DH bundle and Double Ratchet sessions are specific to the backend and compatibility is neither possible nor required.

Each backend has a way to report which identity key pair types it supports: `Ed`, `Mont` or `Flexible`.

When a new identity key pair has to be generated, an `Ed` key pair is generated and the X3DH states of the backends are loaded as described below for the deserialization case.

When loading an identity key pair from serialized data, the key pair must be converted to fit the needs of all backends:
- If the loaded identity key pair is `Ed`, the X3DH states of the backend are loaded as follows:
    - If the backend requires `Ed` or is `Flexible`, the key pair is passed in as-is.
    - If the backend requires `Mont`, the key pair is converted to `Mont` and the converted key pair is passed in.
- If the loaded identity key pair is `Mont`, the X3DH states of the backend are loaded as follows:
    - If the backend requires `Mont` or is `Flexible`, the key pair is passed in as-is.
    - If the backend requires `Ed`, this requirement can't be fulfilled and compatibility between the backends can't be retained using that identity key pair. There are a few options how to handle that case:
        1. Discard the old identity key pair and generate a new `Ed` key pair, then proceed as described above. This solves the problem at the cost of a new identity key pair and related trust decisions.
        2. Disable usage of the incompatible backend, which solves the immediate problem at the cost of backend compatibility.
        3. Use different identity key pairs with the different backends, which also solves the immediate problem at the cost of backend compatibility.

The goal of python-omemo is to provide seamless compatibility between all backends, thus option 1 is the only solution viable for python-omemo.

## Public APIs and Backends ##

Backends differ in many aspects, from the wire format of the transferred data to the internal cryptographic primitves used. Thus, most parts of the public API take a parameter that specifies the backend to use for the given operation. The core transparently handles all things common to backends and forwards the specific parts to the corresponding backend.
