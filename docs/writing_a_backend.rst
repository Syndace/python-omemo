.. _writing_a_backend:

Writing a Backend
=================

python-omemo only ships the core functionality common to all versions of `XEP-0384 <https://xmpp.org/extensions/xep-0384.html>`_ and relies on backends to implement the details of each version. Each backend is uniquely identified by the namespace it implements. The core of python-omemo does not contain any code specific to any of the backends.

Compatibility Between Backends
==============================

Only the identity key used by the `X3DH key agreement scheme <https://www.signal.org/docs/specifications/x3dh/>`_ is relevant for compatibility between the backends, and all versions of the OMEMO specification ensure compatibility of the identity key. Other parts of the X3DH bundle and `Double Ratchet <https://www.signal.org/docs/specifications/doubleratchet/>`_ sessions are specific to the backend and compatibility is neither possible nor required. Thus, the identity key is managed by the core library, while everything else is managed by the backends.

TODO
