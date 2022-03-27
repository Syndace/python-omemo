OMEMO - A Python implementation of the OMEMO Multi-End Message and Object Encryption protocol.
==============================================================================================

A Python implementation of the `OMEMO Multi-End Message and Object Encryption protocol <https://xmpp.org/extensions/xep-0384.html>`_.

A complete implementation of `XEP-0384 <https://xmpp.org/extensions/xep-0384.html>`_ on protocol-level, i.e. more than just the cryptography. python-omemo supports different versions of the specification through so-called backends. One backend for OMEMO in the `urn:xmpp:omemo:1` namespace is shipped with python-omemo. A backend for (legacy) OMEMO in the `eu.siacs.conversations.axolotl` namespace is available as a separate package: `python-omemo-backend-legacy <https://github.com/Syndace/python-omemo-backend-legacy>`_. Multiple backends can be loaded and used at the same time, the library manages their coexistence transparently.

.. toctree::
    Installation <installation>
    Getting Started <getting_started>
    Writing a Backend <writing_a_backend>
    Migration from Legacy <migration_from_legacy>
    Package: omemo <omemo/package>
