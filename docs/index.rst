OMEMO - A Python implementation of the OMEMO Multi-End Message and Object Encryption protocol.
==============================================================================================

A Python implementation of the `OMEMO Multi-End Message and Object Encryption protocol <https://xmpp.org/extensions/xep-0384.html>`_.

A complete implementation of `XEP-0384 <https://xmpp.org/extensions/xep-0384.html>`_ on protocol-level, i.e. more than just the cryptography. python-omemo supports different versions of the specification through so-called backends. A backend for OMEMO in the ``urn:xmpp:omemo:2`` namespace (the most recent version of the specification) is available in the `python-twomemo <https://github.com/Syndace/python-twomemo>`_ Python package. A backend for (legacy) OMEMO in the ``eu.siacs.conversations.axolotl`` namespace is available in the `python-oldmemo <https://github.com/Syndace/python-oldmemo>`_ package. Multiple backends can be loaded and used at the same time, the library manages their coexistence transparently.

.. toctree::
    installation
    getting_started
    migration_from_legacy
    exceptions
    API Documentation <omemo/package>
