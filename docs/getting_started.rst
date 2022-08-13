Getting Started
===============

python-omemo only ships the core functionality common to all versions of `XEP-0384 <https://xmpp.org/extensions/xep-0384.html>`_ and relies on backends to implement the details of each version. Each backend is uniquely identified by the namespace it implements.

Backend Selection
-----------------

There are two official backends:

==================================  ====
Namespace                           Link
==================================  ====
``urn:xmpp:omemo:2``                `python-twomemo <https://github.com/Syndace/python-twomemo>`_
``eu.siacs.conversations.axolotl``  `python-oldmemo <https://github.com/Syndace/python-oldmemo>`_
==================================  ====

Both backends (and more) can be loaded at the same time and the library will handle compatibility. You can specify backend priority, which will be used to decide which backend to use for encryption in case a recipient device supports multiple loaded backends.

Public API and Backends
-----------------------

Backends differ in many aspects, from the wire format of the transferred data to the internal cryptographic primitves used. Thus, most parts of the public API take a parameter that specifies the backend to use for the given operation. The core transparently handles all things common to backends and forwards the backend-specific parts to the corresponding backend.

Trust
-----

python-omemo offers trust management. Since it is not always obvious how trust and JID/device id/identity key belong together, this section gives an overview of the trust concept followed by python-omemo.

Each XMPP account has a pool of identity keys. Each device is assigned one identity key from the pool. Theoretically, this concept allows for one identity key to be assigned to multiple devices, however, the security implications of doing so have not been addressed in the XEP, thus it is not recommended and not supported by this library.

Trust levels are assigned to identity keys, not devices. I.e. devices are not directly trusted, only implicitly by trusting the identity key assigned to them.

The library works with two types of trust levels: custom trust levels and core trust levels. Custom trust levels are assigned to identity keys and can be any Python string. There is no limitation on the number of custom trust levels. Custom trust levels are not used directly by the library for decisions requiring trust (e.g. during message encryption), instead they are translated to one of the three core trust levels first: Trusted, Distrusted, Undecided. The translation from custom trust levels to core trust levels has to be supplied by implementing the :meth:`~omemo.session_manager.SessionManager._evaluate_custom_trust_level` method.

This trust concept allows for the implementation of trust systems like `BTBV <https://gultsch.de/trust.html>`_, `TOFU <https://en.wikipedia.org/wiki/Trust_on_first_use>`_, simple manual trust or more complex systems.

Storage
-------

python-omemo uses a simple key-value storage to persist its state. This storage has to be provided to the library by implementing the :class:`~omemo.storage.Storage` interface. Refer to the API documentation of the :class:`~omemo.storage.Storage` interface for details.

.. WARNING::
    It might be tempting to offer a backup/restore flow for the OMEMO data. However, due to the forward secrecy of OMEMO, restoring old data results in broken sessions. It is strongly recommended to not include OMEMO data in backups, and to at most include it in migration flows that make sure that old data can't be restored over newer data.

Setting it Up
-------------

With the backends selected, the trust system chosen and the storage implementation prepared, the library can be set up.

This is done in three steps:

1. Subclass abstract backend classes
2. Subclass abstract core library classes
3. Instantiate the :class:`~omemo.session_manager.SessionManager`

Backend Subclassing
^^^^^^^^^^^^^^^^^^^

Create subclasses of the respective backend classes if necessary. Some backends may require you to implement abstract methods, others may not. Refer to the docs of the respective backends for setup instructions.

Core Library Subclassing
^^^^^^^^^^^^^^^^^^^^^^^^

Create a subclass of :class:`~omemo.session_manager.SessionManager`. There are various abstract methods for interaction with XMPP (device lists, bundles etc.) and trust management that you have to fill out to integrate the library with your client/framework. The API documentation of the :class:`~omemo.session_manager.SessionManager` class should contain the necessary information.

Instantiate the Library
^^^^^^^^^^^^^^^^^^^^^^^

Finally, instantiate the storage, backends and then the :class:`~omemo.session_manager.SessionManager`, which is the class that offers all of the public API for message encryption, decryption, trust and device management etc. To do so, simply call the :meth:`~omemo.session_manager.SessionManager.create` method, passing the backend and storage implementations you've prepared. Refer to the API documentation for details on the configuration options accepted by :meth:`~omemo.session_manager.SessionManager.create`.

Migration
---------

Refer to :ref:`migration_from_legacy` for information about migrating from pre-stable python-omemo to python-omemo 1.0+. Migrations within stable (1.0+) versions are handled automatically.
