from typing import Optional
import xml.etree.ElementTree as ET

import oldmemo
import oldmemo.etree
from oldmemo.migrations import migrate
import twomemo
import twomemo.etree
import pytest

from .data import NS_TWOMEMO, NS_OLDMEMO, ALICE_BARE_JID, BOB_BARE_JID
from .in_memory_storage import InMemoryStorage
from .migration import POST_MIGRATION_TEST_MESSAGE, LegacyStorageImpl, download_bundle
from .session_manager_impl import \
    BundleStorage, DeviceListStorage, MessageQueue, TrustLevel, make_session_manager_impl


__all__ = [
    "test_regression0",
    "test_oldmemo_migration"
]


pytestmark = pytest.mark.asyncio


async def test_regression0() -> None:
    """
    Test a specific scenario that caused trouble during Libervia's JET plugin implementation.
    """

    bundle_storage: BundleStorage = {}
    device_list_storage: DeviceListStorage = {}

    alice_message_queue: MessageQueue = []
    bob_message_queue: MessageQueue = []

    AliceSessionManagerImpl = make_session_manager_impl(
        ALICE_BARE_JID,
        bundle_storage,
        device_list_storage,
        alice_message_queue
    )

    BobSessionManagerImpl = make_session_manager_impl(
        BOB_BARE_JID,
        bundle_storage,
        device_list_storage,
        bob_message_queue
    )

    alice_storage = InMemoryStorage()
    bob_storage = InMemoryStorage()

    # Create a session manager for each party
    alice_session_manager = await AliceSessionManagerImpl.create(
        backends=[ twomemo.Twomemo(alice_storage), oldmemo.Oldmemo(alice_storage) ],
        storage=alice_storage,
        own_bare_jid=ALICE_BARE_JID,
        initial_own_label=None,
        undecided_trust_level_name=TrustLevel.UNDECIDED.name
    )

    bob_session_manager = await BobSessionManagerImpl.create(
        backends=[ twomemo.Twomemo(bob_storage), oldmemo.Oldmemo(bob_storage) ],
        storage=bob_storage,
        own_bare_jid=BOB_BARE_JID,
        initial_own_label=None,
        undecided_trust_level_name=TrustLevel.UNDECIDED.name
    )

    # Exit history synchronization mode
    await alice_session_manager.after_history_sync()
    await bob_session_manager.after_history_sync()

    # Ask both parties to refresh the device lists of the other party
    await alice_session_manager.refresh_device_list(NS_TWOMEMO, BOB_BARE_JID)
    await alice_session_manager.refresh_device_list(NS_OLDMEMO, BOB_BARE_JID)

    await bob_session_manager.refresh_device_list(NS_TWOMEMO, ALICE_BARE_JID)
    await bob_session_manager.refresh_device_list(NS_OLDMEMO, ALICE_BARE_JID)

    # Have Alice encrypt an initial message to Bob to set up sessions between them
    for namespace in [ NS_TWOMEMO, NS_OLDMEMO ]:
        messages, encryption_errors = await alice_session_manager.encrypt(
            bare_jids=frozenset({ BOB_BARE_JID }),
            plaintext={ namespace: b"Hello, Bob!" },
            backend_priority_order=[ namespace ]
        )

        assert len(messages) == 1
        assert len(encryption_errors) == 0

        # Have Bob decrypt the message
        message = next(iter(messages.keys()))

        plaintext, _, _ = await bob_session_manager.decrypt(message)
        assert plaintext == b"Hello, Bob!"

        # Bob should now have an empty message for Alice in his message queue
        assert len(bob_message_queue) == 1
        bob_queued_message_recipient, bob_queued_message = bob_message_queue.pop()
        assert bob_queued_message_recipient == ALICE_BARE_JID

        # Have Alice decrypt the empty message to complete the session intiation
        plaintext, _, _ = await alice_session_manager.decrypt(bob_queued_message)
        assert plaintext is None

    # The part that caused trouble in the Libervia JET plugin implementation was an attempt at sending an
    # oldmemo KeyTransportElement. 32 zero-bytes were used as the plaintext, and the payload was manually
    # removed from the serialized XML. This test tests that scenario with both twomemo and oldmemo.
    for namespace in [ NS_TWOMEMO, NS_OLDMEMO ]:
        messages, encryption_errors = await alice_session_manager.encrypt(
            bare_jids=frozenset({ BOB_BARE_JID }),
            plaintext={ namespace: b"\x00" * 32 },
            backend_priority_order=[ namespace ]
        )

        assert len(messages) == 1
        assert len(encryption_errors) == 0

        message = next(iter(messages.keys()))

        # Serialize the message to XML, remove the payload, and parse it again
        encrypted_elt: Optional[ET.Element] = None
        if namespace == NS_TWOMEMO:
            encrypted_elt = twomemo.etree.serialize_message(message)
        if namespace == NS_OLDMEMO:
            encrypted_elt = oldmemo.etree.serialize_message(message)
        assert encrypted_elt is not None

        for payload_elt in encrypted_elt.findall(f"{{{namespace}}}payload"):
            encrypted_elt.remove(payload_elt)

        if namespace == NS_TWOMEMO:
            message = twomemo.etree.parse_message(encrypted_elt, ALICE_BARE_JID)
        if namespace == NS_OLDMEMO:
            message = await oldmemo.etree.parse_message(
                encrypted_elt,
                ALICE_BARE_JID,
                BOB_BARE_JID,
                bob_session_manager
            )

        # Decrypt the message on Bob's side
        plaintext, _, _ = await bob_session_manager.decrypt(message)
        assert plaintext is None

    # At this point, communication between both parties was broken. Try to send two messages back and forth.
    for namespace in [ NS_TWOMEMO, NS_OLDMEMO ]:
        messages, encryption_errors = await alice_session_manager.encrypt(
            bare_jids=frozenset({ BOB_BARE_JID }),
            plaintext={ namespace: b"Hello again, Bob!" },
            backend_priority_order=[ namespace ]
        )
        assert len(messages) == 1
        assert len(encryption_errors) == 0
        plaintext, _, _ = await bob_session_manager.decrypt(next(iter(messages.keys())))
        assert plaintext == b"Hello again, Bob!"

        messages, encryption_errors = await bob_session_manager.encrypt(
            bare_jids=frozenset({ ALICE_BARE_JID }),
            plaintext={ namespace: b"Hello back, Alice!" },
            backend_priority_order=[ namespace ]
        )
        assert len(messages) == 1
        assert len(encryption_errors) == 0
        plaintext, _, _ = await alice_session_manager.decrypt(next(iter(messages.keys())))
        assert plaintext == b"Hello back, Alice!"


    await alice_session_manager.shutdown()
    await bob_session_manager.shutdown()


async def test_oldmemo_migration() -> None:
    """
    Tests the migration of the legacy storage format, which is provided by python-oldmemo.
    """

    bundle_storage: BundleStorage = {}
    device_list_storage: DeviceListStorage = {}
    message_queue: MessageQueue = []

    SessionManagerImpl = make_session_manager_impl(
        ALICE_BARE_JID,
        bundle_storage,
        device_list_storage,
        message_queue
    )

    legacy_storage = LegacyStorageImpl()
    storage = InMemoryStorage()

    await migrate(
        legacy_storage=legacy_storage,
        storage=storage,
        trusted_trust_level_name=TrustLevel.TRUSTED.name,
        undecided_trust_level_name=TrustLevel.UNDECIDED.name,
        untrusted_trust_level_name=TrustLevel.DISTRUSTED.name,
        download_bundle=download_bundle
    )

    session_manager = await SessionManagerImpl.create(
        backends=[ oldmemo.Oldmemo(storage) ],
        storage=storage,
        own_bare_jid=ALICE_BARE_JID,
        initial_own_label=None,
        undecided_trust_level_name=TrustLevel.UNDECIDED.name
    )

    await session_manager.after_history_sync()

    message = await oldmemo.etree.parse_message(
        ET.fromstring(POST_MIGRATION_TEST_MESSAGE),
        BOB_BARE_JID,
        ALICE_BARE_JID,
        session_manager
    )

    plaintext, _, _ = await session_manager.decrypt(message)

    assert plaintext == b"This is a test message"

    await session_manager.shutdown()
