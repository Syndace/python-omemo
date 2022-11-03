import enum
from typing import Dict, FrozenSet, List, NamedTuple, Optional, Tuple, Type
import xml.etree.ElementTree as ET

import oldmemo
import oldmemo.etree
import twomemo
import twomemo.etree
import pytest
from typing_extensions import assert_never

import omemo


__all__ = [  # pylint: disable=unused-variable
    "test_regression0"
]


pytestmark = pytest.mark.asyncio  # pylint: disable=unused-variable


@enum.unique
class TrustLevel(enum.Enum):
    """
    Trust levels modeling simple manual trust.
    """

    TRUSTED: str = "TRUSTED"
    UNDECIDED: str = "UNDECIDED"
    DISTRUSTED: str = "DISTRUSTED"


class InMemoryStorage(omemo.Storage):
    """
    Volatile storage implementation with the values held in memory.
    """

    def __init__(self) -> None:
        super().__init__(True)

        self.__storage: Dict[str, omemo.JSONType] = {}

    async def _load(self, key: str) -> omemo.Maybe[omemo.JSONType]:
        try:
            return omemo.Just(self.__storage[key])
        except KeyError:
            return omemo.Nothing()

    async def _store(self, key: str, value: omemo.JSONType) -> None:
        self.__storage[key] = value

    async def _delete(self, key: str) -> None:
        self.__storage.pop(key, None)


class BundleStorageKey(NamedTuple):
    # pylint: disable=invalid-name
    """
    The key identifying a bundle in the tests.
    """

    namespace: str
    bare_jid: str
    device_id: int


class DeviceListStorageKey(NamedTuple):
    # pylint: disable=invalid-name
    """
    The key identifying a device list in the tests.
    """

    namespace: str
    bare_jid: str


BundleStorage = Dict[BundleStorageKey, omemo.Bundle]
DeviceListStorage = Dict[DeviceListStorageKey, Dict[int, Optional[str]]]
MessageQueue = List[Tuple[str, omemo.Message]]


def make_session_manager_impl(
    own_bare_jid: str,
    bundle_storage: BundleStorage,
    device_list_storage: DeviceListStorage,
    message_queue: MessageQueue
) -> Type[omemo.SessionManager]:
    """
    Args:
        own_bare_jid: The bare JID of the account that will be used with the session manager instances created
            from this implementation.
        bundle_storage: The dictionary to "upload", "download" and delete bundles to/from.
        device_list_storage: The dictionary to "upload" and "download" device lists to/from.
        message_queue: The list to "send" automated messages to. The first entry of each tuple is the bare JID
            of the recipient. The second entry is the message itself.

    Returns:
        A session manager implementation which sends/uploads/downloads/deletes data to/from the collections
        given as parameters.
    """

    class SessionManagerImpl(omemo.SessionManager):
        # pylint: disable=missing-class-docstring
        @staticmethod
        async def _upload_bundle(bundle: omemo.Bundle) -> None:
            bundle_storage[BundleStorageKey(
                namespace=bundle.namespace,
                bare_jid=bundle.bare_jid,
                device_id=bundle.device_id
            )] = bundle

        @staticmethod
        async def _download_bundle(namespace: str, bare_jid: str, device_id: int) -> omemo.Bundle:
            try:
                return bundle_storage[BundleStorageKey(
                    namespace=namespace,
                    bare_jid=bare_jid,
                    device_id=device_id
                )]
            except KeyError as e:
                raise omemo.BundleDownloadFailed() from e

        @staticmethod
        async def _delete_bundle(namespace: str, device_id: int) -> None:
            try:
                bundle_storage.pop(BundleStorageKey(
                    namespace=namespace,
                    bare_jid=own_bare_jid,
                    device_id=device_id
                ))
            except KeyError as e:
                raise omemo.BundleDeletionFailed() from e

        @staticmethod
        async def _upload_device_list(namespace: str, device_list: Dict[int, Optional[str]]) -> None:
            device_list_storage[DeviceListStorageKey(
                namespace=namespace,
                bare_jid=own_bare_jid
            )] = device_list

        @staticmethod
        async def _download_device_list(namespace: str, bare_jid: str) -> Dict[int, Optional[str]]:
            try:
                return device_list_storage[DeviceListStorageKey(
                    namespace=namespace,
                    bare_jid=bare_jid
                )]
            except KeyError:
                return {}

        async def _evaluate_custom_trust_level(self, device: omemo.DeviceInformation) -> omemo.TrustLevel:
            try:
                trust_level = TrustLevel(device.trust_level_name)
            except ValueError as e:
                raise omemo.UnknownTrustLevel() from e

            if trust_level is TrustLevel.TRUSTED:
                return omemo.TrustLevel.TRUSTED
            if trust_level is TrustLevel.UNDECIDED:
                return omemo.TrustLevel.UNDECIDED
            if trust_level is TrustLevel.DISTRUSTED:
                return omemo.TrustLevel.DISTRUSTED

            assert_never(trust_level)

        async def _make_trust_decision(
            self,
            undecided: FrozenSet[omemo.DeviceInformation],
            identifier: Optional[str]
        ) -> None:
            for device in undecided:
                await self.set_trust(device.bare_jid, device.identity_key, TrustLevel.TRUSTED.name)

        @staticmethod
        async def _send_message(message: omemo.Message, bare_jid: str) -> None:
            message_queue.append((bare_jid, message))

    return SessionManagerImpl


NS_TWOMEMO = twomemo.twomemo.NAMESPACE
NS_OLDMEMO = oldmemo.oldmemo.NAMESPACE

ALICE_BARE_JID = "alice@example.org"
BOB_BARE_JID = "bob@example.org"


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
