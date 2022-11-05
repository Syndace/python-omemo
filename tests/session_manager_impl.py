import enum
from typing import Dict, FrozenSet, List, Optional, Tuple, Type

from typing_extensions import NamedTuple, assert_never

import omemo


__all__ = [  # pylint: disable=unused-variable
    "TrustLevel",
    "BundleStorageKey",
    "DeviceListStorageKey",
    "BundleStorage",
    "DeviceListStorage",
    "MessageQueue",
    "make_session_manager_impl"
]


@enum.unique
class TrustLevel(enum.Enum):
    """
    Trust levels modeling simple manual trust.
    """

    TRUSTED: str = "TRUSTED"
    UNDECIDED: str = "UNDECIDED"
    DISTRUSTED: str = "DISTRUSTED"


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
