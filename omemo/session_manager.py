from abc import ABC, abstractmethod
import asyncio
import base64
import itertools
import logging
import secrets
from typing import Any, Dict, FrozenSet, List, NamedTuple, Optional, Set, Tuple, Type, TypeVar, Union, cast

from .backend import Backend, KeyExchangeFailed
from .bundle import Bundle
from .identity_key_pair import IdentityKeyPair
from .message import EncryptedKeyMaterial, KeyExchange, Message, PlainKeyMaterial
from .session import Initiation, Session
from .storage import NothingException, Storage
from .types import DeviceInformation, OMEMOException, TrustLevel


__all__ = [  # pylint: disable=unused-variable
    "SessionManagerException",

    "TrustDecisionFailed",
    "StillUndecided",
    "NoEligibleDevices",

    "MessageNotForUs",
    "SenderNotFound",
    "SenderDistrusted",
    "NoSession",
    "PublicDataInconsistency",

    "UnknownTrustLevel",
    "UnknownNamespace",

    "XMPPInteractionFailed",
    "BundleUploadFailed",
    "BundleDownloadFailed",
    "BundleDeletionFailed",
    "DeviceListUploadFailed",
    "DeviceListDownloadFailed",
    "MessageSendingFailed",

    "SessionManager"
]


class SessionManagerException(OMEMOException):
    """
    Parent type for all exceptions specific to :class:`SessionManager`.
    """


class TrustDecisionFailed(SessionManagerException):
    """
    Raised by :meth:`SessionManager._make_trust_decision` if the trust decisions that were queried somehow
    failed. Indirectly raised by the encryption flow.
    """


class StillUndecided(SessionManagerException):
    """
    Raised by :meth:`SessionManager.encrypt` in case there are still undecided devices after a trust decision
    was queried via :meth:`SessionManager._make_trust_decision`.
    """


class NoEligibleDevices(SessionManagerException):
    """
    Raised by :meth:`SessionManager.encrypt` in case none of the devices of one or more recipient are eligible
    for encryption, for example due to distrust or bundle downloading failures.
    """

    def __init__(self, bare_jids: FrozenSet[str], *args: object) -> None:
        """
        Args:
            bare_jids: The JIDs whose devices were not eligible. Accessible as an attribute of the returned
                instance.
        """

        super().__init__(*args)

        self.bare_jids = bare_jids


class MessageNotForUs(SessionManagerException):
    """
    Raised by :meth:`SessionManager.decrypt` in case the message to decrypt does not seem to be encrypting for
    this device.
    """


class SenderNotFound(SessionManagerException):
    """
    Raised by :meth:`SessionManager.decrypt` in case the usual public information of the sending device could
    not be downloaded.
    """


class SenderDistrusted(SessionManagerException):
    """
    Raised by :meth:`SessionManager.decrypt` in case the sending device is explicitly distrusted.
    """


class NoSession(SessionManagerException):
    """
    Raised by :meth:`SessionManager.decrypt` in case there is no session with the sending device, and a new
    session can't be built either.
    """


class PublicDataInconsistency(SessionManagerException):
    """
    Raised by :meth:`SessionManager.decrypt` in case inconsistencies were found in the public data of the
    sending device.
    """


class UnknownTrustLevel(SessionManagerException):
    """
    Raised by :meth:`SessionManager._evaluate_custom_trust_level` if the custom trust level name to evaluate
    is unknown. Indirectly raised by the encryption and decryption flows.
    """


class UnknownNamespace(SessionManagerException):
    """
    Raised by various methods of :class:`SessionManager`, in case the namespace to perform an operation under
    is not known or the corresponding backend is not currently loaded.
    """


class XMPPInteractionFailed(SessionManagerException):
    """
    Parent type for all exceptions related to network/XMPP interactions.
    """


class BundleUploadFailed(XMPPInteractionFailed):
    """
    Raised by :meth:`SessionManager._upload_bundle`, and indirectly by various methods of
    :class:`SessionManager`.
    """


class BundleDownloadFailed(XMPPInteractionFailed):
    """
    Raised by :meth:`SessionManager._download_bundle`, and indirectly by various methods of
    :class:`SessionManager`.
    """


class BundleDeletionFailed(XMPPInteractionFailed):
    """
    Raised by :meth:`SessionManager._delete_bundle`, and indirectly by :meth:`SessionManager.purge_backend`.
    """


class DeviceListUploadFailed(XMPPInteractionFailed):
    """
    Raised by :meth:`SessionManager._upload_device_list`, and indirectly by various methods of
    :class:`SessionManager`.
    """


class DeviceListDownloadFailed(XMPPInteractionFailed):
    """
    Raised by :meth:`SessionManager._download_device_list`, and indirectly by various methods of
    :class:`SessionManager`.
    """


class MessageSendingFailed(XMPPInteractionFailed):
    """
    Raised by :meth:`SessionManager._send_message`, and indirectly by various methods of
    :class:`SessionManager`.
    """


class EncryptionError(NamedTuple):
    # pylint: disable=invalid-name
    """
    Structure containing information about an encryption error, returned by :meth:`SessionManager.encrypt`.
    """

    namespace: str
    bare_jid: str
    device_id: int
    exception: Union[BundleDownloadFailed, KeyExchangeFailed]


SessionManagerTypeT = TypeVar("SessionManagerTypeT", bound="SessionManager")


class SessionManager(ABC):
    """
    The core of python-omemo. Manages your own key material and bundle, device lists, sessions with other
    users and much more, all while being flexibly usable with different backends and transparenlty maintaining
    a level of compatibility between the backends that allows you to maintain a single identity throughout all
    of them. Easy APIs are provided to handle common use-cases of OMEMO-enabled XMPP clients, with one of the
    primary goals being strict type safety.

    Note:
        Most methods can raise :class:`~omemo.storage.StorageException` in addition to those exceptions
        listed explicitly.

    Note:
        All parameters are treated as immutable unless explicitly noted otherwise.

    Note:
        All usages of "identity key" in the public API refer to the public part of the identity key pair in
        Ed25519 format. Otherwise, "identity key pair" is explicitly used to refer to the full key pair.

    Note:
        The library was designed for use as part of an XMPP library/client. The API is shaped for XMPP and
        comments/documentation contain references to XEPs and other XMPP-specific nomenclature. However, the
        library can be used with any economy that provides similar functionality.
    """

    DEVICE_ID_MIN = 1
    DEVICE_ID_MAX = 2 ** 31 - 1
    STALENESS_MAGIC_NUMBER = 53
    LOG_TAG = "omemo.core"

    def __init__(self) -> None:
        # Just the type definitions here
        self.__backends: List[Backend]
        self.__storage: Storage
        self.__own_bare_jid: str
        self.__own_device_id: int
        self.__undecided_trust_level_name: str
        self.__pre_key_refill_threshold: int
        self.__identity_key_pair: IdentityKeyPair
        self.__synchronizing: bool

    @classmethod
    async def create(
        cls: Type[SessionManagerTypeT],
        backends: List[Backend],
        storage: Storage,
        own_bare_jid: str,
        initial_own_label: Optional[str],
        undecided_trust_level_name: str,
        signed_pre_key_rotation_period: int = 7 * 24 * 60 * 60,
        pre_key_refill_threshold: int = 99
    ) -> SessionManagerTypeT:
        """
        Load or create OMEMO backends. This method takes care of everything regarding the initialization of
        OMEMO: generating a unique device id, uploading the bundle and adding the new device to the device
        list. While doing so, it makes sure that all backends share the same identity key, so that a certain
        level of compatibility between the backends can be achieved. If a backend was created before, this
        method loads the backend from the storage instead of creating it.

        Args:
            backends: The list of backends to use.
            storage: The storage for all OMEMO-related data.
            own_bare_jid: The own bare JID of the account this device belongs to.
            initial_own_label: The initial (optional) label to assign to this device if supported by any of
                the backends.
            undecided_trust_level_name: The name of the custom trust level to initialize the trust level with
                when a new device is first encoutered. :meth:`_evaluate_custom_trust_level` should evaluate
                this custom trust level to :attr:`~omemo.types.TrustLevel.UNDECIDED`.
            signed_pre_key_rotation_period: The rotation period for the signed pre key, in seconds. The
                rotation period is recommended to be between one week (the default) and one month.
            pre_key_refill_threshold: The number of pre keys that triggers a refill to 100. Defaults to 99,
                which means that each pre key gets replaced with a new one right away. The threshold can not
                be configured to lower than 25.

        Returns:
            A configured instance of :class:`~omemo.session_manager.SessionManager`, with all backends loaded,
            bundles published and device lists adjusted.

        Raises:
            BundleUploadFailed: if a bundle upload failed. Forwarded from :meth:`_upload_bundle`.
            BundleDownloadFailed: if a bundle download failed. Forwarded from :meth:`_download_bundle`.
            BundleDeletionFailed: if a bundle deletion failed. Forwarded from :meth:`_delete_bundle`.
            DeviceListUploadFailed: if a device list upload failed. Forwarded from
                :meth:`_upload_device_list`.
            DeviceListDownloadFailed: if a device list download failed. Forwarded from
                :meth:`_download_device_list`.

        Warning:
            The library starts in history synchronization mode. Call :meth:`after_history_sync` to return to
            normal operation. Refer to the documentation of :meth:`before_history_sync` and
            :meth:`after_history_sync` for details.

        Warning:
            The library takes care of keeping online data in sync. That means, if the library is loaded
            without a backend that was loaded before, it will remove all online data related to the missing
            backend and as much of the offline data as possible (refer to :meth:`purge_backend` for details).

        Note:
            This method takes care of leaving the device lists in a consistent state. To do so, backends are
            "initialized" one after the other. For each backend, the device list is updated as the very last
            step, after everything else that could fail is done. This ensures that either all data is
            consistent or the device list does not yet list the inconsistent device. If the creation of one
            backend succeeds, the data is persisted in the storage before the next backend is created. This
            guarantees that even if the next backend creation fails, the data is not lost and will be loaded
            from the storage when calling this method again.

        Note:
            The order of the backends can optionally be used by :meth:`encrypt` as the order of priority, in
            case a recipient device supports multiple backends. Refer to the documentation of :meth:`encrypt`
            for details.
        """

        if len(frozenset(backend.namespace for backend in backends)) != len(backends):
            raise ValueError("Multiple backends that handle the same namespace were passed.")

        if not 25 <= pre_key_refill_threshold <= 99:
            raise ValueError("Pre key refill threshold out of allowed range.")

        logging.getLogger(SessionManager.LOG_TAG).debug(
            f"Preparing library core.\n"
            f"\tcls={cls}\n"
            f"\tbackends={backends}\n"
            f"\tbackend namespaces={[ backend.namespace for backend in backends ]}\n"
            f"\tstorage={storage}\n"
            f"\town_bare_jid={own_bare_jid}\n"
            f"\tinitial_own_label={initial_own_label}\n"
            f"\tundecided_trust_level_name={undecided_trust_level_name}\n"
            f"\tsigned_pre_key_rotation_period={signed_pre_key_rotation_period}\n"
            f"\tpre_key_refill_threshold={pre_key_refill_threshold}"
        )

        self = cls()
        self.__backends = list(backends)  # Copy to make sure the original is not modified
        self.__storage = storage
        self.__own_bare_jid = own_bare_jid
        self.__undecided_trust_level_name = undecided_trust_level_name
        self.__pre_key_refill_threshold = pre_key_refill_threshold
        self.__identity_key_pair = await IdentityKeyPair.get(storage)
        self.__synchronizing = True

        try:
            self.__own_device_id = (await self.__storage.load_primitive("/own_device_id", int)).from_just()
            logging.getLogger(SessionManager.LOG_TAG).debug(f"Device id from storage: {self.__own_device_id}")
        except NothingException:
            # First run.
            logging.getLogger(SessionManager.LOG_TAG).info("First run.")

            # Fetch the device lists for this bare JID for all loaded backends.
            device_ids = cast(FrozenSet[int], frozenset()).union(*[
                frozenset((await self._download_device_list(backend.namespace, self.__own_bare_jid)).keys())
                for backend
                in self.__backends
            ])

            # Generate a new device id for this device, making sure that it doesn't clash with any of the
            # existing device ids.
            self.__own_device_id = next(filter(
                lambda device_id: device_id not in device_ids,
                (
                    secrets.randbelow(cls.DEVICE_ID_MAX - cls.DEVICE_ID_MIN) + cls.DEVICE_ID_MIN
                    for _
                    in itertools.count()
                )
            ))
            logging.getLogger(SessionManager.LOG_TAG).debug(f"Generated device id: {self.__own_device_id}")

            # Store the device information for this device
            await storage.store(
                f"/devices/{self.__own_bare_jid}/{self.__own_device_id}/namespaces",
                [ backend.namespace for backend in self.__backends ]
            )

            await storage.store(
                f"/devices/{self.__own_bare_jid}/{self.__own_device_id}/active",
                { backend.namespace: True for backend in self.__backends }
            )

            await storage.store(
                f"/devices/{self.__own_bare_jid}/{self.__own_device_id}/label",
                initial_own_label
            )

            await storage.store_bytes(
                f"/devices/{self.__own_bare_jid}/{self.__own_device_id}/identity_key",
                self.__identity_key_pair.identity_key
            )

            # Initialize the local device list for this bare JID
            await storage.store(
                f"/devices/{self.__own_bare_jid}/list",
                [ self.__own_device_id ]
            )

            # The trust level of the own identity key doesn't really matter as it's not checked anywhere, but
            # some value still has to be set such that the device doesn't need special treatment in storage
            # accessing code.
            identity_key_b64 = base64.urlsafe_b64encode(self.__identity_key_pair.identity_key)
            await self.__storage.store(
                f"/trust/{self.__own_bare_jid}/{identity_key_b64.decode('ASCII')}",
                undecided_trust_level_name
            )

            # Finally store the device id once the other setup is done
            await self.__storage.store("/own_device_id", self.__own_device_id)

            # Generate the first 100 pre keys for each backend
            for backend in self.__backends:
                await backend.generate_pre_keys(100)

            # Publish the bundles for all backends
            for backend in self.__backends:
                await self._upload_bundle(await backend.get_bundle(self.__own_bare_jid, self.__own_device_id))

            # Trigger a refresh of the own device lists for all backends, this will result in this device
            # being added to the lists and the lists republished.
            for backend in self.__backends:
                await self.refresh_device_list(backend.namespace, self.__own_bare_jid)

        # If there a mismatch between loaded and active namespaces, look for changes in the loaded backends.
        device, _ = await self.get_own_device_information()
        loaded_namespaces = frozenset(backend.namespace for backend in self.__backends)
        active_namespaces = device.namespaces
        if loaded_namespaces != active_namespaces:
            logging.getLogger(SessionManager.LOG_TAG).info(
                "The list of backends loaded now differs from the list of backends that were loaded last run:"
                f" {loaded_namespaces} vs. {active_namespaces} (now vs. previous run)"
            )

            # Store the updated list of loaded namespaces
            await storage.store(
                f"/devices/{self.__own_bare_jid}/{self.__own_device_id}/namespaces",
                list(loaded_namespaces)
            )

            # Set the device active for all loaded namespaces
            await storage.store(
                f"/devices/{self.__own_bare_jid}/{self.__own_device_id}/active",
                { namespace: True for namespace in loaded_namespaces }
            )

            # Take care of the initialization of newly added backends
            for backend in self.__backends:
                if backend.namespace not in active_namespaces:
                    # Refill pre keys if necessary
                    num_visible_pre_keys = await backend.get_num_visible_pre_keys()
                    if num_visible_pre_keys <= self.__pre_key_refill_threshold:
                        await backend.generate_pre_keys(100 - num_visible_pre_keys)

                    # Publish the bundle of the new backend
                    await self._upload_bundle(await backend.get_bundle(
                        self.__own_bare_jid,
                        self.__own_device_id
                    ))

                    # Trigger a refresh of the own device list of the new backend, this will result in this
                    # device being added to the lists and the lists republished.
                    await self.refresh_device_list(backend.namespace, self.__own_bare_jid)

            # Perform cleanup of removed backends
            for namespace in active_namespaces - loaded_namespaces:
                await self.purge_backend(namespace)

        # Start signed pre key rotation management "in the background"
        asyncio.ensure_future(self.__manage_signed_pre_key_rotation(signed_pre_key_rotation_period))

        logging.getLogger(SessionManager.LOG_TAG).info(
            "Library core prepared, entering history synchronization mode."
        )

        return self

    async def purge_backend(self, namespace: str) -> None:
        """
        Purge a backend, removing both the online data (bundle, device list entry) and the offline data that
        belongs to this backend. Note that the backend-specific offline data can only be purged if the
        respective backend is currently loaded. This backend-specific removal can be triggered manually at any
        time by calling the :meth:`~omemo.backend.Backend.purge` method of the respecfive backend. If the
        backend to purge is currently loaded, the method will unload it.

        Args:
            namespace: The XML namespace managed by the backend to purge.

        Raises:
            BundleDeletionFailed: if a bundle deletion failed. Forwarded from :meth:`_delete_bundle`.
            DeviceListUploadFailed: if a device list upload failed. Forwarded from
                :meth:`_upload_device_list`.
            DeviceListDownloadFailed: if a device list download failed. Forwarded from
                :meth:`_download_device_list`.

        Warning:
            Make sure to unsubscribe from updates to all device lists before calling this method.

        Note:
            If the backend-specific offline data is not purged, the backend can be loaded again at a later
            point and the online data can be restored. This is what happens when a backend that was previously
            loaded is omitted from :meth:`create`.
        """

        logging.getLogger(SessionManager.LOG_TAG).warning(f"Purging backend {namespace}")

        # First half of online data removal: remove this device from the device list. This has to be the first
        # step for consistency reasons.
        device_list = await self._download_device_list(namespace, self.__own_bare_jid)
        try:
            device_list.pop(self.__own_device_id)
        except KeyError:
            pass
        else:
            await self._upload_device_list(namespace, device_list)

        # Synchronize the offline device list with the online information
        device, _ = await self.get_own_device_information()
        active = dict(device.active)
        active.pop(namespace, None)
        device = device._replace(namespaces=device.namespaces - frozenset([ namespace ]))
        device = device._replace(active=frozenset(active.items()))

        await self.__storage.store(
            f"/devices/{self.__own_bare_jid}/{self.__own_device_id}/namespaces",
            list(device.namespaces)
        )

        await self.__storage.store(
            f"/devices/{self.__own_bare_jid}/{self.__own_device_id}/active",
            dict(device.active)
        )

        # If the backend is currently loaded, remove it from the list of loaded backends
        purged_backend = next(filter(lambda backend: backend.namespace == namespace, self.__backends), None)
        self.__backends = list(filter(lambda backend: backend.namespace != namespace, self.__backends))

        # Remaining backend-specific offline data removal
        if purged_backend is None:
            logging.getLogger(SessionManager.LOG_TAG).info(
                "The backend to purge is not currently loaded. Not purging backend-specific data,"
                " only online data."
            )
        else:
            logging.getLogger(SessionManager.LOG_TAG).info(
                "The backend to purge is currently loaded. Purging backend-specific offline data in addition"
                " to the online data."
            )
            await purged_backend.purge()

        # Second half of online data removal: delete the bundle of this device. This step has low priority,
        # thus done last.
        await self._delete_bundle(namespace, self.__own_device_id)

        logging.getLogger(SessionManager.LOG_TAG).info(f"Backend {namespace} purged.")

    async def purge_bare_jid(self, bare_jid: str) -> None:
        """
        Delete all data corresponding to an XMPP account. This includes the device list, trust information and
        all sessions across all loaded backends. The backend-specific data can be removed at any time by
        calling the :meth:`~omemo.backend.Backend.purge_bare_jid` method of the respective backend.

        Args:
            bare_jid: Delete all data corresponding to this bare JID.
        """

        logging.getLogger(SessionManager.LOG_TAG).warning(f"Purging bare JID {bare_jid}")

        storage = self.__storage

        # Get the set of devices to delete
        device_list = frozenset((await storage.load_list(f"/devices/{bare_jid}/list", int)).maybe([]))

        # Collect identity keys used by this account
        identity_keys: Set[bytes] = set()
        for device_id in device_list:
            try:
                identity_keys.add((await storage.load_bytes(
                    f"/devices/{bare_jid}/{device_id}/identity_key"
                )).from_just())
            except NothingException:
                pass

        # Delete information about the individual devices
        for device_id in device_list:
            await storage.delete(f"/devices/{bare_jid}/{device_id}/namespaces")
            await storage.delete(f"/devices/{bare_jid}/{device_id}/active")
            await storage.delete(f"/devices/{bare_jid}/{device_id}/label")
            await storage.delete(f"/devices/{bare_jid}/{device_id}/identity_key")

        # Delete the device list
        await storage.delete(f"/devices/{bare_jid}/list")

        # Delete information about the identity keys
        for identity_key in identity_keys:
            await storage.delete(
                f"/trust/{bare_jid}/{base64.urlsafe_b64encode(identity_key).decode('ASCII')}"
            )

        # Remove backend-specific data
        for backend in self.__backends:
            await backend.purge_bare_jid(bare_jid)

        logging.getLogger(SessionManager.LOG_TAG).info(
            f"Bare JID {bare_jid} purged from library core data and backend-specific data of all currently"
            " loaded backends."
        )

    async def __manage_signed_pre_key_rotation(self, signed_pre_key_rotation_period: int) -> None:
        """
        Manage signed pre key rotation. Checks for signed pre keys that are due for rotation, rotates them,
        uploads the new bundles, and then goes to sleep until the next rotation is due, in an infinite loop.
        Start this loop "in the background" using ``asyncio.ensure_future``, without ``await``ing the result.

        Args:
            signed_pre_key_rotation_period: The rotation period for the signed pre key, in seconds. The
                rotation period is recommended to be between one week and one month.

        Note:
            If a bundle upload fails after rotating a signed pre key, the method stalls further rotations and
            instead periodically attempts to upload the bundle. Once the bundle upload succeeds, the method
            returns to normal operation.
        """

        while True:
            # Keep track of when the next signed pre key rotation is due
            next_check = signed_pre_key_rotation_period

            # For each backend, check whether the signed pre key is due for rotation
            for backend in self.__backends:
                signed_pre_key_age = await backend.signed_pre_key_age()
                next_rotation = signed_pre_key_rotation_period - signed_pre_key_age

                logging.getLogger(SessionManager.LOG_TAG).debug(
                    f"Signed pre key age for backend {backend.namespace}: {signed_pre_key_age}. Rotating in"
                    f" {next_rotation} seconds."
                )

                if next_rotation < 0:
                    # Rotate the signed pre if necessary
                    await backend.rotate_signed_pre_key()
                    while True:
                        retry_delay = 60  # Start with one minute of retry delay
                        try:
                            await self._upload_bundle(await backend.get_bundle(
                                self.__own_bare_jid,
                                self.__own_device_id
                            ))
                        except BundleUploadFailed:
                            logging.getLogger(SessionManager.LOG_TAG).error(
                                "Bundle upload failed after rotating signed pre key.",
                                exc_info=True
                            )
                            await asyncio.sleep(retry_delay)
                            retry_delay += 2  # Double the retry delay
                            retry_delay = min(retry_delay, 60 * 60)  # Cap the retry delay at one hour
                        else:
                            break
                else:
                    # Otherwise, keep track of when the next signed pre key rotation is due
                    next_check = min(next_check, next_rotation)

            logging.getLogger(SessionManager.LOG_TAG).debug(
                f"The next signed pre key rotation is due in {next_check} seconds."
            )

            # Add a minute to the delay for the next check
            next_check += 60

            # Wait for the given delay and check again
            await asyncio.sleep(next_check)

    async def ensure_data_consistency(self) -> None:
        """
        Ensure that the online data for all loaded backends is consistent with the offline data. Refreshes
        device lists of all backends while making sure that this device is included in all of them. Downloads
        the bundle for each backend, compares it with the local bundle contents, and uploads the local bundle
        if necessary.

        Raises:
            DeviceListDownloadFailed: if a device list download failed. Forwarded from
                :meth:`_download_device_list`.
            DeviceListUploadFailed: if a device list upload failed. Forwarded from :meth:`update_device_list`.
            BundleUploadFailed: if a bundle upload failed. Forwarded from :meth:`_upload_bundle`.

        Note:
            This method is not called automatically by the library, since under normal working conditions,
            online and offline data should never desync. However, if clients can spare the network traffic, it
            is recommended to call this method e.g. once after starting the library and possibly in other
            scenarios/at regular intervals too.
        """

        logging.getLogger(SessionManager.LOG_TAG).info("Ensuring data consistency.")

        for backend in self.__backends:
            await self.refresh_device_list(backend.namespace, self.__own_bare_jid)

            local_bundle = await backend.get_bundle(self.__own_bare_jid, self.__own_device_id)

            upload_bundle = False
            try:
                remote_bundle = await self._download_bundle(
                    backend.namespace,
                    self.__own_bare_jid,
                    self.__own_device_id
                )
            except BundleDownloadFailed:
                logging.getLogger(SessionManager.LOG_TAG).warning(
                    "Couldn't download own bundle.",
                    exc_info=True
                )

                upload_bundle = True
            else:
                upload_bundle = remote_bundle != local_bundle

            if upload_bundle:
                logging.getLogger(SessionManager.LOG_TAG).warning(
                    "Online bundle data differs from offline bundle data."
                )

                await self._upload_bundle(local_bundle)

        logging.getLogger(SessionManager.LOG_TAG).info("Data consistency ensured/restored.")

    ####################
    # abstract methods #
    ####################

    @staticmethod
    @abstractmethod
    async def _upload_bundle(bundle: Bundle) -> Any:
        """
        Upload the bundle corresponding to this device, overwriting any previously published bundle data.

        Args:
            bundle: The bundle to publish.

        Returns:
            Anything, the return value is ignored.

        Raises:
            UnknownNamespace: if the namespace is unknown.
            BundleUploadFailed: if the upload failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.

        Note:
            This method must be able to handle at least the namespaces of all loaded backends.
        """

    @staticmethod
    @abstractmethod
    async def _download_bundle(namespace: str, bare_jid: str, device_id: int) -> Bundle:
        """
        Download the bundle corresponding to a specific device.

        Args:
            namespace: The XML namespace to execute this operation under.
            bare_jid: The bare JID the device belongs to.
            device_id: The id of the device.

        Returns:
            The bundle.

        Raises:
            UnknownNamespace: if the namespace is unknown.
            BundleDownloadFailed: if the download failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.

        Note:
            This method must be able to handle at least the namespaces of all loaded backends.
        """

    @staticmethod
    @abstractmethod
    async def _delete_bundle(namespace: str, device_id: int) -> Any:
        """
        Delete the bundle corresponding to this device.

        Args:
            namespace: The XML namespace to execute this operation under.
            device_id: The id of this device.

        Returns:
            Anything, the return value is ignored.

        Raises:
            UnknownNamespace: if the namespace is unknown.
            BundleDeletionFailed: if the deletion failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.

        Note:
            This method must be able to handle at least the namespaces of all loaded backends. In case of
            backend purging via :meth:`purge_backend`, the corresponding namespace must be supported even if
            the backend is not currently loaded.
        """

    @staticmethod
    @abstractmethod
    async def _upload_device_list(namespace: str, device_list: Dict[int, Optional[str]]) -> Any:
        """
        Upload the device list for this XMPP account.

        Args:
            namespace: The XML namespace to execute this operation under.
            device_list: The device list to upload. Mapping from device id to optional label.

        Returns:
            Anything, the return value is ignored.

        Raises:
            UnknownNamespace: if the namespace is unknown.
            DeviceListUploadFailed: if the upload failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.

        Note:
            This method must be able to handle at least the namespaces of all loaded backends.
        """

    @staticmethod
    @abstractmethod
    async def _download_device_list(namespace: str, bare_jid: str) -> Dict[int, Optional[str]]:
        """
        Download the device list of a specific XMPP account.

        Args:
            namespace: The XML namespace to execute this operation under.
            bare_jid: The bare JID of the XMPP account.

        Returns:
            The device list as a dictionary, mapping the device ids to their optional label.

        Raises:
            UnknownNamespace: if the namespace is unknown.
            DeviceListDownloadFailed: if the download failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.

        Note:
            This method must be able to handle at least the namespaces of all loaded backends.
        """

    @staticmethod
    @abstractmethod
    def _evaluate_custom_trust_level(trust_level_name: str) -> TrustLevel:
        """
        Evaluate a custom trust level to one of the three core trust levels:

        * :attr:`~omemo.types.TrustLevel.TRUSTED`: This device is trusted, encryption/decryption of messages
          to/from it is allowed.
        * :attr:`~omemo.types.TrustLevel.DISTRUSTED`: This device is explicitly *not* trusted, do not
          encrypt/decrypt messages to/from it.
        * :attr:`~omemo.types.TrustLevel.UNDECIDED`: A trust decision is yet to be made. It is not clear
          whether it is okay to encrypt messages to it, however decrypting messages from it is allowed.

        Args:
            trust_level_name: The name of the custom trust level to translate.

        Returns:
            The core trust level corresponding to the custom trust level.

        Raises:
            UnknownTrustLevel: if a custom trust level with this name is not known. Feel free to raise a
                subclass instead.

        Note:
            This method should be "stupid", i.e. only implementing a simple mapping from custom trust levels
            to core trust levels, without any side effects.
        """

    @abstractmethod
    async def _make_trust_decision(self, undecided: FrozenSet[DeviceInformation]) -> Any:
        """
        Make a trust decision on a set of undecided identity keys.

        Args:
            undecided: A set of devices that require trust decisions.

        Returns:
            Anything, the return value is ignored. The trust decisions are expected to be persisted by calling
            :meth:`set_trust`.

        Raises:
            TrustDecisionFailed: if for any reason the trust decision failed/could not be completed. Feel free
                to raise a subclass instead.

        Note:
            This is called when the encryption needs to know whether it is allowed to encrypt for these
            devices or not. When this method returns, all previously undecided trust levels should have been
            replaced by calling :meth:`set_trust` with a different trust level. If they are not replaced or
            still evaluate to the undecided trust level after the call, the encryption will fail with an
            exception. See :meth:`encrypt` for details.
        """

    @staticmethod
    @abstractmethod
    async def _send_message(message: Message) -> Any:
        """
        Send an OMEMO-encrypted message. This is required for various automated behaviours to improve the
        overall stability of the protocol, for example:

        * Automatic handshake completion, by responding to incoming key exchanges.
        * Automatic heartbeat messages to forward the ratchet if many messages were received without a
          (manual) response, to assure forward secrecy (aka staleness prevention). The number of messages
          required to trigger this behaviour is hardcoded in :attr:`STALENESS_MAGIC_NUMBER`.
        * Automatic session initiation if an encrypted message is received but no session exists for that
          device.
        * Backend-dependent session healing mechanisms.
        * Backend-dependent empty messages to notify other devices about potentially "broken" sessions.

        Note that messages sent here do not contain any content, they just transport key material.

        Args:
            message: The message to send.

        Returns:
            Anything, the return value is ignored.

        Raises:
            UnknownNamespace: if the namespace is unknown.
            MessageSendingFailed: if for any reason the message could not be sent. Feel free to raise a
                subclass instead.
        """

    ##########################
    # device list management #
    ##########################

    async def update_device_list(
        self,
        namespace: str,
        bare_jid: str,
        device_list: Dict[int, Optional[str]]
    ) -> None:
        """
        Update the device list of a specific bare JID, e.g. after receiving an update for the XMPP account
        from `PEP <https://xmpp.org/extensions/xep-0163.html>`__.

        Args:
            namespace: The XML namespace to execute this operation under.
            bare_jid: The bare JID of the XMPP account.
            device_list: The updated device list. Mapping from device id to optional label.

        Raises:
            UnknownNamespace: if the backend to handle the message is not currently loaded.
            DeviceListUploadFailed: if a device list upload failed. An upload can happen if the device list
                update is for the own bare JID and does not include the own device. Forwarded from
                :meth:`_upload_device_list`.
        """

        logging.getLogger(SessionManager.LOG_TAG).debug(
            f"Incoming device list update:\n"
            f"\tnamespace={namespace}\n"
            f"\tbare_jid={bare_jid}\n"
            f"\tdevice_list={device_list}"
        )

        storage = self.__storage

        # This isn't strictly necessary, but good for consistency
        if namespace not in frozenset(backend.namespace for backend in self.__backends):
            raise UnknownNamespace(f"The backend handling the namespace {namespace} is not currently loaded.")

        # Copy to make sure the original is not modified
        device_list = dict(device_list)

        new_device_list = frozenset(device_list.keys())
        old_device_list = frozenset((await storage.load_list(f"/devices/{bare_jid}/list", int)).maybe([]))

        new_devices = new_device_list - old_device_list

        logging.getLogger(SessionManager.LOG_TAG).debug(f"Old device list: {old_device_list}")

        # If the device list is for this JID and a loaded backend, make sure this device is included
        if (
            bare_jid == self.__own_bare_jid
            and namespace in frozenset(backend.namespace for backend in self.__backends)
            and self.__own_device_id not in new_device_list
        ):
            logging.getLogger(SessionManager.LOG_TAG).warning(
                "Own device id was not included in the online device list."
            )

            # Add this device to the device list and publish it
            device_list[self.__own_device_id] = (await storage.load_optional(
                f"/devices/{self.__own_bare_jid}/{self.__own_device_id}/label",
                str
            )).from_just()
            await self._upload_device_list(namespace, device_list)

        # Add new device information entries for new devices
        for device_id in new_devices:
            await storage.store(f"/devices/{bare_jid}/{device_id}/namespaces", [ namespace ])
            await storage.store(f"/devices/{bare_jid}/{device_id}/active", { namespace: True })
            await storage.store(f"/devices/{bare_jid}/{device_id}/label", device_list[device_id])

        # Update namespaces, label and status for previously known devices
        for device_id in old_device_list:
            namespaces = set((await storage.load_list(
                f"/devices/{bare_jid}/{device_id}/namespaces",
                str
            )).from_just())

            active = (await storage.load_dict(f"/devices/{bare_jid}/{device_id}/active", bool)).from_just()

            if device_id in device_list:
                # Add the namespace if required
                if namespace not in namespaces:
                    namespaces.add(namespace)
                    await storage.store(f"/devices/{bare_jid}/{device_id}/namespaces", list(namespaces))

                # Update the status if required
                if namespace not in active or active[namespace] is False:
                    active[namespace] = True
                    await storage.store(f"/devices/{bare_jid}/{device_id}/active", active)

                # Update the label if required. Even though loading the value first isn't strictly required,
                # it is done under the assumption that loading values is cheaper than writing.
                label = (await storage.load_optional(
                    f"/devices/{bare_jid}/{device_id}/label",
                    str
                )).from_just()

                # Don't interpret ``None`` as "no label set" here. Instead, interpret ``None`` as "the backend
                # doesn't support labels".
                if device_list[device_id] is not None and device_list[device_id] != label:
                    await storage.store(f"/devices/{bare_jid}/{device_id}/label", device_list[device_id])
            else:
                # Update the status if required
                if namespace in namespaces:
                    if active[namespace] is True:
                        active[namespace] = False
                        await storage.store(f"/devices/{bare_jid}/{device_id}/active", active)

        # If there are unknown devices in the new device list, update the list of known devices. Do this as
        # the last step to ensure data consistency.
        if len(new_devices) > 0:
            await storage.store(f"/devices/{bare_jid}/list", list(new_device_list | old_device_list))

        logging.getLogger(SessionManager.LOG_TAG).debug("Device list update processed.")

    async def refresh_device_list(self, namespace: str, bare_jid: str) -> None:
        """
        Manually trigger the refresh of a device list.

        Args:
            namespace: The XML namespace to execute this operation under.
            bare_jid: The bare JID of the XMPP account.

        Raises:
            UnknownNamespace: if the namespace is unknown.
            DeviceListDownloadFailed: if the device list download failed. Forwarded from
                :meth:`_download_device_list`.
            DeviceListUploadFailed: if a device list upload failed. An upload can happen if the device list
                update is for the own bare JID and does not include the own device. Forwarded from
                :meth:`update_device_list`.
        """

        logging.getLogger(SessionManager.LOG_TAG).debug(
            f"Device list refresh triggered for namespace {namespace} and bare JID {bare_jid}."
        )

        await self.update_device_list(
            namespace,
            bare_jid,
            await self._download_device_list(namespace, bare_jid)
        )

    ####################
    # trust management #
    ####################

    async def set_trust(self, bare_jid: str, identity_key: bytes, trust_level_name: str) -> None:
        """
        Set the trust level for an identity key.

        Args:
            bare_jid: The bare JID of the XMPP account this identity key belongs to.
            identity_key: The identity key.
            trust_level_name: The custom trust level to set for the identity key.
        """

        logging.getLogger(SessionManager.LOG_TAG).debug(
            f"Setting trust level for identity key {identity_key} to {trust_level_name}."
        )

        await self.__storage.store(
            f"/trust/{bare_jid}/{base64.urlsafe_b64encode(identity_key).decode('ASCII')}",
            trust_level_name
        )

    ######################
    # session management #
    ######################

    async def replace_sessions(self, device: DeviceInformation) -> Dict[str, OMEMOException]:
        """
        Manually replace all sessions for a device. Can be used if sessions are suspected to be broken. This
        method automatically notifies the other end about the new sessions, so that hopefully no messages are
        lost.

        Args:
            device: The device whose sessions to replace.

        Returns:
            Information about exceptions that happened during session replacement attempts. A mapping from the
            namespace of the backend for which the replacement failed, to the reason of failure. If the reason
            is a :class:`~omemo.storage.StorageException`, there is a high change that the session was left in
            an inconsistent state. Other reasons imply that the session replacement failed before having any
            effect on the state of either side.

        Warning:
            This method can not guarantee that sessions are left in a consistent state. For example, if a
            notification message for the recipient is lost or heavily delayed, the recipient may not know
            about the new session and keep using the old one. Only use this method to attempt replacement of
            sessions that already seem broken. Do not attempt to replace healthy sessions.

        Warning:
            This method does not optimize towards minimizing network usage. One notification message is sent
            per session to replace, the notifications are not bundled. This is to minimize the negative impact
            of network failure.
        """

        logging.getLogger(SessionManager.LOG_TAG).warning(f"Replacing sessions with device {device}.")

        # The challenge with this method is minimizing the impact of failures at any point. For example, if a
        # session is replaced and persisted in storage, but sending the corresponding empty message to notify
        # the recipient about the new session fails, the session in storage will be desync with the session on
        # the recipient side. Thus, the replacement session is only persisted after the message was
        # successfully sent. Persisting the new session could fail, resulting in another desync state, however
        # storage interactions are assumed to be more stable than network interactions. None of this is
        # failure-proof: the notification message could be lost or heavily delayed, too. However, since this
        # method is used to replace broken sessions in the first place, a low chance of replacing the broken
        # session with another broken one doesn't hurt too much.

        # Do not assume that the given device information is complete and up-to-date. It is okay to use
        # get_device_information here, since there can only be sessions for devices that have full device
        # information available.
        device = next(filter(
            lambda dev: dev.device_id == device.device_id,
            await self.get_device_information(device.bare_jid)
        ))

        logging.getLogger(SessionManager.LOG_TAG).debug(f"Device information from storage: {device}")

        # Remove namespaces that correspond to backends which are not currently loaded or backends which have
        # no session for this device.
        device = device._replace(namespaces=(device.namespaces & frozenset(
            backend.namespace
            for backend
            in self.__backends
            if await backend.load_session(device.bare_jid, device.device_id) is not None
        )))

        unsuccessful: Dict[str, OMEMOException] = {}

        # Perform the replacement
        for backend in self.__backends:
            if backend.namespace in device.namespaces:
                try:
                    # Prepare an empty message
                    content, plain_key_material = await backend.encrypt_empty()

                    # Build a new session to replace the old one
                    session, encrypted_key_material = await backend.build_session_active(
                        device.bare_jid,
                        device.device_id,
                        await self._download_bundle(
                            backend.namespace,
                            device.bare_jid,
                            device.device_id
                        ),
                        plain_key_material
                    )

                    # Send the notification message
                    await self._send_message(Message(
                        backend.namespace,
                        self.__own_bare_jid,
                        self.__own_device_id,
                        content,
                        frozenset({ (encrypted_key_material, session.key_exchange) })
                    ))

                    # Store the replacement
                    await backend.store_session(session)
                except OMEMOException as e:
                    logging.getLogger(SessionManager.LOG_TAG).warning(
                        f"Session replacement failed for namespace {backend.namespace}.",
                        exc_info=True
                    )
                    unsuccessful[backend.namespace] = e

        logging.getLogger(SessionManager.LOG_TAG).info("Session replacement done.")

        return unsuccessful

    async def get_sending_chain_length(self, device: DeviceInformation) -> Dict[str, Optional[int]]:
        """
        Get the sending chain lengths of all sessions with a device. Can be used for external staleness
        detection logic.

        Args:
            device: The device.

        Returns:
            A mapping from namespace to sending chain length. `None` for the sending chain length implies that
            there is no session with the device for that backend.
        """

        logging.getLogger(SessionManager.LOG_TAG).debug(f"Sending chain length of device {device} requested.")

        sessions = {
            backend.namespace: await backend.load_session(device.bare_jid, device.device_id)
            for backend
            in self.__backends
            if backend.namespace in device.namespaces
        }

        sending_chain_length = {
            namespace: None if session is None else session.sending_chain_length
            for namespace, session
            in sessions.items()
        }

        logging.getLogger(SessionManager.LOG_TAG).debug(
            f"Sending chain lengths reported by the backends: {sending_chain_length}"
        )

        return sending_chain_length

    ##############################
    # device metadata management #
    ##############################

    async def set_own_label(self, own_label: Optional[str]) -> None:
        """
        Replace the label for this device, if supported by any of the backends.

        Args:
            own_label: The new (optional) label for this device.

        Raises:
            DeviceListUploadFailed: if a device list upload failed. Forwarded from
                :meth:`_upload_device_list`.
            DeviceListDownloadFailed: if a device list download failed. Forwarded from
                :meth:`_download_device_list`.

        Note:
            It is recommended to keep the length of the label under 53 unicode code points.
        """

        logging.getLogger(SessionManager.LOG_TAG).debug(f"Updating own label to {own_label}.")

        # Store the new label
        await self.__storage.store(f"/devices/{self.__own_bare_jid}/{self.__own_device_id}/label", own_label)

        # For each loaded backend, upload an updated device list including the new label
        for backend in self.__backends:
            # Note: it is not required to download the device list here, since it should be cached locally.
            # However, one PEP node fetch per backend isn't super expensive and it's nice to avoid the code to
            # load the cached device list.
            device_list = await self._download_device_list(backend.namespace, self.__own_bare_jid)
            device_list[self.__own_device_id] = own_label
            await self._upload_device_list(backend.namespace, device_list)

    async def get_device_information(self, bare_jid: str) -> FrozenSet[DeviceInformation]:
        """
        Args:
            bare_jid: Get information about the devices of the XMPP account belonging to this bare JID.

        Returns:
            Information about each device of `bare_jid`. The information includes the device id, the identity
            key, the trust level, whether the device is active and, if supported by any of the backends, the
            optional label. Returns information about all known devices, regardless of the backend they belong
            to.

        Note:
            Only returns information about cached devices. The cache, however, should be up to date if
            `PEP <https://xmpp.org/extensions/xep-0163.html>`__ updates are correctly fed to
            :meth:`update_device_list`. A manual update of a device list can be triggered using
            :meth:`refresh_device_list` if needed.

        Warning:
            This method attempts to download the bundle of devices whose corresponding identity key is not
            known yet. In case the information can not be fetched due to bundle download failures, the device
            is not included in the returned set.
        """

        # Do not expose the bundle cache publicly.
        return (await self.__get_device_information(bare_jid))[0]

    async def __get_device_information(
        self,
        bare_jid: str
    ) -> Tuple[FrozenSet[DeviceInformation], FrozenSet[Bundle]]:
        """
        Internal implementation of :meth:`get_device_information` with the return value extended to include
        bundles that were downloaded in the process.

        Args:
            bare_jid: Get information about the devices of the XMPP account belonging to this bare JID.

        Returns:
            Information about each device of `bare_jid`. The information includes the device id, the identity
            key, the trust level, whether the device is active and, if supported by any of the backends, the
            optional label. Returns information about all known devices, regardless of the backend they belong
            to. In the process of gathering this information, it may be necessary to download bundles. Those
            bundles are returned as well, so that they can be used if required immediately afterwards. This is
            to avoid double downloading bundles during encryption/decryption flows and is purely for internal
            use.

        Warning:
            This method attempts to download the bundle of devices whose corresponding identity key is not
            known yet. In case the information can not be fetched due to bundle download failures, the device
            is not included in the returned set.
        """

        logging.getLogger(SessionManager.LOG_TAG).debug(
            f"Gathering device information for bare JID {bare_jid}."
        )

        storage = self.__storage

        device_list = frozenset((await storage.load_list(f"/devices/{bare_jid}/list", int)).maybe([]))

        logging.getLogger(SessionManager.LOG_TAG).debug(f"Offline device list: {device_list}")

        devices: Set[DeviceInformation] = set()
        bundle_cache: Set[Bundle] = set()

        for device_id in device_list:
            namespaces = frozenset((await storage.load_list(
                f"/devices/{bare_jid}/{device_id}/namespaces",
                str
            )).from_just())

            # Load the identity key as soon as possible, since this is the most likely operation to fail (due
            # to bundle downloading errors)
            identity_key: bytes
            try:
                identity_key = (await storage.load_bytes(
                    f"/devices/{bare_jid}/{device_id}/identity_key"
                )).from_just()
            except NothingException:
                logging.getLogger(SessionManager.LOG_TAG).debug(
                    f"Identity key assigned to device {device_id} not known."
                )

                # The identity key assigned to this device is not known yet. Fetch the bundle to find that
                # information. Return the downloaded bundle to avoid double-fetching it if the same bundle is
                # required for session initiation afterwards.
                for namespace in namespaces:
                    try:
                        bundle = await self._download_bundle(namespace, bare_jid, device_id)
                    except BundleDownloadFailed:
                        logging.getLogger(SessionManager.LOG_TAG).warning(
                            f"Bundle download failed for device {device_id} of bare JID {bare_jid} for"
                            f" namespace {namespace}.",
                            exc_info=True
                        )
                    else:
                        logging.getLogger(SessionManager.LOG_TAG).debug(
                            f"Identity key information extracted from bundle of namespace {namespace}."
                        )

                        bundle_cache.add(bundle)

                        identity_key = bundle.identity_key

                        await storage.store_bytes(
                            f"/devices/{bare_jid}/{device_id}/identity_key",
                            identity_key
                        )
                        break
                else:
                    # Skip this device in case none of the bundles could be downloaded
                    logging.getLogger(SessionManager.LOG_TAG).warning(
                        f"Not including device {device_id} in the device information set for bare JID"
                        f" {bare_jid} due to the lack of downloadable bundles for identity key assignment."
                    )
                    continue

            active = (await storage.load_dict(f"/devices/{bare_jid}/{device_id}/active", bool)).from_just()
            label = (await storage.load_optional(f"/devices/{bare_jid}/{device_id}/label", str)).from_just()

            trust_level_name = (await storage.load_primitive(
                f"/trust/{bare_jid}/{base64.urlsafe_b64encode(identity_key).decode('ASCII')}",
                str
            )).maybe(self.__undecided_trust_level_name)

            devices.add(DeviceInformation(
                namespaces=namespaces,
                active=frozenset(active.items()),
                bare_jid=bare_jid,
                device_id=device_id,
                identity_key=identity_key,
                trust_level_name=trust_level_name,
                label=label
            ))

        logging.getLogger(SessionManager.LOG_TAG).debug("Device information gathered.")

        return frozenset(devices), frozenset(bundle_cache)

    async def get_own_device_information(self) -> Tuple[DeviceInformation, FrozenSet[DeviceInformation]]:
        """
        Variation of :meth:`get_device_information` for convenience.

        Returns:
            A tuple, where the first entry is information about this device and the second entry contains
            information about the other devices of the own bare JID.
        """

        all_own_devices = await self.get_device_information(self.__own_bare_jid)
        other_own_devices = frozenset(filter(
            lambda dev: dev.device_id != self.__own_device_id,
            all_own_devices
        ))

        return next(iter(all_own_devices - other_own_devices)), other_own_devices

    @staticmethod
    def format_identity_key(identity_key: bytes) -> List[str]:
        """
        Args:
            identity_key: The identity key to generate the fingerprint of.

        Returns:
            The fingerprint of the identity key, as eight groups of eight lowercase hex chars each. Consider
            applying `Consistent Color Generation <https://xmpp.org/extensions/xep-0392.html>`__ to each
            individual group when displaying the fingerprint, if applicable.
        """

        ik_hex_string = identity_key.hex()
        group_size = 8

        return [ ik_hex_string[i:i + group_size] for i in range(0, len(ik_hex_string), group_size) ]

    ###########################
    # history synchronization #
    ###########################

    def before_history_sync(self) -> None:
        """
        Sets the library into "history synchronization mode". In this state, the library assumes that it was
        offline before and is now running catch-up with whatever happened during the offline phase. Make sure
        to call :meth:`after_history_sync` when the history synchronization (if any) is done, so that the
        library can change to normal working behaviour again. The library automatically enters history
        synchronization mode when loaded via :meth:`create`. Calling this method again when already in history
        synchronization mode has no effect.

        Internally, the library does the following things differently during history synchronization:

        * Pre keys are kept around during history synchronization, to account for the (hopefully rather
          hypothetical) case that two or more parties selected the same pre key to initiate a session with
          this device while it was offline. When history synchronization ends, all pre keys that were kept
          around are deleted and the library returns to normal behaviour.
        * Empty messages to "complete" sessions or prevent staleness are deferred until after the
          synchronization is done. Only one empty message is sent per session when exiting the history
          synchronization mode.

        Note:
            While in history synchronization mode, the library can process live events too.
        """

        logging.getLogger(SessionManager.LOG_TAG).info("Entering history synchronization mode.")

        self.__synchronizing = True

    async def after_history_sync(self) -> None:
        """
        If the library is in "history synchronization mode" started by :meth:`create` or
        :meth:`before_history_sync`, calling this makes it return to normal working behaviour. Make sure to
        call this as soon as history synchronization (if any) is done.

        Raises:
            MessageSendingFailed: if one of the queued empty messages could not be sent. Forwarded from
                :meth:`_send_message`.
        """

        logging.getLogger(SessionManager.LOG_TAG).info("Exiting history synchronization mode.")

        storage = self.__storage

        self.__synchronizing = False

        # Delete pre keys that were hidden while in history synchronization mode
        for backend in self.__backends:
            await backend.delete_hidden_pre_keys()

        # Send empty messages that were queued while in history synchronization mode
        for backend in self.__backends:
            # Load and delete the list of bare JIDs that have queued empty messages for this backend
            queued_jids = frozenset((await storage.load_list(f"/queue/{backend.namespace}", str)).maybe([]))
            await storage.delete(f"/queue/{backend.namespace}")

            logging.getLogger(SessionManager.LOG_TAG).debug(
                f"Bare JIDs for which empty messages are queued for namespace {backend.namespace}:"
                f" {queued_jids}"
            )

            for bare_jid in queued_jids:
                # For each queued bare JID, load and delete the list of devices that have queued an empty
                # message for this backend
                queued_device_ids = frozenset((await storage.load_list(
                    f"/queue/{backend.namespace}/{bare_jid}",
                    int
                )).maybe([]))
                await storage.delete(f"/queue/{backend.namespace}/{bare_jid}")

                logging.getLogger(SessionManager.LOG_TAG).debug(f"Queued device ids: {queued_device_ids}")

                for device_id in queued_device_ids:
                    session = await backend.load_session(bare_jid, device_id)
                    if session is None:
                        logging.getLogger(SessionManager.LOG_TAG).warning(
                            f"Can't send queued empty message for device {device_id} of bare JID {bare_jid}"
                            f" for namespace {backend.namespace}. The session could not be loaded."
                        )
                    else:
                        # It is theoretically possible that the session has been deleted after an empty
                        # message was queued for it.
                        await self.__send_empty_message(backend, session)

        logging.getLogger(SessionManager.LOG_TAG).debug("History synchronization mode exited.")

    ######################
    # en- and decryption #
    ######################

    async def __send_empty_message(self, backend: Backend, session: Session) -> None:
        """
        Internal helper to send an empty message for ratchet forwarding.

        Args:
            backend: The backend to encrypt the message with.
            session: The session to encrypt the message with.

        Raises:
            MessageSendingFailed: if the message could not be sent. Forwarded from :meth:`_send_message`.
        """

        logging.getLogger(SessionManager.LOG_TAG).debug(
            f"Sending empty message using session {session} ({session.device_id}, {session.bare_jid},"
            f" {session.namespace}) and backend {backend} ({backend.namespace})."
        )

        content, plain_key_material = await backend.encrypt_empty()
        encrypted_key_material = await backend.encrypt_key_material(session, plain_key_material)
        await self._send_message(Message(
            backend.namespace,
            self.__own_bare_jid,
            self.__own_device_id,
            content,
            frozenset({ (encrypted_key_material, (
                session.key_exchange
                if session.initiation is Initiation.ACTIVE and not session.confirmed
                else None
            )) })
        ))
        await backend.store_session(session)

    async def encrypt(
        self,
        bare_jids: FrozenSet[str],
        plaintext: Dict[str, bytes],
        backend_priority_order: Optional[List[str]] = None
    ) -> Tuple[FrozenSet[Message], FrozenSet[EncryptionError]]:
        """
        Encrypt some plaintext for a set of recipients.

        Args:
            bare_jids: The bare JIDs of the intended recipients.
            plaintext: The plaintext to encrypt for the recipients. Since different backends may use different
                kinds of plaintext, for example just the message body versus a whole stanza using
                `Stanza Content Encryption <https://xmpp.org/extensions/xep-0420.html>`__, this parameter is a
                dictionary, where the keys are backend namespaces and the values are the plaintext for each
                specific backend. The plaintext has to be supplied for each backend.
            backend_priority_order: If a recipient device supports multiple versions of OMEMO, this parameter
                decides which version to prioritize. If ``None`` is supplied, the order of backends as passed
                to :meth:`create` is assumed as the order of priority. If a list of namespaces is supplied,
                the first namespace supported by the recipient is chosen. Lower index means higher priority.

        Returns:
            One message per backend, encrypted for each device of each recipient and for other devices of this
            account, and a set of non-critical errors encountered during encryption.

        Raises:
            UnknownNamespace: if the backend priority order list contains a namespace of a backend that is not
                currently available.
            UnknownTrustLevel: if an unknown custom trust level name is encountered. Forwarded from
                :meth:`_evaluate_custom_trust_level`.
            TrustDecisionFailed: if for any reason the trust decision for undecided devices failed/could not
                be completed. Forwarded from :meth:`_make_trust_decision`.
            StillUndecided: if the trust level for one of the recipient devices still evaluates to undecided,
                even after :meth:`_make_trust_decision` was called to decide on the trust.
            NoEligibleDevices: if at least one of the intended recipients does not have a single device which
                qualifies for encryption. Either the recipient does not advertize any OMEMO-enabled devices or
                all devices were disqualified due to missing trust or failure to download their bundles.
            BundleDownloadFailed: if a bundle download failed. Forwarded from :meth:`_download_bundle`.
            KeyExchangeFailed: in case there is an error during the key exchange required for session
                building. Forwarded from :meth:`~omemo.backend.Backend.build_session_active`.

        Note:
            The own JID is implicitly added to the set of recipients, there is no need to list it manually.
        """

        logging.getLogger(SessionManager.LOG_TAG).debug(
            f"Encrypting plaintext {plaintext} for recipients {bare_jids} with following backend priority"
            f" order: {backend_priority_order}"
        )

        # Prepare the backend priority order list
        available_namespaces = [ backend.namespace for backend in self.__backends ]

        if backend_priority_order is not None:
            unavailable_namespaces = frozenset(backend_priority_order) - frozenset(available_namespaces)
            if len(unavailable_namespaces) > 0:
                raise UnknownNamespace(
                    f"One or more unavailable namespaces were passed in the backend priority order list:"
                    f" {unavailable_namespaces}"
                )

        effective_backend_priority_order = \
            available_namespaces if backend_priority_order is None else backend_priority_order

        logging.getLogger(SessionManager.LOG_TAG).debug(
            f"Effective backend priority order: {effective_backend_priority_order}"
        )

        # Add the own bare JID to the list of recipients.
        # Copy to make sure the original is not modified.
        bare_jids = frozenset(bare_jids) | frozenset({ self.__own_bare_jid })

        # Load the device information of all recipients
        def is_valid_recipient_device(device: DeviceInformation) -> bool:
            """
            Helper that performs various checks to device whether a device is a valid recipient for this
            encryption operation or not. Excluded are:
            - this device aka the sending device
            - devices that are only supported by inactive backends
            - devices that are only supported by backends which are not in the effective priority order list

            Args:
                device: The device to check.

            Returns:
                Whether the device is a valid recipient for this encryption operation or not.
            """

            # Remove the own device
            if device.bare_jid == self.__own_bare_jid and device.device_id == self.__own_device_id:
                return False

            # Remove namespaces for which the device is inactive
            namespaces_active = frozenset(filter(
                lambda namespace: dict(device.active)[namespace],
                device.namespaces
            ))

            # Remove devices which are only available with backends that are not currently loaded and in
            # the priority list
            if len(namespaces_active & frozenset(effective_backend_priority_order)) == 0:
                return False

            return True

        # Using get_device_information here means that some devices may be excluded, if their corresponding
        # identity key is not known and attempts to download the respecitve bundles fail. Those devices
        # missing is fine, since get_device_information is the public API for device information anyway, so
        # the publicly available device list and the recipient devices used here are consistent.
        tmp = frozenset([ await self.__get_device_information(bare_jid) for bare_jid in bare_jids ])

        devices = cast(Set[DeviceInformation], set()).union(*(devices for devices, _ in tmp))
        devices = set(filter(is_valid_recipient_device, devices))

        bundle_cache = cast(FrozenSet[Bundle], frozenset()).union(*(bundle_cache for _, bundle_cache in tmp))

        logging.getLogger(SessionManager.LOG_TAG).debug(
            f"Recipient devices: {devices}, bundle cache: {bundle_cache}"
        )

        # Apply the backend priority order to the remaining devices
        def apply_backend_priorty_order(
            device: DeviceInformation,
            backend_priority_order: List[str]
        ) -> DeviceInformation:
            """
            Apply the backend priority order to the namespaces of a device.

            Args:
                device: The devices whose namespaces to adjust.
                backend_priority_order: The backend priority order given as a list of namespaces. Lower index
                    means higher priority.

            Returns:
                A copy of the device, with the namespaces adjusted. The set of supported namespaces contains
                only one namespace - the one with highest priority that is supported by the device.
            """

            return device._replace(namespaces=frozenset(sorted((
                namespace
                for namespace
                in device.namespaces
                if dict(device.active)[namespace] and namespace in backend_priority_order
            ), key=backend_priority_order.index)[0:1]))

        devices = {
            apply_backend_priorty_order(device, effective_backend_priority_order) for device in devices
        }

        # Remove devices that are not covered by the effective backend priority list
        devices = { device for device in devices if len(device.namespaces) > 0 }

        logging.getLogger(SessionManager.LOG_TAG).debug(f"Backend priority order applied: {devices}")

        # Ask for trust decisions on the remaining devices (or rather, on the identity keys corresponding to
        # the remaining devices)
        def is_undecided(device: DeviceInformation) -> bool:
            """
            Helper for trust level evaluation and checks.

            Args:
                device: A device.

            Returns:
                Whether the trust status of this device is undecided, i.e. whether the custom trust level
                assigned to the identity key used by this device evaluates to
                :attr:`~omemo.types.TrustLevel.UNDECIDED`.
            """

            return self._evaluate_custom_trust_level(device.trust_level_name) is TrustLevel.UNDECIDED

        def is_trusted(device: DeviceInformation) -> bool:
            """
            Helper for trust level evaluation and checks.

            Args:
                device: A device.

            Returns:
                Whether the trust status of this device is trusted, i.e. whether the custom trust level
                assigned to the identity key used by this device evaluates to
                :attr:`~omemo.types.TrustLevel.TRUSTED`.
            """

            return self._evaluate_custom_trust_level(device.trust_level_name) is TrustLevel.TRUSTED

        undecided_devices = frozenset(filter(is_undecided, devices))
        logging.getLogger(SessionManager.LOG_TAG).debug(f"Undecided devices: {undecided_devices}")
        if len(undecided_devices) > 0:
            await self._make_trust_decision(undecided_devices)

            # Update to the new trust levels
            devices = { device._replace(trust_level_name=(await self.__storage.load_primitive(
                f"/trust/{device.bare_jid}/{base64.urlsafe_b64encode(device.identity_key).decode('ASCII')}",
                str
            )).maybe(self.__undecided_trust_level_name)) for device in devices }

            logging.getLogger(SessionManager.LOG_TAG).debug(f"Updated trust: {devices}")

        # Make sure the trust status of all previously undecided devices has been decided on
        undecided_devices = frozenset(filter(is_undecided, devices))
        if len(undecided_devices) > 0:
            raise StillUndecided(
                f"The trust status of one or more devices has not been decided on: {undecided_devices}"
            )

        # Keep only trusted devices
        devices = set(filter(is_trusted, devices))

        logging.getLogger(SessionManager.LOG_TAG).debug(f"Trusted devices: {devices}")

        # Encrypt the plaintext once per backend.
        # About error handling:
        # - It doesn't matter if a message is encrypted, the corresponding session is stored, and a failure
        #   occurs afterwards. The cryptography/ratchet will not break if that happens.
        # - Because of the previous point, library-scoped failures like storage failures can crash the whole
        #   encryption process without risking inconsistencies.
        # - Other than library-scoped failures like storage failures, the only thing that can fail are bundle
        #   fetches/key agreements with new devices. Those failures must not prevent the encryption for the
        #   other devices to fail. Instead, those failures are collected and returned together with the
        #   successful encryption results, such that the library user can decide how to react in detail.
        messages: Set[Message] = set()
        encryption_errors: Set[EncryptionError] = set()
        sessions: Set[Tuple[Backend, Session]] = set()
        for backend in self.__backends:
            # Find the devices to encrypt for using this backend
            backend_devices = frozenset(
                device for device in devices if next(iter(device.namespaces)) == backend.namespace
            )

            logging.getLogger(SessionManager.LOG_TAG).debug(
                f"Encrypting for devices {backend_devices} using backend {backend.namespace}."
            )

            # Skip this backend if there isn't a single recipient device using it
            if len(backend_devices) == 0:
                continue

            # Encrypt the message content symmetrically
            content, plain_key_material = await backend.encrypt_plaintext(plaintext[backend.namespace])

            keys: Set[Tuple[EncryptedKeyMaterial, Optional[KeyExchange]]] = set()

            for device in backend_devices:
                # Attempt to load the session
                session = await backend.load_session(device.bare_jid, device.device_id)
                logging.getLogger(SessionManager.LOG_TAG).debug(f"Session for device {device}: {session}")

                # Prepare the cached bundle in case it is needed for session building
                bundle = next((bundle for bundle in bundle_cache if (
                    bundle.namespace == backend.namespace
                    and bundle.bare_jid == device.bare_jid
                    and bundle.device_id == device.device_id
                )), None)
                logging.getLogger(SessionManager.LOG_TAG).debug(f"Cached bundle: {bundle}")

                try:
                    # Build the session if necessary, and encrypt the key material
                    session, encrypted_key_material = await backend.build_session_active(
                        device.bare_jid,
                        device.device_id,
                        await self._download_bundle(
                            backend.namespace,
                            device.bare_jid,
                            device.device_id
                        ) if bundle is None else bundle,
                        plain_key_material
                    ) if session is None else (session, await backend.encrypt_key_material(
                        session,
                        plain_key_material
                    ))
                except (BundleDownloadFailed, KeyExchangeFailed) as e:
                    # Those failures are non-critical, i.e. encryption for other devices is still performed
                    # and the errors are simply collected and returned.
                    devices.remove(device)
                    encryption_errors.add(EncryptionError(
                        backend.namespace,
                        device.bare_jid,
                        device.device_id,
                        e
                    ))
                else:
                    # Extract the data that needs to be sent to the other party
                    keys.add((encrypted_key_material, (
                        session.key_exchange
                        if session.initiation is Initiation.ACTIVE and not session.confirmed
                        else None
                    )))

                    # Keep track of the modified sessions to store them once encryption is fully done.
                    sessions.add((backend, session))

            # Build the message from content, key material and key exchange information
            messages.add(Message(
                backend.namespace,
                self.__own_bare_jid,
                self.__own_device_id,
                content,
                frozenset(keys)
            ))

        logging.getLogger(SessionManager.LOG_TAG).debug(f"Devices with sessions: {devices}")

        # Check for recipients without a single remaining device
        no_eligible_devices = frozenset(filter(
            lambda bare_jid: all(device.bare_jid != bare_jid for device in devices),
            bare_jids
        ))

        if len(no_eligible_devices) > 0:
            raise NoEligibleDevices(
                no_eligible_devices,
                "One or more of the intended recipients does not have a single active and trusted device with"
                " a valid session for the loaded backends."
            )

        for backend, session in sessions:
            # Persist the session as the final step
            await backend.store_session(session)

        logging.getLogger(SessionManager.LOG_TAG).debug(f"Message encrypted: {messages}")
        logging.getLogger(SessionManager.LOG_TAG).debug(
            f"Non-critical encryption errors: {encryption_errors}"
        )

        return frozenset(messages), frozenset(encryption_errors)

    async def decrypt(self, message: Message) -> Tuple[Optional[bytes], DeviceInformation]:
        """
        Decrypt a message.

        Args:
            message: The message to decrypt.

        Returns:
            A tuple, where the first entry is the decrypted plaintext and the second entry contains
            information about the device that sent the message. The plaintext is optional and will be ``None``
            in case the message was an empty OMEMO message purely used for protocol stability reasons.

        Raises:
            UnknownNamespace: if the backend to handle the message is not currently loaded.
            UnknownTrustLevel: if an unknown custom trust level name is encountered. Forwarded from
                :meth:`_evaluate_custom_trust_level`.
            KeyExchangeFailed: in case a new session is built while decrypting this message, and there is an
                error during the key exchange that's part of the session building. Forwarded from
                :meth:`~omemo.backend.Backend.build_session_passive`.
            MessageNotForUs: in case the message does not seem to be encrypted for us.
            SenderNotFound: in case the public information about the sending device could not be found or is
                incomplete.
            SenderDistrusted: in case the identity key corresponding to the sending device is explicitly
                distrusted.
            NoSession: in case there is no session with the sending device, and the information required to
                build a new session is not included either.
            PublicDataInconsistency: in case there is an inconsistency in the public data of the sending
                device, which can affect the trust status.
            MessageSendingFailed: if an attempt to send an empty OMEMO message failed. Forwarded from
                :meth:`_send_message`.
            DecryptionFailed: in case of backend-specific failures during decryption. Forwarded from the
                respective backend implementation.

        Warning:
            Do **NOT** implement any automatic reaction to decryption failures, those automatic reactions are
            transparently handled by the library! *Do* notify the user about decryption failures though, if
            applicable.

        Note:
            If the trust level of the sender evaluates to undecided, the message is decrypted.

        Note:
            May send empty OMEMO messages to "complete" key exchanges or prevent staleness.
        """

        logging.getLogger(SessionManager.LOG_TAG).debug(f"Decrypting message: {message}")

        storage = self.__storage

        # Find the backend to handle this message
        backend = next(filter(lambda backend: backend.namespace == message.namespace, self.__backends), None)
        if backend is None:
            raise UnknownNamespace(
                f"Backend corresponding to namespace {message.namespace} is not currently loaded."
            )

        # Check if there is key material for us
        try:
            encrypted_key_material, key_exchange = next(filter(
                lambda k: k[0].bare_jid == self.__own_bare_jid and k[0].device_id == self.__own_device_id,
                message.keys
            ))
        except StopIteration:
            # pylint: disable=raise-missing-from
            raise MessageNotForUs("The message to decrypt does not contain key material for us.")

        logging.getLogger(SessionManager.LOG_TAG).debug(
            f"Encrypted key material: {encrypted_key_material}, key exchange: {key_exchange}"
        )

        # Check whether the sending device is known
        devices = await self.get_device_information(message.bare_jid)
        device = next(filter(lambda device: device.device_id == message.device_id, devices), None)
        if device is None:
            logging.getLogger(SessionManager.LOG_TAG).warning(
                "Sender device is not known, triggering a device list update."
            )

            # If it isn't, trigger a refresh of the device list. This shouldn't be necessary due to PEP
            # subscription mechanisms, however there might be race conditions and it doesn't hurt to refresh
            # here.
            await self.refresh_device_list(message.namespace, message.bare_jid)

            # Once the device list has been refreshed, look for the device again
            devices = await self.get_device_information(message.bare_jid)

            # This time, if the device is still not found, abort. This is not strictly required - the message
            # could be decrypted anyway. However, it would mean the sending device is not complying with the
            # specification, which is shady, thus it's not wrong to abort here either.
            device = next((device for device in devices if device.device_id == message.device_id), None)
            if device is None:
                raise SenderNotFound(
                    "Couldn't find public information about the device which sent this message. I.e. the"
                    " device either does not appear in the device list of the sending XMPP account, or the"
                    " bundle of the sending device could not be downloaded."
                )

            logging.getLogger(SessionManager.LOG_TAG).warning(
                "Sender device found by the manual device list update. Make sure your PEP subscription is set"
                " up correctly."
            )

        # Check the trust level of the sending device. Abort in case of explicit distrust.
        if self._evaluate_custom_trust_level(device.trust_level_name) is TrustLevel.DISTRUSTED:
            raise SenderDistrusted(
                "The identity key corresponding to the sending device is explicitly distrusted."
            )

        async def decrypt_key_material(
            backend: Backend,
            device: DeviceInformation,
            encrypted_key_material: EncryptedKeyMaterial
        ) -> Tuple[Session, PlainKeyMaterial]:
            """
            Load an existing session and use it to decrypt some key material.

            Args:
                backend: The backend to load the session from.
                device: The device whose session to load.
                encrypted_key_material: The key material to decrypt.

            Returns:
                The session and the decrypted key material.

            Raises:
                NoSession: in case there is no session with the device in storage.
                DecryptionFailed: in case of backend-specific failures during decryption. Forwarded from
                    :meth:`~omemo.backend.Backend.decrypt_key_material`.
            """

            # If there is no key exchange, a session has to exist and should be loadable
            session = await backend.load_session(device.bare_jid, device.device_id)
            if session is None:
                raise NoSession(
                    "There is no session with the sending device, and key exchange information required to"
                    " build a new session is not included in the message."
                )

            plain_key_material = await backend.decrypt_key_material(session, encrypted_key_material)

            return session, plain_key_material

        async def handle_key_exchange(
            backend: Backend,
            device: DeviceInformation,
            key_exchange: KeyExchange,
            encrypted_key_material: EncryptedKeyMaterial
        ) -> Tuple[Session, PlainKeyMaterial]:
            """
            Handle a key exchange by building a new session if necessary, and decrypt some key material in the
            process.

            Args:
                backend: The backend to handle the key exchange with.
                device: The device which sent the key exchange information.
                key_exchange: The key exchange information.
                encrypted_key_material: The key material to decrypt.

            Returns:
                A session that was built using the key exchange information, either now or in the past,
                and the decrypted key material.

            Raises:
                PublicDataInconsistency: if the identity key that's part of the key exchange information
                    doesn't match the identity key in the bundle of the device.
                KeyExchangeFailed: in case a new session needed to be built, and there was an error during the
                    key exchange that's part of the session building. Forwarded from
                    :meth:`~omemo.backend.Backend.build_session_passive`.
                DecryptionFailed: in case of backend-specific failures during decryption. Forwarded from the
                    respective backend implementation.
            """

            # Check whether the identity key matches the one we know
            if key_exchange.identity_key != device.identity_key:
                raise PublicDataInconsistency(
                    "There is no session with the sending device. Key exchange information to build a new"
                    " session is included in the message, however the identity key of the key exchange"
                    " information does not match the identity key known for the sending device."
                )

            # Check whether there is a session with the sending device already
            session = await backend.load_session(device.bare_jid, device.device_id)
            if session is not None:
                logging.getLogger(SessionManager.LOG_TAG).debug("Key exchange present, but session exists.")
                # If the key exchange would build a new session, treat this session as non-existent
                if session.initiation is Initiation.PASSIVE and session.key_exchange == key_exchange:
                    logging.getLogger(SessionManager.LOG_TAG).debug("Key exchange builds existing session.")
                else:
                    logging.getLogger(SessionManager.LOG_TAG).warning(
                        "Key exchange replaces existing session."
                    )
                    session = None

            # If a new session needs to be built, do so.
            session, plain_key_material = await backend.build_session_passive(
                device.bare_jid,
                device.device_id,
                key_exchange,
                encrypted_key_material
            ) if session is None else (session, await backend.decrypt_key_material(
                session,
                encrypted_key_material
            ))

            # If an existing session is used, and the session was built through active session initiation, it
            # should now be flagged as confirmed.
            return session, plain_key_material

        # Inline if for type safety and pylint satisfaction.
        session, plain_key_material = (
            await decrypt_key_material(backend, device, encrypted_key_material)
            if key_exchange is None else
            await handle_key_exchange(backend, device, key_exchange, encrypted_key_material)
        )

        logging.getLogger(SessionManager.LOG_TAG).debug(f"Plain key material: {plain_key_material}")

        # Decrypt the message
        plaintext = None if message.content.empty else await backend.decrypt_plaintext(
            message.content,
            plain_key_material
        )

        logging.getLogger(SessionManager.LOG_TAG).debug(f"Message decrypted: {plaintext}")

        # Persist the session following successful decryption
        await backend.store_session(session)

        # If this message was a key exchange, take care of pre key hiding/deletion.
        if key_exchange is not None:
            bundle_changed: bool
            if self.__synchronizing:
                # If the library is currently in history synchronization mode, hide the pre key but defer the
                # deletion.
                logging.getLogger(SessionManager.LOG_TAG).debug("Hiding pre key.")
                bundle_changed = await backend.hide_pre_key(session)
            else:
                # Otherwise, delete the pre key right away
                logging.getLogger(SessionManager.LOG_TAG).debug("Deleting pre key.")
                bundle_changed = await backend.delete_pre_key(session)

            if bundle_changed:
                num_visible_pre_keys = await backend.get_num_visible_pre_keys()
                if num_visible_pre_keys <= self.__pre_key_refill_threshold:
                    logging.getLogger(SessionManager.LOG_TAG).debug("Refilling pre keys.")
                    await backend.generate_pre_keys(100 - num_visible_pre_keys)
                    bundle = await backend.get_bundle(self.__own_bare_jid, self.__own_device_id)

                await self._upload_bundle(bundle)

        # Send an empty message if necessary to avoid staleness and to "complete" the handshake in case this
        # was a key exchange
        if (
            key_exchange is not None
            or (session.receiving_chain_length or 0) > self.__class__.STALENESS_MAGIC_NUMBER
        ):
            logging.getLogger(SessionManager.LOG_TAG).debug(
                "Sending/queueing empty message for session completion or staleness prevention."
            )
            if self.__synchronizing:
                # Add this bare JID to the queue
                queued_jids = set((await storage.load_list(f"/queue/{session.namespace}", str)).maybe([]))

                queued_jids.add(session.bare_jid)
                await storage.store(f"/queue/{session.namespace}", list(queued_jids))

                # Add this device id to the queue
                queued_device_ids = set((await storage.load_list(
                    f"/queue/{session.namespace}/{session.bare_jid}",
                    int
                )).maybe([]))

                queued_device_ids.add(session.device_id)
                await storage.store(f"/queue/{session.namespace}/{session.bare_jid}", list(queued_device_ids))
            else:
                # If not in history synchronization mode, send the empty message right away
                await self.__send_empty_message(backend, session)

        logging.getLogger(SessionManager.LOG_TAG).debug("Post-decryption tasks completed.")

        # Return the plaintext and information about the sending device
        return (plaintext, device)
