from abc import ABCMeta, abstractmethod
import base64
import itertools
import secrets
from typing import Any, cast, Dict, Generic, List, Optional, Set, Tuple, Type, TypeVar

from .backend import Backend
from .bundle  import Bundle
from .identity_key_pair import IdentityKeyPair
from .message import Message
from .session import Session
from .storage import Nothing, Storage
from .types   import DeviceInformation, OMEMOException, TrustLevel

# TODO: Add missing API promised in functionality.md
# TODO: Add more machine-readable data to exceptions?

class SessionManagerException(OMEMOException):
    """
    Parent type for all exceptions specific to :class:`SessionManager`.
    """



class TrustDecisionFailed(SessionManagerException):
    """
    Raised by :meth:`_make_trust_decision` if the trust decisions that were queried somehow failed. Indirectly
    raised by the encryption flow.
    """

class StillUndecided(SessionManagerException):
    """
    Raised by :meth:`encrypt` in case there are still undecided devices after a trust decision was queried via
    :meth:`_make_trust_decision`.
    """

class NoEligibleDevices(SessionManagerException):
    """
    Raised by :meth:`encrypt` in case none of the devices of one or more recipient are eligible for
    encryption, for example due to distrust or bundle downloading failures.
    """

    def __init__(self, msg: str, bare_jids: Set[str]) -> None:
        """
        Args:
            bare_jids: The JIDs whose devices were not eligible. Accessible as an attribute of the returned
                instance.
        """

        super().__init__(msg)

        self.bare_jids = bare_jids



class MessageNotForUs(SessionManagerException):
    """
    Raised by :meth:`decrypt` in case the message to decrypt does not seem to be encrypting for this device.
    """

class SenderNotFound(SessionManagerException):
    """
    Raised by :meth:`decrypt` in case the usual public information of the sending device could not be
    downloaded.
    """

class SenderDistrusted(SessionManagerException):
    """
    Raised by :meth:`decrypt` in case the sending device is explicitly distrusted.
    """

class NoSession(SessionManagerException):
    """
    Raised by :meth:`decrypt` in case there is no session with the sending device, and a new session can't be
    built either.
    """

class PublicDataInconsistency(SessionManagerException):
    """
    Raised by :meth:`decrypt` in case inconsistencies were found in the public data of the sending device.
    """



class UnknownTrustLevel(SessionManagerException):
    """
    Raised by :meth:`_evaluate_custom_trust_level` if the custom trust level name to evaluate is unknown.
    Indirectly raised by the encryption and decryption flows.
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
    Raised by :meth:`_upload_bundle`, and indirectly by various methods of :class:`SessionManager`.
    """

class BundleDownloadFailed(XMPPInteractionFailed):
    """
    Raised by :meth:`_download_bundle`, and indirectly by various methods of :class:`SessionManager`.
    """

class BundleDeletionFailed(XMPPInteractionFailed):
    """
    Raised by :meth:`_delete_bundle`, and indirectly by :meth:`purge_backend`.
    """

class DeviceListUploadFailed(XMPPInteractionFailed):
    """
    Raised by :meth:`_upload_device_list`, and indirectly by various methods of :class:`SessionManager`.
    """

class DeviceListDownloadFailed(XMPPInteractionFailed):
    """
    Raised by :meth:`_download_device_list`, and indirectly by various methods of :class:`SessionManager`.
    """

class MessageSendingFailed(XMPPInteractionFailed):
    """
    Raised by :meth:`_send_message`, and indirectly by various methods of :class:`SessionManager`.
    """



# TODO: Take care of logging
SM = TypeVar("SM", bound="SessionManager")
Plaintext = TypeVar("Plaintext")
class SessionManager(Generic[Plaintext], metaclass=ABCMeta):
    """
    The core of python-omemo. Manages your own key material and bundle, device lists, sessions with other
    users and much more, all while being flexibly usable with different backends and transparenlty maintaining
    a level of compatibility between the backends that allows you to maintain a single identity throughout all
    of them. Easy APIs are provided to handle common use-cases of OMEMO-enabled XMPP clients, with one of the
    primary goals being strict type safety. The plaintext generic can be used to choose a convenient type for
    the plaintext passed/received from the encrypt/decrypt methods. Which type to choose depends on the loaded
    backends. For example, if only one backend is loaded which uses
    `SCE <https://xmpp.org/extensions/xep-0420.html>`__, a good choice for the plaintext type might be some
    XML/stanza structure. For other backends, Pythons `str` type might be a better choice. If multiple
    backends are loaded, a common ground must be chosen.

    Note:
        Most methods can raise :class:`~omemo.storage.StorageException` in addition to those exceptions
        listed explicitly.
    
    Note:
        All parameters are treated as immutable unless explicitly noted otherwise.

    Note:
        All usages of "identity key" in the public API refer to the public part of the identity key pair in
        Ed25519 format. Otherwise, "identity key pair" is explicitly used to refer to the full key pair.
    """

    HEARTBEAT_MESSAGE_TRIGGER = 53

    def __init__(self) -> None:
        # Just the type definitions here
        self.__backends: List[Backend[Plaintext]]
        self.__storage: Storage
        self.__own_bare_jid: str
        self.__own_device_id: int
        self.__undecided_trust_level_name: str
        self.__max_num_per_session_skipped_keys: int
        self.__max_num_per_message_skipped_keys: Optional[int]
        self.__pre_key_refill_threshold: int
        self.__identity_key_pair: IdentityKeyPair
        self.__synchronizing: bool

    @classmethod
    async def create(
        cls: Type[SM],
        backends: List[Backend[Plaintext]],
        storage: Storage,
        own_bare_jid: str,
        initial_own_label: Optional[str],
        undecided_trust_level_name: str,
        max_num_per_session_skipped_keys: int = 1000,
        max_num_per_message_skipped_keys: Optional[int] = None,
        signed_pre_key_rotation_period: int = 7 * 24 * 60 * 60,
        pre_key_refill_threshold: int = 99
    ) -> SM:
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
                this custom trust level to ``TrustLevel.Undecided``.
            max_num_per_session_skipped_keys: The maximum number of skipped message keys to keep around per
                session. Once the maximum is reached, old message keys are deleted to make space for newer
                ones.
            max_num_per_message_skipped_keys: The maximum number of skipped message keys to accept in a single
                message. When set to ``None`` (the default), this parameter defaults to the per-session
                maximum (i.e. the value of the ``max_num_per_session_skipped_keys`` parameter). This parameter
                may only be 0 if the per-session maximum is 0, otherwise it must be a number between 1 and the
                per-session maximum.
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

        if len({ backend.namespace for backend in backends }) != len(backends):
            raise ValueError("Multiple backends that handle the same namespace were passed.")

        self = cls()
        self.__backends = list(backends) # Copy to make sure the original is not modified
        self.__storage = storage
        self.__own_bare_jid = own_bare_jid
        self.__undecided_trust_level_name = undecided_trust_level_name
        self.__max_num_per_session_skipped_keys = max_num_per_session_skipped_keys
        self.__max_num_per_message_skipped_keys = max_num_per_message_skipped_keys
        self.__pre_key_refill_threshold = pre_key_refill_threshold
        self.__identity_key_pair = await IdentityKeyPair.get(storage)
        self.__synchronizing = True

        try:
            self.__own_device_id = (await self.__storage.load_primitive("/own_device_id", int)).from_just()
        except Nothing:
            # First run.

            # Fetch the device lists for this bare JID for all loaded backends.
            device_ids = cast(Set[int], {}).union(*{
                set((await self._download_device_list(backend.namespace, self.__own_bare_jid)).keys())
                for backend
                in self.__backends
            })

            # Generate a new device id for this device, making sure that it doesn't clash with any of the
            # existing device ids.
            DEVICE_ID_MIN = 1
            DEVICE_ID_MAX = 2 ** 31 - 1

            self.__own_device_id = next(filter(
                lambda device_id: device_id not in device_ids,
                (secrets.randbelow(DEVICE_ID_MAX - DEVICE_ID_MIN) + DEVICE_ID_MIN for _ in itertools.count())
            ))

            # Store the device information for this device
            await storage.store("/devices/{}/{}/namespaces".format(
                self.__own_bare_jid,
                self.__own_device_id
            ), [ backend.namespace for backend in self.__backends ])

            await storage.store("/devices/{}/{}/active".format(
                self.__own_bare_jid,
                self.__own_device_id
            ), { backend.namespace: True for backend in self.__backends })

            await storage.store("/devices/{}/{}/label".format(
                self.__own_bare_jid,
                self.__own_device_id
            ), initial_own_label)

            await storage.store_bytes("/devices/{}/{}/identity_key".format(
                self.__own_bare_jid,
                self.__own_device_id
            ), self.__identity_key_pair.identity_key)

            # Publish the bundles for all backends
            for backend in self.__backends:
                await self._upload_bundle(await backend.bundle(
                    self.__own_bare_jid,
                    self.__own_device_id,
                    self.__identity_key_pair.identity_key
                ))

            # Trigger a refresh of the own device lists for all backends, this will result in this device
            # being added to the lists and the lists republished.
            for backend in self.__backends:
                await self.refresh_device_list(backend.namespace, self.__own_bare_jid)
        
        # If there a mismatch between loaded and active namespaces, look for changes in the loaded backends.
        device, _ = await self.get_own_device_information()
        loaded_namespaces = { backend.namespace for backend in self.__backends }
        active_namespaces = device.namespaces
        if loaded_namespaces != active_namespaces:
            # Store the updated list of loaded namespaces
            await storage.store("/devices/{}/{}/namespaces".format(
                self.__own_bare_jid,
                self.__own_device_id
            ), loaded_namespaces)

            # Set the device active for all loaded namespaces
            await storage.store("/devices/{}/{}/active".format(
                self.__own_bare_jid,
                self.__own_device_id
            ), { namespace: True for namespace in loaded_namespaces })

            # Take care of the initialization of newly added backends
            for backend in self.__backends:
                if backend.namespace not in active_namespaces:
                    # Publish the bundle of the new backend
                    await self._upload_bundle(await backend.bundle(
                        self.__own_bare_jid,
                        self.__own_device_id,
                        self.__identity_key_pair.identity_key
                    ))

                    # Trigger a refresh of the own device list of the new backend, this will result in this
                    # device being added to the lists and the lists republished.
                    await self.refresh_device_list(backend.namespace, self.__own_bare_jid)
            
            # Perform cleanup of removed backends
            for namespace in active_namespaces - loaded_namespaces:
                await self.purge_backend(namespace)

        # Perform age check and rotation of the signed pre key
        for backend in self.__backends:
            if await backend.signed_pre_key_age() > signed_pre_key_rotation_period:
                await backend.rotate_signed_pre_key(self.__identity_key_pair)
                await self._upload_bundle(await backend.bundle(
                    self.__own_bare_jid,
                    self.__own_device_id,
                    self.__identity_key_pair.identity_key
                ))

        return self

    async def purge_backend(self, namespace: str) -> None:
        """
        Purge a backend, removing both the online data (bundle, device list entry) and the offline data that
        belongs to this backend. Note that the backend-specific offline data can only be purged if the
        respective backend is currently loaded. This backend-specific removal can be triggered manually at any
        time by calling the :meth:`purge` method of the respecfive backend. If the backend to purge is
        currently loaded, the method will unload it.

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
        device.namespaces.remove(namespace)
        device.active.pop(namespace, None)

        await self.__storage.store("/devices/{}/{}/namespaces".format(
            self.__own_bare_jid,
            self.__own_device_id
        ), device.namespaces)

        await self.__storage.store("/devices/{}/{}/active".format(
            self.__own_bare_jid,
            self.__own_device_id
        ), device.active)

        # If the backend is currently loaded, remove it from the list of loaded backends
        purged_backend = next(filter(lambda backend: backend.namespace == namespace, self.__backends), None)
        self.__backends = list(filter(lambda backend: backend.namespace != namespace, self.__backends))

        # Remaining backend-specific offline data removal
        if purged_backend is not None:
            await purged_backend.purge()

        # Second half of online data removal: delete the bundle of this device. This step has low priority,
        # thus done last.
        await self._delete_bundle(namespace, self.__own_device_id)

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
            BundleUploadFailed: if the upload failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.

        Note:
            This method must be able to handle at least the namespaces of all loaded backends.
        """

        raise NotImplementedError("Create a subclass of SessionManager and implement `_upload_bundle`.")

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
            UnkownNamespace: if the namespace is unknown.
            BundleDownloadFailed: if the download failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.

        Note:
            This method must be able to handle at least the namespaces of all loaded backends.
        """

        raise NotImplementedError("Create a subclass of SessionManager and implement `_download_bundle`.")

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
            UnkownNamespace: if the namespace is unknown.
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

        raise NotImplementedError("Create a subclass of SessionManager and implement `_delete_bundle`.")

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
            UnkownNamespace: if the namespace is unknown.
            DeviceListUploadFailed: if the upload failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.

        Note:
            This method must be able to handle at least the namespaces of all loaded backends.
        """

        raise NotImplementedError("Create a subclass of SessionManager and implement `_upload_device_list`.")
        

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
            UnkownNamespace: if the namespace is unknown.
            DeviceListDownloadFailed: if the download failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.

        Note:
            This method must be able to handle at least the namespaces of all loaded backends.
        """

        raise NotImplementedError(
            "Create a subclass of SessionManager and implement `_download_device_list`."
        )

    @staticmethod
    @abstractmethod
    def _evaluate_custom_trust_level(trust_level_name: str) -> TrustLevel:
        """
        Evaluate a custom trust level to one of the three core trust levels:

        * `Trusted`: This device is trusted, encryption/decryption of messages to/from it is allowed.
        * `Distrusted`: This device is explicitly *not* trusted, do not encrypt/decrypt messages to/from it.
        * `Undecided`: A trust decision is yet to be made. It is not clear whether it is okay to
            encrypt messages to it, however decrypting messages from it is allowed.

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

        raise NotImplementedError(
            "Create a subclass of SessionManager and implement `_evaluate_custom_trust_level`."
        )

    @abstractmethod
    async def _make_trust_decision(self, undecided: Set[DeviceInformation]) -> Any:
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

        raise NotImplementedError("Create a subclass of SessionManager and implement `_make_trust_decision`.")

    @staticmethod
    @abstractmethod
    async def _send_message(message: Message) -> Any:
        """
        Send an OMEMO-encrypted message. This is required for various automated behaviours to improve the
        overall stability of the protocol, for example:

        * Automatic handshake completion, by responding to incoming key exchanges.
        * Automatic heartbeat messages to forward the ratchet if many messages were received without a
            (manual) response, to assure forward secrecy (aka staleness prevention). The number of messages
            required to trigger this behaviour is hardcoded in ``SessionManager.HEARTBEAT_MESSAGE_TRIGGER``.
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
            MessageSendingFailed: if for any reason the message could not be sent. Feel free to raise a
                subclass instead.
        """

        raise NotImplementedError("Create a subclass of SessionManager and implement `_send_message`.")

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
            UnkownNamespace: if the backend to handle the message is not currently loaded.
            DeviceListUploadFailed: if a device list upload failed. An upload can happen if the device list
                update is for the own bare JID and does not include the own device. Forwarded from
                :meth:`_upload_device_list`.
        """

        storage = self.__storage

        # This isn't strictly necessary, but good for consistency
        if namespace not in { backend.namespace for backend in self.__backends }:
            raise UnknownNamespace("The backend hanlding the namespace {} is not currently loaded.".format(
                namespace
            ))

        # Copy to make sure the original is not modified
        device_list = dict(device_list)

        new_device_list = set(device_list.keys())
        old_device_list = set((await storage.load_list("/devices/{}/list".format(bare_jid), int)).maybe([]))

        new_devices = new_device_list - old_device_list

        # If the device list is for this JID and a loaded backend, make sure this device is included
        if (bare_jid == self.__own_bare_jid and
            namespace in { backend.namespace for backend in self.__backends } and
            self.__own_device_id not in new_device_list):
            # Add this device to the device list and publish it
            device_list[self.__own_device_id] = (await storage.load_optional("/devices/{}/{}/label".format(
                self.__own_bare_jid,
                self.__own_device_id
            ), str)).from_just()
            await self._upload_device_list(namespace, device_list)

        # Add new device information entries for new devices
        for device_id in new_devices:
            await storage.store("/devices/{}/{}/namespaces".format(bare_jid, device_id), [ namespace ])
            await storage.store("/devices/{}/{}/active".format(bare_jid, device_id), { namespace: True })
            await storage.store("/devices/{}/{}/label".format(bare_jid, device_id), device_list[device_id])

        # Update namespaces, label and status for previously known devices
        for device_id in old_device_list:
            namespaces = set((await storage.load_list("/devices/{}/{}/namespaces".format(
                bare_jid,
                device_id
            ), str)).from_just())

            active = (await storage.load_dict("/devices/{}/{}/active".format(
                bare_jid,
                device_id
            ), str, bool)).from_just()

            if device_id in device_list:
                # Add the namespace if required
                if namespace not in namespaces:
                    namespaces.add(namespace)
                    await storage.store("/devices/{}/{}/namespaces".format(bare_jid, device_id), namespaces)
                
                # Update the status if required
                if namespace not in active or active[namespace] == False:
                    active[namespace] = True
                    await storage.store("/devices/{}/{}/active".format(bare_jid, device_id), active)

                # Update the label if required. Even though loading the value first isn't strictly required,
                # it is done under the assumption that loading values is cheaper than writing.
                label = (await storage.load_optional("/devices/{}/{}/label".format(
                    bare_jid,
                    device_id
                ), str)).from_just()

                if device_list[device_id] != label:
                    await storage.store("/devices/{}/{}/label".format(
                        bare_jid,
                        device_id
                    ), device_list[device_id])
            else:
                # Update the status if required
                if namespace in namespaces:
                    if active[namespace] == True:
                        active[namespace] = False
                        await storage.store("/devices/{}/{}/active".format(bare_jid, device_id), active)

        # If there are unknown devices in the new device list, update the list of known devices. Do this as
        # the last step to ensure data consistency.
        if len(new_devices) > 0:
            await storage.store("/devices/{}/list".format(bare_jid), list(new_device_list | old_device_list))

    async def refresh_device_list(self, namespace: str, bare_jid: str) -> None:
        """
        Manually trigger the refresh of a device list.

        Args:
            namespace: The XML namespace to execute this operation under.
            bare_jid: The bare JID of the XMPP account.

        Raises:
            UnkownNamespace: if the namespace is unknown.
            DeviceListDownloadFailed: if the device list download failed. Forwarded from
                :meth:`_download_device_list`.
            DeviceListUploadFailed: if a device list upload failed. An upload can happen if the device list
                update is for the own bare JID and does not include the own device. Forwarded from
                :meth:`update_device_list`.
        """

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

        await self.__storage.store("/trust/{}/{}".format(
            bare_jid,
            base64.urlsafe_b64encode(identity_key).decode("ASCII")
        ), trust_level_name)

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
            is a :class:`StorageException`, there is a high change that the session was left in an
            inconsistent state. Other reasons imply that the session replacement failed before having any
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

        # Remove namespaces that correspond to backends which are not currently loaded or backends which have
        # no session for this device.
        device = device._replace(namespaces=(device.namespaces & {
            backend.namespace
            for backend
            in self.__backends
            if await backend.load_session(device) is not None
        }))

        unsuccessful: Dict[str, OMEMOException] = {}

        # Perform the replacement
        for backend in self.__backends:
            if backend.namespace in device.namespaces:
                try:
                    session, key_exchange = await backend.build_session_active(
                        device,
                        await self._download_bundle(
                            backend.namespace,
                            device.bare_jid,
                            device.device_id
                        )
                    )
                    session.set_key_exchange(key_exchange)

                    # Send the notification message
                    await self.__send_empty_message(backend, session)
                except OMEMOException as e:
                    unsuccessful[backend.namespace] = e

        return unsuccessful

    async def purge_bare_jid(self, bare_jid: str) -> None:
        """
        Delete all data corresponding to an XMPP account. This includes the device list, trust information and
        all sessions across all loaded backends. The backend-specific data can be removed at any time by
        calling the :meth:`purge_bare_jid` method of the respective backend.

        Args:
            bare_jid: Delete all data corresponding to this bare JID.
        """

        storage = self.__storage

        # Get the set of devices to delete
        device_list = set((await storage.load_list("/devices/{}/list".format(bare_jid), int)).maybe([]))
        
        # Collect identity keys used by this account
        identity_keys: Set[bytes] = {}
        for device_id in device_list:
            try:
                identity_keys.add((await storage.load_bytes("/devices/{}/{}/identity_key".format(
                    bare_jid,
                    device_id
                ))).from_just())
            except Nothing:
                pass

        # Delete information about the individual devices
        for device_id in device_list:
            await storage.delete("/devices/{}/{}/namespaces".format(bare_jid, device_id))
            await storage.delete("/devices/{}/{}/active".format(bare_jid, device_id))
            await storage.delete("/devices/{}/{}/label".format(bare_jid, device_id))
            await storage.delete("/devices/{}/{}/identity_key".format(bare_jid, device_id))

        # Delete the device list
        await storage.delete("/devices/{}/list".format(bare_jid))

        # Delete information about the identity keys
        for identity_key in identity_keys:
            await storage.delete("/trust/{}/{}".format(
                bare_jid,
                base64.urlsafe_b64encode(identity_key).decode("ASCII")
            ))

        # Remove backend-specific data
        for backend in self.__backends:
            await backend.purge_bare_jid(bare_jid)

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

        # Store the new label
        await self.__storage.store("/devices/{}/{}/label".format(
            self.__own_bare_jid,
            self.__own_device_id
        ), own_label)

        # For each loaded backend, upload an updated device list including the new label
        for backend in self.__backends:
            # Note: it is not required to download the device list here, since it should be cached locally.
            # However, one PEP node fetch per backend isn't super expensive and it's nice to avoid the code to
            # load the cached device list.
            device_list = await self._download_device_list(backend.namespace, self.__own_bare_jid)
            device_list[self.__own_device_id] = own_label
            await self._upload_device_list(backend.namespace, device_list)

    async def get_device_information(self, bare_jid: str) -> Set[DeviceInformation]:
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
        
        Raises:
            BundleDownloadFailed: if a bundle download failed. Forwarded from :meth:`_download_bundle`.
        """

        # Do not expose the bundle cache publicly.
        return (await self.__get_device_information(bare_jid))[0]

    async def __get_device_information(self, bare_jid: str) -> Tuple[Set[DeviceInformation], Set[Bundle]]:
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
        
        Raises:
            BundleDownloadFailed: if a bundle download failed. Forwarded from :meth:`_download_bundle`.
        """

        storage = self.__storage

        device_list = set((await storage.load_list("/devices/{}/list".format(bare_jid), int)).maybe([]))

        devices: Set[DeviceInformation] = {}
        bundle_cache: Set[Bundle] = {}

        for device_id in device_list:
            # Load the identity key first, since this is the most likely operation to fail (due to bundle
            # downloading errors)
            identity_key: bytes
            try:
                identity_key = (await storage.load_bytes("/devices/{}/{}/identity_key".format(
                    bare_jid,
                    device_id
                ))).from_just()
            except Nothing:
                # The identity key assigned to this device is not known yet. Fetch the bundle to find that
                # information. Return the downloaded bundle to avoid double-fetching it if the same bundle is
                # required for session initiation afterwards.
                for namespace in namespaces:
                    try:
                        bundle = await self._download_bundle(namespace, bare_jid, device_id)
                    except BundleDownloadFailed:
                        pass
                    else:
                        bundle_cache.add(bundle)

                        identity_key = bundle.identity_key

                        await storage.store_bytes("/devices/{}/{}/identity_key".format(
                            bare_jid,
                            device_id
                        ), identity_key)
                        break
                else:
                    # Skip this device in case none of the bundles could be downloaded
                    continue

            namespaces = set((await storage.load_list("/devices/{}/{}/namespaces".format(
                bare_jid,
                device_id
            ), str)).from_just())

            active = (await storage.load_dict("/devices/{}/{}/active".format(
                bare_jid,
                device_id
            ), str, bool)).from_just()

            label = (await storage.load_optional("/devices/{}/{}/label".format(
                bare_jid,
                device_id
            ), str)).from_just()

            trust_level_name = (await storage.load_primitive("/trust/{}/{}".format(
                bare_jid,
                base64.urlsafe_b64encode(identity_key).decode("ASCII")
            ), str)).maybe(self.__undecided_trust_level_name)

            devices.add(DeviceInformation(
                namespaces=namespaces,
                active=active,
                bare_jid=bare_jid,
                device_id=device_id,
                identity_key=identity_key,
                trust_level_name=trust_level_name,
                label=label
            ))

        return devices, bundle_cache

    async def get_own_device_information(self) -> Tuple[DeviceInformation, Set[DeviceInformation]]:
        """
        Variation of :meth:`get_device_information` for convenience.

        Returns:
            A tuple, where the first entry is information about this device and the second entry contains
            information about the other devices of the own bare JID.

        Raises:
            BundleDownloadFailed: if a bundle download failed. Forwarded from :meth:`_download_bundle`.
        """

        all_own_devices = await self.get_device_information(self.__own_bare_jid)
        other_own_devices = set(filter(lambda dev: dev.device_id != self.__own_device_id, all_own_devices))

        return next(all_own_devices - other_own_devices), other_own_devices

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

        return [ ik_hex_string[i : i + group_size] for i in range(0, len(ik_hex_string), group_size) ]

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
        
        Note:
            While in history synchronization mode, the library can process live events too.
        """

        self.__synchronizing = True

    async def after_history_sync(self) -> None:
        """
        If the library is in "history synchronization mode" started by :meth:`create` or
        :meth:`before_history_sync`, calling this makes it return to normal working behaviour. Make sure to
        call this as soon as history synchronization (if any) is done.
        """

        self.__synchronizing = False
        for backend in self.__backends:
            await backend.delete_hidden_pre_keys()

    ######################
    # en- and decryption #
    ######################

    async def __send_empty_message(self, backend: Backend[Plaintext], session: Session) -> None:
        """
        Internal helper to send an empty message for ratchet forwarding.

        Args:
            backend: The backend to encrypt the message with.
            session: The session to encrypt the message with.
        
        Raises:
            MessageSendingFailed: if the message could not be sent. Forwarded from :meth:`_send_message`.
        """

        content, key_material = await backend.encrypt_empty(session)
        await self._send_message(backend.build_message(content, { (key_material, session.key_exchange) }))
        await session.persist()

    async def encrypt(
        self,
        bare_jids: Set[str],
        plaintext: Plaintext,
        backend_priority_order: Optional[List[str]] = None
    ) -> Set[Message]:
        """
        Encrypt some plaintext for a set of recipients.

        Args:
            bare_jids: The bare JIDs of the intended recipients.
            plaintext: The plaintext to encrypt for the recipients. Details depend on the backend(s).
            backend_priority_order: If a recipient device supports multiple versions of OMEMO, this parameter
                decides which version to prioritize. If ``None`` is supplied, the order of backends as passed
                to :meth:`create` is assumed as the order of priority. If a list of namespaces is supplied,
                the first namespace supported by the recipient is chosen. Lower index means higher priority.

        Returns:
            One message per backend, encrypted for each device of each recipient and for other devices of this
            account.

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
                building. Forwarded from :meth:`build_session_active`.

        Note:
            The own JID is implicitly added to the set of recipients, there is no need to list it manually.

        Note:
            Refer to the documentation of the :class:`~omemo.session_manager.SessionManager` class for
            information about the ``Plaintext`` type.
        """

        # Prepare the backend priority order list
        effective_backend_priority_order: List[str]
        available_namespaces = [ backend.namespace for backend in self.__backends ]

        if backend_priority_order is None:
            effective_backend_priority_order = available_namespaces
        else:
            unavailable_namespaces = set(backend_priority_order) - set(available_namespaces)
            if len(unavailable_namespaces) > 0:
                raise UnknownNamespace(
                    "One or more unavailable namespaces were passed in the backend priority order list: {}"
                        .format(unavailable_namespaces)
                )

            effective_backend_priority_order = backend_priority_order

        # Add the own bare JID to the list of recipients.
        # Copy to make sure the original is not modified.
        bare_jids = set(bare_jids) | { self.__own_bare_jid }
        
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
            namespaces_active = set(filter(lambda namespace: device.active[namespace], device.namespaces))

            # Remove devices which are only available with backends that are not currently loaded and in
            # the priority list
            if len(namespaces_active & set(effective_backend_priority_order)) == 0:
                return False

            return True

        # Using get_device_information here means that some devices may be excluded, if their corresponding
        # identity key is not known and attempts to download the respecitve bundles fail. Those devices
        # missing is fine, since get_device_information is the public API for device information anyway, so
        # the publicly available device list and the recipient devices used here are consistent.
        tmp = { await self.__get_device_information(bare_jid) for bare_jid in bare_jids }

        devices = cast(Set[DeviceInformation], {}).union(*(devices for devices, _ in tmp))
        devices = set(filter(is_valid_recipient_device, devices))

        bundle_cache = cast(Set[Bundle], {}).union(*(bundle_cache for _, bundle_cache in tmp))

        # Check for recipients without a single active device
        no_eligible_devices = set(filter(
            lambda bare_jid: all(device.bare_jid != bare_jid for device in devices),
            bare_jids
        ))

        if len(no_eligible_devices) > 0:
            raise NoEligibleDevices(
                "One or more of the intended recipients does not have a single active device for the loaded"
                " backends.",
                no_eligible_devices
            )

        # Apply the backend priority order to the remaining devices
        devices = { device._replace(namespaces={ next(sorted(
            filter(lambda namespace: device.active[namespace], device.namespaces),
            key=effective_backend_priority_order.index
        )) }) for device in devices }

        # Ask for trust decisions on the remaining devices (or rather, on the identity keys corresponding to
        # the remaining devices)
        def is_undecided(device: DeviceInformation) -> bool:
            """
            Helper for trust level evaluation and checks.

            Args:
                device: A device.
            
            Returns:
                Whether the trust status of this device is undecided, i.e. whether the custom trust level
                assigned to the identity key used by this device evaluates to `TrustLevel.Undecided`.
            """

            return self._evaluate_custom_trust_level(device.trust_level_name) is TrustLevel.Undecided

        def is_trusted(device: DeviceInformation) -> bool:
            """
            Helper for trust level evaluation and checks.

            Args:
                device: A device.
            
            Returns:
                Whether the trust status of this device is trusted, i.e. whether the custom trust level
                assigned to the identity key used by this device evaluates to `TrustLevel.Trusted`.
            """
        
            return self._evaluate_custom_trust_level(device.trust_level_name) is TrustLevel.Trusted
        
        undecided_devices = set(filter(is_undecided, devices))
        if len(undecided_devices) > 0:
            await self._make_trust_decision(undecided_devices)

            # Update to the new trust levels
            devices = { device._replace(trust_level_name=(await self.__storage.load_primitive(
                "/trust/{}/{}".format(
                    device.bare_jid,
                    base64.urlsafe_b64encode(device.identity_key).decode("ASCII")
                ),
                str
            )).maybe(self.__undecided_trust_level_name)) for device in devices }

        # Make sure the trust status of all previously undecided devices has been decided on
        undecided_devices = set(filter(is_undecided, devices))
        if len(undecided_devices) > 0:
            raise StillUndecided("The trust status of one or more devices has not been decided on: {}".format(
                undecided_devices
            ))

        # Keep only trusted devices
        devices = set(filter(is_trusted, devices))

        # Check for recipients without a single remaining device
        no_eligible_devices = set(filter(
            lambda bare_jid: all(device.bare_jid != bare_jid for device in devices),
            bare_jids
        ))

        if len(no_eligible_devices) > 0:
            raise NoEligibleDevices(
                "One or more of the intended recipients does not have a single active and trusted device for"
                " the loaded backends.",
                no_eligible_devices
            )

        async def load_or_create_session(backend: Backend[Plaintext], device: DeviceInformation) -> Session:
            """
            Helper to load a session for a device or create it if it doesn't exist.

            Args:
                backend: The backend to load/create this session with.
                device: The device to load/create this session with.
            
            Returns:
                The loaded or newly created session.
            
            Raises:
                BundleDownloadFailed: if a bundle download failed. Forwarded from :meth:`_download_bundle`.
                KeyExchangeFailed: in case there is an error during the key exchange required for session
                    building. Forwarded from :meth:`build_session_active`.
            """

            session = await backend.load_session(device)
            if session is None:
                try:
                    bundle = next(filter(lambda bundle: (
                        bundle.namespace == backend.namespace and
                        bundle.bare_jid == device.bare_jid and
                        bundle.device_id == device.device_id
                    ), bundle_cache))
                except StopIteration:
                    bundle = await self._download_bundle(backend.namespace, device.bare_jid, device.device_id)

                session, key_exchange = await backend.build_session_active(device, bundle)
                session.set_key_exchange(key_exchange)

            return session

        # Encrypt the plaintext once per backend
        # TODO: Think about how to handle failures
        # - Device-scope failures: bundle download and key exchange failures
        # - Library-scope failures: storage failures
        # - Anything else?
        # Also don't forget to adjust the excepions in the documentation after the decision is made.
        messages: Set[Message] = {}
        for backend in self.__backends:
            # Find the devices to encrypt for using this backend
            backend_devices = set(filter(lambda device: device.namespaces[0] == backend.namespace, devices))

            # Skip this backend if there isn't a single recipient device using it
            if len(backend_devices) == 0:
                continue

            # Prepare the sessions
            sessions = { await load_or_create_session(backend, device) for device in backend_devices }

            # Perform the encryption, which is mostly backend-specific.
            content, key_material = await backend.encrypt(sessions, plaintext)

            # Build pairs of key material and key exchange information
            keys = { (
                next(filter(
                    lambda km: km.bare_jid == session.bare_jid and km.device_id == session.device_id,
                    key_material
                )),
                session.key_exchange
            ) for session in sessions }

            # Build the message from content, key material and key exchange information
            messages.add(backend.build_message(content, keys))

            # Persist the sessions as the final step
            for session in sessions:
                await session.persist()

        return messages

    async def decrypt(self, message: Message) -> Tuple[Plaintext, DeviceInformation]:
        """
        Decrypt a message.

        Args:
            message: The message to decrypt.

        Returns:
            A tuple, where the first entry is the decrypted plaintext and the second entry contains
            information about the device that sent the message.

        Raises:
            UnkownNamespace: if the backend to handle the message is not currently loaded.
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

        Warning:
            Do **NOT** implement any automatic reaction to decryption failures, those automatic reactions are
            transparently handled by the library! *Do* notify the user about decryption failures though, if
            applicable.

        Note:
            If the trust level of the sender evaluates to undecided, the message is decrypted.
        
        Note:
            May send empty OMEMO messages to "complete" key exchanges or prevent staleness.

        Note:
            Refer to the documentation of the :class:`~omemo.session_manager.SessionManager` class for
            information about the ``Plaintext`` type.
        """

        # Find the backend to handle this message
        backend = next(filter(lambda backend: backend.namespace == message.namespace, self.__backends), None)
        if backend is None:
            raise UnknownNamespace("Backend corresponding to namespace {} is not currently loaded.".format(
                message.namespace
            ))

        # Check if there is key material for us
        try:
            key_material, key_exchange = next(filter(
                lambda k: k[0].bare_jid == self.__own_bare_jid and k[0].device_id == self.__own_device_id,
                message.keys
            ))
        except StopIteration:
            raise MessageNotForUs("The message to decrypt does not contain key material for us.")

        # Check whether the sending device is known
        devices = await self.get_device_information(message.bare_jid)
        device = next(filter(lambda device: device.device_id == message.device_id, devices), None)
        if device is None:
            # If it isn't, trigger a refresh of the device list. This shouldn't be necessary due to PEP
            # subscription mechanisms, however there might be race conditions and it doesn't hurt to refresh
            # here.
            await self.refresh_device_list(message.namespace, message.bare_jid)

            # Once the device list has been refreshed, look for the device again
            devices = await self.get_device_information(message.bare_jid)

            # This time, if the device is still not found, abort. This is not strictly required - the message
            # could be decrypted anyway. However, it would mean the sending device is not complying with the
            # specification, which is shady, thus it's not wrong to abort here either.
            device = next(filter(lambda device: device.device_id == message.device_id, devices), None)
            if device is None:
                raise SenderNotFound(
                    "Couldn't find public information about the device which sent this message. I.e. the"
                    " device either does not appear in the device list of the sending XMPP account, or the"
                    " bundle of the sending device could not be downloaded."
                )

        # Check the trust level of the sending device. Abort in case of explicit distrust.
        if self._evaluate_custom_trust_level(device.trust_level_name) is TrustLevel.Distrusted:
            raise SenderDistrusted(
                "The identity key corresponding to the sending device is explicitly distrusted."
            )

        # Handle the key exchange if available
        if key_exchange is None:
            # If there is no key exchange, a session has to exist and should be loadable
            session = await backend.load_session(device)
            if session is None:
                raise NoSession(
                    "There is no session with the sending device, and key exchange information required to"
                    " build a new session is not included in the message."
                )
        else:
            # Check whether the identity key matches the one we know
            if key_exchange.identity_key != device.identity_key:
                raise PublicDataInconsistency(
                    "There is no session with the sending device. Key exchange information to build a new"
                    " session is included in the message, however the identity key of the key exchange"
                    " information does not match the identity key known for the sending device."
                )

            # Check whether there is a session with the sending device already
            session = await backend.load_session(device)
            if session is not None:
                # Check whether the key exchange would build the same session
                if not session.built_by_key_exchange(key_exchange):
                    # If the key exchange would build a new session, treat this session as non-existent
                    session = None

            # If a new session needs to be built, do so
            if session is None:
                session = await backend.build_session_passive(device, key_exchange)

        # Decrypt the message
        plaintext = await backend.decrypt(
            session,
            message.content,
            key_material,
            self.__max_num_per_session_skipped_keys,
            self.__max_num_per_message_skipped_keys
        )

        # Key exchanges are sent with encrypted messages for new sessions, until it is confirmed that the
        # other party has received at least one of them. Once a new session is used to decrypt a message, the
        # other party is confirmed to have received at least one of the key exchanges, so the data can be
        # safely deleted.
        session.delete_key_exchange()

        # Persist the session following successful decryption
        await session.persist()

        # If this message was a key exchange, take care of pre key hiding/deletion and send and empty message
        # to forward the ratchet to "complete" the handshake.
        if key_exchange is not None:
            bundle_changed: bool
            if self.__synchronizing:
                # If the library is currently in history synchronization mode, hide the pre key but defer the
                # deletion.
                bundle_changed = await backend.hide_pre_key(session)
            else:
                # Otherwise, delete the pre key right away
                bundle_changed = await backend.delete_pre_key(session)

            if bundle_changed:
                num_visible_pre_keys = await backend.get_num_visible_pre_keys()
                if num_visible_pre_keys <= self.__pre_key_refill_threshold:
                    await backend.generate_pre_keys(100 - num_visible_pre_keys)
                    bundle = await backend.bundle(
                        self.__own_bare_jid,
                        self.__own_device_id,
                        self.__identity_key_pair.identity_key
                    )

                await self._upload_bundle(bundle)
            
            await self.__send_empty_message(backend, session)
        
        # Send an empty message if necessary to avoid staleness
        if session.receiving_chain_length >= self.__class__.HEARTBEAT_MESSAGE_TRIGGER: # TODO: Make prettier
            await self.__send_empty_message(backend, session)
        
        # Return the plaintext and information about the sending device
        return (plaintext, device)
