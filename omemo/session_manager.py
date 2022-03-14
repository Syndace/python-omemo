from abc import ABCMeta, abstractmethod
import base64
import enum
from typing import cast, Any, Dict, Generic, List, NamedTuple, Optional, Set, Tuple, Type, TypeVar

from .backend import Backend
from .bundle  import Bundle
from .message import Message
from .storage import Nothing, Storage
from .types   import OMEMOException

DeviceList = Dict[int, Optional[str]]

class DeviceInformation(NamedTuple):
    namespaces: Set[str]
    active: Dict[str, bool]
    bare_jid: str
    device_id: int
    identity_key: bytes
    trust_level_name: str
    label: Optional[str]

@enum.unique
class TrustLevel(enum.Enum):
    Trusted    = 1
    Distrusted = 2
    Undecided  = 3

class SessionManagerException(OMEMOException):
    pass

class XMPPInteractionFailed(SessionManagerException):
    pass

class UnknownTrustLevel(SessionManagerException):
    pass

class TrustDecisionFailed(SessionManagerException):
    pass

class StillUndecided(SessionManagerException):
    pass

class NoEligibleDevices(SessionManagerException):
    def __init__(self, msg: str, bare_jids: Set[str]) -> None:
        super().__init__(msg)

        self.bare_jids = bare_jids

class UnknownNamespace(SessionManagerException):
    pass

class BundleUploadFailed(XMPPInteractionFailed):
    pass

class BundleDownloadFailed(XMPPInteractionFailed):
    pass

class BundleDeletionFailed(XMPPInteractionFailed):
    pass

class DeviceListUploadFailed(XMPPInteractionFailed):
    pass

class DeviceListDownloadFailed(XMPPInteractionFailed):
    pass

class MessageSendingFailed(XMPPInteractionFailed):
    pass

# TODO: Take care of logging
S = TypeVar("S", bound="SessionManager")
Plaintext = TypeVar("Plaintext")
class SessionManager(Generic[Plaintext], metaclass=ABCMeta):
    """
    The core of python-omemo. Manages your own key material and bundle, device lists, sessions with other
    users, automatic session healing and much more, all while being flexibly usable with different backends
    and transparenlty maintaining a level of compatibility between the backends that allows you to maintain a
    single identity throughout all of them. Easy APIs are provided to handle common use-cases of OMEMO-enabled
    XMPP clients, with one of the primary goals being strict type safety.

    Note:
        Most methods can raise :class:`~omemo.storage.StorageException` in addition to those exceptions
        listed explicitly.
    
    Note:
        All parameters are treated as immutable unless explicitly noted otherwise. TODO

    TODO: Document the Plaintext generic
    """

    # TODO: Should this really be the only class property?
    HEARTBEAT_MESSAGE_TRIGGER = 53

    def __init__(self) -> None:
        # Just the type definitions here
        self.__backends: List[Backend[Plaintext]]
        self.__storage: Storage
        self.__own_bare_jid: str
        self.__own_device_id: int

    @classmethod
    async def create(
        cls: Type[S],
        backends: List[Backend[Plaintext]],
        storage: Storage,
        own_bare_jid: str,
        initial_own_label: Optional[str],
        undecided_trust_level_name: str,
        decrypt_when_undecided: bool = True,
        max_num_per_session_skipped_keys: int = 1000,
        max_num_per_message_skipped_keys: Optional[int] = None,
        signed_pre_key_rotation_period: int = 7 * 24 * 60 * 60,
        pre_key_refill_threshold: int = 99
    ) -> S:
        # pylint: disable=protected-access
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
            decrypt_when_undecided: When receiving an encrypted message from a source that is not yet trusted
                or distrusted, this flag decides what to do. If set to ``True`` (the default), the message is
                decrypted. If set to ``False``, the message is not decrypted and an exception is raised.
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
            # TODO

        Warning:
            The library starts in history synchronization mode. Call :meth:`after_history_sync` to return to
            normal operation. Refer to the documentation of :meth:`before_history_sync` and
            :meth:`after_history_sync` for details.

        Note:
            This method takes care of leaving the device lists in a consistent state. To do so, backends are
            initialized one after the other. For each backend, the device list is updated as the very last
            step, after everything else that could fail is done. This ensures that either all data is
            consistent or the device list does not yet list the inconsistent device. If the creation of one
            backend succeeds, the data is persisted in the storage before the next backend is created. This
            guarantees that even if the next backend creation fails, the data is not lost and will be loaded
            from the storage when calling this method again.

        Note:
            The order of the backends can optionally be used by :meth:`encrypt_message` as the order of
            priority, in case a recipient device supports multiple backends. Refer to the documentation of
            :meth:`encrypt_message` for details.
        """

        self = cls()
        self.__backends = backends
        self.__storage = storage
        self.__own_bare_jid = own_bare_jid
        self.__own_device_id = (await self.__storage.load_primitive("/own_device_id", int)).maybe(...) # TODO

        # TODO

        return self

    async def purge_backend(self, namespace: str) -> None:
        """
        Purge a backend, removing both the online data (bundle, device list entry) and the offline data that
        belongs to this backend.

        Args:
            namespace: The XML namespace managed by the backend to purge.

        Raises:
            # TODO

        Note:
            Make sure to unsubscribe from updates to all device lists before calling this method.
        """
        # This method is not affected by history synchronization mode. #

        # TODO

    ####################
    # abstract methods #
    ####################

    @staticmethod
    @abstractmethod
    async def _upload_bundle(bundle: Bundle, device_id: int) -> Any:
        """
        Upload the bundle corresponding to this device, overwriting any previously published bundle data.

        Args:
            bundle: The bundle to publish.
            device_id: The id of this device.

        Returns:
            Anything, the return value is ignored.

        Raises:
            BundleUploadFailed: if the upload failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.
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
            BundleDownloadFailed: if the download failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.
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
            BundleDeletionFailed: if the deletion failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.
        """

        raise NotImplementedError("Create a subclass of SessionManager and implement `_delete_bundle`.")

    @staticmethod
    @abstractmethod
    async def _upload_device_list(namespace: str, device_list: DeviceList) -> Any:
        """
        Upload the device list for this XMPP account.

        Args:
            namespace: The XML namespace to execute this operation under.
            device_list: The device list to upload.

        Returns:
            Anything, the return value is ignored.

        Raises:
            DeviceListUploadFailed: if the upload failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.
        """

        raise NotImplementedError("Create a subclass of SessionManager and implement `_upload_device_list`.")
        

    @staticmethod
    @abstractmethod
    async def _download_device_list(namespace: str, bare_jid: str) -> DeviceList:
        """
        Download the device list of a specific XMPP account.

        Args:
            namespace: The XML namespace to execute this operation under.
            bare_jid: The bare JID of the XMPP account.

        Returns:
            The list of device ids and their optional label, if available.

        Raises:
            DeviceListDownloadFailed: if the download failed. Feel free to raise a subclass instead.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.
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
            encrypt/decrypt messages to/from it.

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
    async def _make_trust_decision(self, undecided: Dict[str, Set[DeviceInformation]]) -> Any:
        """
        Make a trust decision on a set of undecided identity public keys.

        Args:
            undecided: A mapping from bare JIDs to sets of devices that require trust decisions.

        Returns:
            Anything, the return value is ignored. The trust decisions are expected to be persisted by calling
            :meth:`set_trust`.

        Raises:
            TrustDecisionFailed: if for any reason the trust decision failed/could not be completed. Feel free
                to raise a subclass instead.

        Note:
            This is called when the message encryption needs to know whether it is allowed to encrypt the
            message for these devices or not. When this method returns, all previously undecided trust levels
            should have been replaced by calling :meth:`set_trust` with a different trust level. If they are
            not replaced or still evaluate to the undecided trust level after the call, the message encryption
            will fail with an exception. See :meth:`encrypt_message` for details.
        """

        raise NotImplementedError("Create a subclass of SessionManager and implement `_make_trust_decision`.")

    @staticmethod
    @abstractmethod
    async def _send_message(message: Message) -> Any:
        """
        Send an OMEMO-encrypted message. This is required for various automated behaviours to improve the
        overall stability of the protocol:

        * Automatic handshake completion, by responding to incoming key exchanges.
        * Automatic heartbeat messages to forward the ratchet if many messages were received without a
            (manual) response, to assure forward secrecy. The number of messages required to trigger this
            behaviour is hardcoded in ``SessionManager.HEARTBEAT_MESSAGE_TRIGGER``.
        * Automatic session initiation if an encrypted message is received but no session exists for that
            device.
        * Automatic session replacement of "broken" sessions, by sending empty key exchanges. Whether this
            feature is used and the exact conditions for an automatic session replacement depends on the
            respective backend. 
        * Backend-dependent empty messages to notify other devices about potentially "broken" sessions.

        Note that messages created here don't contain any content, they are just empty messages to transport
        key material.

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

    async def update_device_list(self, namespace: str, bare_jid: str, device_list: DeviceList) -> None:
        """
        Update the device list of a specific bare JID, e.g. after receiving an update for the XMPP account
        from `PEP <https://xmpp.org/extensions/xep-0163.html>`__.

        Args:
            namespace: The XML namespace to execute this operation under.
            bare_jid: The bare JID of the XMPP account.
            device_list: The updated device list. Each device list entry consists of the device id and the
                optional label, if available.

        Raises:
            DeviceListUploadFailed: if a device list upload failed. An upload can happen if the device list
                update is for the own bare JID and does not include the own device. Forwarded from
                :meth:`_upload_device_list`.
        """
        # This method is not affected by history synchronization mode. #

        storage = self.__storage

        new_device_list = set(device_list.keys())
        old_device_list = set((await storage.load_list("/devices/{}/list".format(bare_jid), int)).maybe([]))

        new_devices = new_device_list - old_device_list

        # If the device list is for this JID and a loaded backend, make sure this device is included
        if (bare_jid == self.__own_bare_jid and
            namespace in set(backend.namespace for backend in self.__backends) and
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
            DeviceListDownloadFailed: if the device list download failed. Forwarded from
                :meth:`_download_device_list`.
            DeviceListUploadFailed: if a device list upload failed. An upload can happen if the device list
                update is for the own bare JID and does not include the own device. Forwarded from
                :meth:`update_device_list`.
        """
        # This method is not affected by history synchronization mode. #

        await self.update_device_list(
            namespace,
            bare_jid,
            await self._download_device_list(namespace, bare_jid)
        )

    ####################
    # trust management #
    ####################

    async def set_trust(self, bare_jid: str, identity_public_key: bytes, trust_level_name: str) -> None:
        """
        Set the trust level for an identity public key.

        Args:
            bare_jid: The bare JID of the XMPP account this identity public key belongs to.
            identity_public_key: The identity public key.
            trust_level_name: The custom trust level to set for the identity public key.
        """
        # This method is not affected by history synchronization mode. #

        await self.__storage.store("/trust/{}/{}".format(
            bare_jid,
            base64.urlsafe_b64encode(identity_public_key).decode("ASCII")
        ), trust_level_name)

    ######################
    # session management #
    ######################

    async def replace_sessions(self, bare_jid: str) -> None:
        """
        Manually replace sessions. Can be used if sessions are suspected to be broken and secure automatic
        session healing does not seem to automatically replace them. This method automatically notifies the
        other ends about the new sessions, so that hopefully no messages are lost.

        Args:
            bare_jid: The bare JID of the XMPP account whose sessions are to be replaced.

        Raises:
            # TODO
        """
        # TODO: per-backend?

        # TODO

    async def purge_bare_jid(self, bare_jid: str) -> None:
        """
        Delete all data corresponding to an XMPP account. This includes the device list, trust information and
        all sessions across all loaded backends.

        Args:
            bare_jid: Delete all data corresponding to this bare JID.

        Raises:
            # TODO
        """

        # TODO

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

        Note:
            It is recommended to keep the length of the label under 53 unicode code points.
        """
        # This method is not affected by history synchronization mode. #

        # Store the new label
        await self.__storage.store("/devices/{}/{}/label".format(
            self.__own_bare_jid,
            self.__own_device_id
        ), own_label)

        # For each loaded backend, upload an updated device list including the new label
        devices = await self.get_device_information(self.__own_bare_jid)
        for backend in self.__backends:
            # Upload the new device list, including all active devices for this backend
            await self._upload_device_list(backend.namespace, {
                device.device_id: device.label
                for device in devices
                if device.active.get(backend.namespace, False)
            })

    async def get_device_information(self, bare_jid: str) -> Set[DeviceInformation]:
        """
        Args:
            bare_jid: Get information about the devices of the XMPP account belonging to this bare JID.

        Returns:
            Information about each device of `bare_jid`. The information includes the device id, the identity
            public key, the trust level, whether the device is active and, if supported by any of the
            backends, the optional label. Returns information about all known devices, regardless of the
            backend they belong to.

        Note:
            Only returns information about cached devices. The cache, however, should be up to date if
            `PEP <https://xmpp.org/extensions/xep-0163.html>`__ updates are correctly fed to
            :meth:`update_device_list`. A manual update of a device list can be triggered using
            :meth:`refresh_device_list` if needed.

        Raises:
            # TODO
        """
        # This method is not affected by history synchronization mode. #

        # Do not expose the bundle cache publicly.
        return (await self.__get_device_information(bare_jid))[0]

    async def __get_device_information(self, bare_jid: str) -> Tuple[Set[DeviceInformation], Set[Bundle]]:
        # This method is not affected by history synchronization mode. #

        storage = self.__storage

        bundle_cache: Set[Bundle] = set()

        device_list = set((await storage.load_list("/devices/{}/list".format(bare_jid), int)).maybe([]))
        
        async def load_device_information(device_id: int) -> DeviceInformation:
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

            try:
                identity_key = (await storage.load_bytes("/devices/{}/{}/identity_key".format(
                    bare_jid,
                    device_id
                ))).from_just()
            except Nothing:
                # The identity key assigned to this device is not known yet. Fetch the bundle to find that
                # information. "Cache" and return the downloaded bundles to avoid double-fetching them if they
                # are required for session initiation afterwards.
                bundle_cache
                pass # TODO

            trust_level_name = (await storage.load_primitive("/trust/{}/{}".format(
                bare_jid,
                base64.urlsafe_b64encode(identity_key).decode("ASCII")
            ), str)).from_just()

            return DeviceInformation(
                namespaces=namespaces,
                active=active,
                bare_jid=bare_jid,
                device_id=device_id,
                identity_key=identity_key,
                trust_level_name=trust_level_name,
                label=label
            ), bundle_cache

        return set((await load_device_information(device_id)) for device_id in device_list)

    async def get_own_device_information(self) -> Tuple[DeviceInformation, Set[DeviceInformation]]:
        """
        Variation of :meth:`get_device_information` for convenience.

        Returns:
            A tuple, where the first entry is information about this device and the second entry contains
            information about the other devices of the own bare JID.

        Raises:
            # TODO
        """
        # This method is not affected by history synchronization mode. #

        all_own_devices = await self.get_device_information(self.__own_bare_jid)
        other_own_devices = set(filter(lambda d: d.device_id != self.__own_device_id, all_own_devices))

        return next(all_own_devices - other_own_devices), other_own_devices

    @staticmethod
    def format_identity_public_key(identity_public_key: bytes) -> List[str]:
        """
        Args:
            identity_public_key: The identity public key to generate the fingerprint of (in Ed25519 format).

        Returns:
            The fingerprint of the identity public key, as eight groups of eight lowercase hex chars each.
            Consider applying `Consistent Color Generation <https://xmpp.org/extensions/xep-0392.html>`__ to
            each individual group when displaying the fingerprint, if applicable.
        """

        ik_hex_string = identity_public_key.hex()
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
        * One-time pre keys are kept around during history synchronization, to account for the (hopefully
            rather hypothetical) case that two or more parties selected the same one-time pre key to initiate
            a session with this device while it was offline. When history synchronization ends, all one-time
            pre keys that were kept around are deleted and the library returns to normal behaviour.
        * If the signed pre key is due for rotation, rotation is deferred until after history synchronization
            is done to account for delayed messages and offline periods.
        * Automated responses are collected during synchronization, such that only the minimum required number
            of messages is sent.

        Note:
            TODO: The lib can process live event too while in history sync mode
        """

        # TODO

    async def after_history_sync(self) -> None:
        """
        If the library is in "history synchronization mode" started by :meth:`create` or
        :meth:`before_history_sync`, calling this makes it return to normal working behaviour. Make sure to
        call this as soon as history synchronization (if any) is done.

        Raises:
            # TODO
        """

        # TODO

    ##############################
    # message en- and decryption #
    ##############################

    # TODO: check whether the ephemeral key is stored with the session for omemo:1
    # TODO: check whether the key exchange header is stored with the session until a successful key exchange is confirmed
    # TODO: need internal method to create new sessions, both for :meth:`encrypt_message` and :meth:`replace_sessions`
    # TODO: internal method to encrypt empty messages?

    async def __encrypt_message(
        self,
        backend: Backend[Plaintext],
        devices: Dict[str, Set[DeviceInformation]],
        message: Plaintext,
        bundle_cache: Set[Bundle]
    ) -> Message:
        """
        TODO
        """
        # This method is not affected by history synchronization mode. #

        # TODO: Bundle fetching
        # TODO: Key exchange simulation?

        pass

    async def encrypt_message(
        self,
        bare_jids: Set[str],
        message: Plaintext,
        backend_priority_order: Optional[List[str]] = None
    ) -> Dict[str, Message]:
        """
        Encrypt a message for a set of recipients.

        Args:
            bare_jids: The bare JIDs of the intended recipients.
            message: The message to encrypt for the recipients. Details depend on the backend(s).
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
            StillUndecided: if the trust level for one of the recipient devices still evaluates to undecided,
                even after :meth:`_make_trust_decision` was called to decide on the trust.
            NoEligibleDevices: if at least one of the intended recipients does not have a single device which
                qualifies for encryption. Either the recipient does not advertize any OMEMO-enabled devices or
                all devices were disqualified due to missing trust or failure to download their bundles.
            # TODO

        Note:
            The own JID is implicitly added to the set of recipients, there is no need to list it manually.

        Note:
            Refer to the documentation of the :class:`~omemo.session_manager.SessionManager` class for
            information about the ``Plaintext`` type.
        """
        # This method is not affected by history synchronization mode. #

        own_bare_jid = self.__own_bare_jid
        own_device_id = self.__own_device_id

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

        # Add the own bare JID to the list of recipients
        bare_jids |= set([ own_bare_jid ])
        
        # Load the device information of all recipients
        async def get_filtered_device_information(bare_jid: str) -> Tuple[Set[DeviceInformation], Set[Bundle]]:
            def device_filter(device: DeviceInformation) -> bool:
                # Remove the own device
                if bare_jid == own_bare_jid and device.device_id == own_device_id:
                    return False

                # Remove namespaces for which the device is inactive
                namespaces = { ns for ns in device.namespaces if device.active[ns] }

                # Remove devices which are only available with backends that are not currently loaded and in
                # the priority list
                if len(namespaces & set(effective_backend_priority_order)) == 0:
                    return False

                return True

            device_information, bundle_cache = await self.__get_device_information(bare_jid)

            return set(filter(device_filter, device_information)), bundle_cache

        filtered_device_information = {
            bare_jid: await get_filtered_device_information(bare_jid) for bare_jid in bare_jids
        }

        devices = { bare_jid: devices for bare_jid, (devices, _) in filtered_device_information.items() }
        bundle_cache = cast(Set[Bundle], set()).union(*(
            bundle_cache for _, bundle_cache in filtered_device_information.values()
        ))

        # Check for recipients without a single active device
        no_eligible_devices = filter(lambda bare_jid: len(devices[bare_jid]) == 0, devices.keys())
        if len(no_eligible_devices) > 0:
            raise NoEligibleDevices(
                "One or more of the intended recipients does not have a single active device for the loaded"
                " backends.",
                no_eligible_devices
            )

        # Apply the backend priority order to the remaining devices
        def apply_backend_priority_order(device: DeviceInformation) -> DeviceInformation:
            namespaces = { ns for ns in device.namespaces if device.active[ns] }
            namespaces_sorted = sorted(namespaces, key=effective_backend_priority_order.index)

            return device._replace(namespaces=set(namespaces_sorted[0:1]))

        devices = { j: set(apply_backend_priority_order(d) for d in ds) for j, ds in devices.items() }

        # Ask for trust decisions on the remaining devices (or rather, on the identity keys corresponding to
        # the remaining devices)
        def is_undecided(device: DeviceInformation) -> bool:
            return self._evaluate_custom_trust_level(device.trust_level_name) is TrustLevel.Undecided

        def is_trusted(device: DeviceInformation) -> bool:
            return self._evaluate_custom_trust_level(device.trust_level_name) is TrustLevel.Trusted
        
        async def update_trust(device: DeviceInformation) -> DeviceInformation:
            return device._replace(trust_level_name=(await self.__storage.load_primitive(
                "/trust/{}/{}".format(
                    device.bare_jid,
                    base64.urlsafe_b64encode(device.identity_key).decode("ASCII")
                ),
                str
            )).from_just())

        undecided_devices = { j: set(d for d in ds if is_undecided(d)) for j, ds in devices.items() }
        if any(len(ds) > 0 for ds in undecided_devices.values()):
            await self._make_trust_decision(undecided_devices)

            # Update to the new trust levels
            devices = { j: set([ (await update_trust(d)) for d in ds ]) for j, ds in devices.items() }

        # Make sure the trust status of all previously undecided devices has been decided on
        undecided_devices = { j: set(d for d in ds if is_undecided(d)) for j, ds in devices.items() }
        if any(len(ds) > 0 for ds in undecided_devices.values()):
            raise StillUndecided("The trust status of one or more devices has not been decided on: {}".format(
                undecided_devices
            ))

        # Remove distrusted devices
        devices = { j: set(d for d in ds if is_trusted(d)) for j, ds in devices.items() }

        # Check for recipients without a single remaining device
        no_eligible_devices = filter(lambda bare_jid: len(devices[bare_jid]) == 0, devices.keys())
        if len(no_eligible_devices) > 0:
            raise NoEligibleDevices(
                "One or more of the intended recipients does not have a single active and trusted device for"
                " the loaded backends.",
                no_eligible_devices
            )

        # Encrypt the message
        result: Dict[str, Message] = {}
        for backend in self.__backends:
            ns = backend.namespace

            # Select the devices to encrypt for using this backend
            backend_devices = { j: set(d for d in ds if d.namespaces[0] == ns) for j, ds in devices.items() }
            backend_devices = { j: ds for j, ds in devices.items() if len(ds) > 0 }

            if len(backend_devices) > 0:
                result[ns] = await self.__encrypt_message(backend, backend_devices, message, bundle_cache)

        return result

    async def decrypt_message(self, message: Message) -> Tuple[Plaintext, DeviceInformation]:
        """
        Decrypt a message.

        Args:
            message: The message to decrypt. The backend is selected based on the type of `message`.

        Returns:
            A tuple, where the first entry is the decrypted message and the second entry contains information
            about the device that sent the message.

        Raises:
            # TODO

        Warning:
            Do **NOT** implement any automatic reaction to decryption failures, those automatic reactions are
            transparently handled by the library! *Do* notify the user about decryption failures though, if
            applicable.

        Note:
            If the trust level of the sender evaluates to undecided, the value of ``decrypt_when_undecided``
            as passed to :meth:`create` determines whether the message is decrypted or rejected.

        Note:
            Refer to the documentation of the :class:`~omemo.session_manager.SessionManager` class for
            information about the ``Plaintext`` type.
        """
        # THIS METHOD IS AFFECTED BY HISTORY SYNCHRONIZATION MODE #

        # TODO
