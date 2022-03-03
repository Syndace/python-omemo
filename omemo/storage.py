from abc import ABCMeta, abstractmethod
from typing import NamedTuple, Optional, Set, Tuple, Dict, Any, TypeVar, Type, Generic

from .types import JSONType, OMEMOException

StateSerialized # TODO
SessionSerialized # TODO

class Device(NamedTuple):
    bare_jid: str
    device_id: int

class DeviceInformation(NamedTuple):
    identity_key: bytes
    active: bool
    last_used: int
    label: Optional[str]

class IdentityPublicKey(NamedTuple):
    bare_jid: str
    identity_public_key: bytes

class StorageException(OMEMOException):
    pass

# typing's Optional[A] is just an alias for Union[None, A], which means if A is a union itself that allows
# None, the Optional[A] doesn't add anything. E.g. Optional[Optional[X]] = Optional[X] is true for any type X.
# This Maybe class actually makes a difference between whether a value is set or not.
V = TypeVar("V")
M = TypeVar("M", bound="Maybe")

class Nothing(Exception):
    pass

class Maybe(Generic[V]):
    def __init__(self):
        # Just the type definitions here
        self.__value: V
        self.__value_set: bool

    @classmethod
    def just(cls: Type[M], value: V) -> M:
        # pylint: disable=protected-access
        self = cls()
        self.__value = value
        self.__value_set = True
        return self

    @classmethod
    def nothing(cls: Type[M]) -> M:
        # pylint: disable=protected-access
        self = cls()
        self.__value_set = False
        return self

    def from_just(self) -> V:
        if self.__value_set:
            return self.__value

        raise Nothing # yuck (❤️ Haskell)

class Storage(metaclass=ABCMeta): # TODO: Add Raises StorageException everywhere
    """
    # TODO
    """

    def __init__(self, disable_cache: bool = False):
        """
        # TODO
        """

        self.__disable_cache = disable_cache

        self.__own_device: Optional[Maybe[Device]] = None
        self.__state: Dict[str, Maybe[JSONType]] = None
        self.__sessions: Dict[Device, Dict[str, JSONType]] = {}
        self.__devices: Dict[str, Dict[int, DeviceInformation]] = {}
        self.__trusts: Dict[IdentityPublicKey, Optional[str]] = {}

    async def load_own_device(self) -> Maybe[Device]:
        """
        Returns:
            
        """

        if not self.__disable_cache and self.__own_device is not None:
            return self.__own_device

        device = await self._load_own_device()
        self.__own_device = device
        return device

    @abstractmethod
    async def _load_own_device(self) -> Maybe[Device]:
        raise NotImplementedError

    async def store_own_device(self, device: Device) -> Any:
        """
        # TODO
        """

        result = await self._store_own_device(device)
        self.__own_device = Maybe.just(device)
        return result

    @abstractmethod
    async def _store_own_device(self, device: Device) -> Any:
        raise NotImplementedError

    async def load_state(self, namespace: str) -> Maybe[JSONType]:
        """
        # TODO
        """

        if not self.__disable_cache:
            try:
                return self.__state[namespace]
            except KeyError:
                pass

        state = await self._load_state(namespace)
        self.__state[namespace] = state
        return state

    @abstractmethod
    async def _load_state(self, namespace: str) -> Maybe[JSONType]:
        raise NotImplementedError

    async def store_state(self, namespace: str, state: StateSerialized) -> Any:
        """
        # TODO
        """

        result = await self._store_state(state)
        self.__state[namespace] = Maybe.just(state)
        return result

    @abstractmethod
    async def _store_state(self, state: StateSerialized) -> Any:
        raise NotImplementedError

    async def purge_state(self, namespace: str) -> Any:
        """
        # TODO
        """

        # Invalidate the cache entries corresponding to the state namespace. Invalidating is safe even in case
        # `_purge_state` fails halfway through the deletion.

        # Invalidate the state itself
        self.__state.pop(namespace, None)

        # Invalidate all sessions that belong to the state
        for device, sessions in list(self.__sessions.items()):
            if namespace in sessions:
                self.__sessions.pop(device, None)

        return await self._purge_state(namespace)

    @abstractmethod
    async def _purge_state(self, namespace: str) -> Any: # TODO: Delete the state itself and all sessions that belong to the state
        raise NotImplementedError

    async def load_session(self, device: Device) -> Dict[str, JSONType]:
        """
        # TODO
        """

        if not self.__disable_cache:
            try:
                return self.__sessions[device]
            except KeyError:
                pass

        session = await self._load_session(device)
        self.__sessions[device] = session
        return session

    @abstractmethod
    async def _load_session(self, device: Device) -> Dict[str, JSONType]:
        raise NotImplementedError

    async def load_sessions(self, devices: Set[Device]) -> Dict[Device, Dict[str, JSONType]]:
        """
        # TODO
        """

        sessions: Dict[Device, Dict[str, JSONType]] = {}
        missing_devices: Set[Device] = set()

        if not self.__disable_cache:
            for device in devices:
                try:
                    sessions[device] = self.__sessions[device]
                except KeyError:
                    missing_devices.add(device)

        missing_sessions: Dict[Device, Dict[str, JSONType]] = {}
        if len(missing_devices) == 1:
            missing_device = next(iter(missing_devices))
            missing_sessions[missing_device] = await self._load_session(missing_device)
        else:
            missing_sessions.update(await self._load_sessions(missing_devices))

        self.__sessions.update(missing_sessions)

        sessions.update(missing_sessions)

        return sessions

    async def _load_sessions(self, devices: Set[Device]) -> Dict[Device, Dict[str, JSONType]]:
        return { device: await self._load_session(device) for device in devices }

    async def store_session(self, device: Device, namespace: str, session: SessionSerialized) -> Any:
        """
        # TODO
        """

        result = await self._store_session(device, namespace, session)
        self.__sessions[device] = self.__sessions.get(device, {})
        self.__sessions[device][namespace] = session
        return result

    @abstractmethod
    async def _store_session(self, device: Device, namespace: str, session: SessionSerialized) -> Any:
        raise NotImplementedError

    async def delete_session(self, device: Device, namespace: str) -> Any: # TODO: Don't throw if non-existent
        """
        # TODO
        """

        result = await self._delete_session(device, namespace)
        self.__sessions.get(device, {}).pop(namespace, None)
        return result

    @abstractmethod
    async def _delete_session(self, device: Device, namespace: str) -> Any:
        raise NotImplementedError

    async def delete_sessions(self, bare_jid: str) -> Any:
        """
        # TODO
        """

        if device_ids is None:
            device_ids = set(await self.load_devices(bare_jid))

        # Invalidate the cache entries corresponding to the sessions. Invalidating is safe even in case
        # `_delete_sessions` fails halfway through the deletion.
        for device_id in device_ids:
            self.__sessions.pop(Device(bare_jid=bare_jid, device_id=device_id), None)

        return await self._delete_sessions(bare_jid, devices)

    async def _delete_sessions(self, bare_jid: str, device_ids: Set[int]) -> Any: # TODO: It's fine if this crashes halfway through
        for device_id in device_ids:
            await self._delete_session(Device(bare_jid=bare_jid, device_id=device_id))

    async def load_devices(self, bare_jid: str) -> Dict[int, DeviceInformation]:
        """
        # TODO
        """

        if not self.__disable_cache:
            try:
                return self.__devices[bare_jid]
            except KeyError:
                pass

        devices = await self._load_devices(bare_jid)
        self.__devices[bare_jid] = devices
        return devices

    @abstractmethod
    async def _load_devices(self, bare_jid: str) -> Dict[int, DeviceInformation]:
        raise NotImplementedError

    async def store_devices(self, bare_jid: str, devices: Dict[int, DeviceInformation]) -> Any:
        """
        # TODO
        """

        result = await self._store_devices(bare_jid, devices)
        self.__devices[bare_jid] = devices
        return result

    @abstractmethod
    async def _store_devices(self, bare_jid: str, devices: Dict[int, DeviceInformation]) -> Any:
        raise NotImplementedError

    async def load_trust(self, identity_public_key: IdentityPublicKey) -> Optional[str]:
        """
        # TODO
        """

        if not self.__disable_cache:
            try:
                return self.__trusts[identity_public_key]
            except KeyError:
                pass

        trust = await self._load_trust(identity_public_key)
        self.__trusts[identity_public_key] = trust
        return trust

    @abstractmethod
    async def _load_trust(self, identity_public_key: IdentityPublicKey) -> Optional[str]:
        raise NotImplementedError

    async def load_trusts(self, identity_public_keys: Set[IdentityPublicKey]) -> Dict[IdentityPublicKey, str]:
        """
        # TODO
        """

        trusts: Dict[IdentityPublicKey, str] = {}
        missing_identity_public_keys: Set[IdentityPublicKey] = set()

        if not self.__disable_cache:
            for identity_public_key in identity_public_keys:
                try:
                    trust = self.__trusts[identity_public_key]
                    if trust is not None:
                        trusts[identity_public_key] = trust
                except KeyError:
                    missing_identity_public_keys.add(identity_public_key)

        missing_trusts: Dict[IdentityPublicKey, str] = {}
        if len(missing_identity_public_keys) == 1:
            missing_identity_public_key = next(iter(missing_identity_public_keys))
            missing_trust = await self._load_trust(missing_identity_public_key)
            if missing_trust is not None:
                missing_trusts[missing_identity_public_key] = missing_trust
        else:
            missing_trusts.update(await self._load_trusts(missing_identity_public_keys))

        for missing_identity_public_key in missing_identity_public_keys:
            try:
                self.__trusts[missing_identity_public_key] = missing_trusts[missing_identity_public_key]
            except KeyError:
                self.__trusts[missing_identity_public_key] = None

        trusts.update(missing_trusts)

        return trusts

    async def _load_trusts(
        self,
        identity_public_keys: Set[IdentityPublicKey]
    ) -> Dict[IdentityPublicKey, str]:
        trusts: Dict[IdentityPublicKey, str] = {}

        for identity_public_key in identity_public_keys:
            trust = await self._load_trust(identity_public_key)
            if trust is not None:
                trusts[identity_public_key] = trust

        return trusts

    async def store_trust(self, identity_public_key: IdentityPublicKey, trust_level_name: str) -> Any:
        """
        # TODO
        """

        result = await self._store_trust(identity_public_key, trust_level_name)
        self.__trusts[identity_public_key] = trust_level_name
        return result

    @abstractmethod
    async def _store_trust(self, identity_public_key: IdentityPublicKey, trust_level_name: str) -> Any:
        raise NotImplementedError

    async def purge_bare_jid(self, bare_jid: str) -> Any: # TODO: Don't throw if non-existent # TODO: Remove sessions, devices, and identity keys # TODO: Allow even own JID
        """
        # TODO
        """

        # Invalidate the cache entries corresponding to the base JID. Invalidating is safe even in case
        # `_purge_bare_jid` fails halfway through the deletion.

        # Invalidate all sessions that belong to a device of the bare JID
        for device in list(self.__sessions):
            if device.bare_jid == bare_jid:
                self.__sessions.pop(device, None)

        # Invalidate all devices that belong to the bare JID
        self.__devices.pop(bare_jid, None)

        # Invalidate the trust levels of all identity public keys that belong to the bare JID
        for identity_public_key in list(self.__trusts):
            if identity_public_key.bare_jid == bare_jid:
                self.__trusts.pop(identity_public_key, None)

        return await self._purge_bare_jid(bare_jid)

    @abstractmethod
    async def _purge_bare_jid(self, bare_jid: str) -> Any:
        raise NotImplementedError
