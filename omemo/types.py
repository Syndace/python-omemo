from typing import Dict, NamedTuple, Optional, Protocol, Set, Type, TYPE_CHECKING, Union

class OMEMOException(Exception):
    pass

class DeviceInformation(NamedTuple):
    namespaces: Set[str]
    active: Dict[str, bool]
    bare_jid: str
    device_id: int
    identity_key: bytes
    trust_level_name: str
    label: Optional[str]

# Thanks @vanburgerberg - https://github.com/python/typing/issues/182
if TYPE_CHECKING:
    class JSONArray(list[JSONType], Protocol):  # type: ignore
        __class__: Type[list[JSONType]]  # type: ignore

    class JSONObject(dict[str, JSONType], Protocol):  # type: ignore
        __class__: Type[dict[str, JSONType]]  # type: ignore

    JSONType = Union[None, float, int, str, bool, JSONArray, JSONObject]