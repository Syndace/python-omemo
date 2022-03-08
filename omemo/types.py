from typing import Union, Protocol, Type, TYPE_CHECKING

class OMEMOException(Exception):
    pass

# Thanks @vanburgerberg - https://github.com/python/typing/issues/182
if TYPE_CHECKING:
    class JSONArray(list[JSONType], Protocol):  # type: ignore
        __class__: Type[list[JSONType]]  # type: ignore

    class JSONObject(dict[str, JSONType], Protocol):  # type: ignore
        __class__: Type[dict[str, JSONType]]  # type: ignore

    JSONType = Union[None, float, int, str, bool, JSONArray, JSONObject]