from typing import Dict

import omemo


__all__ = [
    "InMemoryStorage"
]


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
