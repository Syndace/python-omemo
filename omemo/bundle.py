from abc import ABC, abstractmethod

class Bundle(ABC):
    """
    The bundle of a device, containing the cryptographic information required for active session building.
    """

    @property
    @abstractmethod
    def namespace(self) -> str:
        pass

    @property
    @abstractmethod
    def bare_jid(self) -> str:
        pass

    @property
    @abstractmethod
    def device_id(self) -> int:
        pass

    @property
    @abstractmethod
    def identity_key(self) -> bytes:
        pass

    @abstractmethod
    def __eq__(self, other: object) -> bool:
        """
        Check an object for equality with this Bundle instance.

        Args:
            other: The object to compare to this instance.

        Returns:
            Whether the other object is a bundle with the same contents as this instance.

        Note:
            The order in which pre keys are included in the bundles does not matter.
        """
