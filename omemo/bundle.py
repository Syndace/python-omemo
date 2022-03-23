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
    def __eq__(self, other: "Bundle") -> bool:
        """
        Check for equality of two Bundle instances.

        Args:
            other: The bundle to compare this instance with.

        Returns:
            Whether the contents of the bundle are equal.

        Note:
            The order in which pre keys are included in the bundles does not matter.
        """
