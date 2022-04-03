from abc import ABC, abstractmethod


class Bundle(ABC):
    """
    The bundle of a device, containing the cryptographic information required for active session building.

    Note:
        All usages of "identity key" in the public API refer to the public part of the identity key pair in
        Ed25519 format.
    """

    @property
    @abstractmethod
    def namespace(self) -> str:
        # pylint: disable=missing-function-docstring
        pass

    @property
    @abstractmethod
    def bare_jid(self) -> str:
        # pylint: disable=missing-function-docstring
        pass

    @property
    @abstractmethod
    def device_id(self) -> int:
        # pylint: disable=missing-function-docstring
        pass

    @property
    @abstractmethod
    def identity_key(self) -> bytes:
        # pylint: disable=missing-function-docstring
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

    @abstractmethod
    def __hash__(self) -> int:
        """
        Hash this instance in a manner that is consistent with :meth:`__eq__`.

        Returns:
            An integer value representing this instance.
        """


__all__ = [  # pylint: disable=unused-variable
    Bundle.__name__
]
