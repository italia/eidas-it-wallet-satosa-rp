from abc import ABC, abstractmethod
from typing import Any, Dict

class BaseVPParser(ABC):
    """
    Standard interface for parsing Verifiable Presentations (VP).
    Each parser must implement these methods to ensure uniformity.
    """

    @abstractmethod
    def parse(self, vp_token: str) -> Dict[str, Any]:
        """Parses a Verifiable Presentation token."""
        pass

    @abstractmethod
    def validate(self, parsed_vp: Dict[str, Any]) -> bool:
        """Validates the content of a Verifiable Presentation."""
        pass
