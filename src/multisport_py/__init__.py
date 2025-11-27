from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("multisport-py")
except PackageNotFoundError:
    # Fallback for when the package is not installed (e.g., in development)
    __version__ = "0.0.0-dev"

from .client import MultisportClient
from .exceptions import APIError, AuthenticationError, MultisportError

__all__ = ["MultisportClient", "MultisportError", "AuthenticationError", "APIError"]
