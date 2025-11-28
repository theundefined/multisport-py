"""Custom exceptions for the multisport-py library."""


class MultisportError(Exception):
    """Base exception for the multisport-py library."""


class AuthenticationError(MultisportError):
    """Exception raised for authentication errors."""


class APIError(MultisportError):
    """Exception raised for API communication errors."""
