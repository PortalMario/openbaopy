"""
Exceptions for Bao class.
"""


class BaoError(Exception):
    """
    Basic exception for all bao related errors.
    """


class UnexpectedError(BaoError):
    """
    Unexpacted error during api operations.
    """
