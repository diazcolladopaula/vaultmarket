class VaultMarketError(Exception):
    """Base class for all errors raised on purpose by this package."""


class MarketError(VaultMarketError):
    """A market rule was violated (bad input, insufficient funds, ...)."""


class AuthError(VaultMarketError):
    """Authentication failed or the account is locked."""


class StoreError(VaultMarketError):
    """The vault could not be created, decrypted or written."""
