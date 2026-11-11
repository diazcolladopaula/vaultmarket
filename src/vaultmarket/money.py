"""Money is handled as integer cents everywhere; floats never touch balances."""

import re
from decimal import Decimal

from vaultmarket.errors import MarketError

MAX_AMOUNT = 100_000_000  # 1,000,000.00 credits, in cents
_AMOUNT_RE = re.compile(r"\d{1,7}(?:\.\d{1,2})?")


def parse_amount(text: str) -> int:
    """Parse user input such as '12', '12.5' or '12,50' into cents."""
    cleaned = text.strip().replace(",", ".")
    if not _AMOUNT_RE.fullmatch(cleaned):
        raise MarketError("Enter a positive amount with at most two decimals, e.g. 12.50.")
    cents = int(Decimal(cleaned) * 100)
    if not 0 < cents <= MAX_AMOUNT:
        raise MarketError("Amount must be between 0.01 and 1,000,000.00.")
    return cents


def format_amount(cents: int) -> str:
    sign = "-" if cents < 0 else ""
    cents = abs(cents)
    return f"{sign}{cents // 100:,}.{cents % 100:02d}"
