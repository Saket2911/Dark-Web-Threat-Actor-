"""Datetime helpers.

The platform stores naive UTC timestamps in SQLite (existing schema). Using
``datetime.utcnow`` directly is deprecated in Python 3.12 and produced more
than a thousand warnings during the test suite, so all code paths go through
``utcnow`` instead. The value keeps the same naive-UTC semantics as the
existing data.
"""

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return the current UTC time as a naive datetime (SQLite compatible)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def parse_datetime(value) -> datetime | None:
    """Best-effort parse of an ISO-8601 string or datetime into naive UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def end_of_day(value: datetime) -> datetime:
    """Return 23:59:59.999999 for a date-like datetime (inclusive filtering)."""
    return value.replace(hour=23, minute=59, second=59, microsecond=999999)
