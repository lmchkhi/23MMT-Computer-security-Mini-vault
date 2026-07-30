from .errors import TransitError
import re
_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
def validate_key_name(key_name: object) -> str:
    if not isinstance(key_name, str):
        raise TransitError("INVALID_KEY_NAME", "Key name is invalid", 400)
    normalized = key_name.strip()
    if not _KEY_NAME_RE.fullmatch(normalized):
        raise TransitError(
            "INVALID_KEY_NAME",
            "Key name must be 1-64 characters using letters, numbers, dot, dash, or underscore",
            400,
        )
    return normalized

