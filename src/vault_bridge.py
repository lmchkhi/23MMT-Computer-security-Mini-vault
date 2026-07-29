from __future__ import annotations

from typing import Any

from flask import current_app


class VaultLockedError(RuntimeError):
    """Raised when a feature requires the in-memory DEK but the vault is locked."""


class VaultConfigurationError(RuntimeError):
    """Raised when an unlocked vault exposes an invalid DEK."""


def _validate_dek(value: Any) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise VaultLockedError("Vault is locked")
    dek = bytes(value)
    if len(dek) != 32:
        raise VaultConfigurationError("Vault DEK must be exactly 32 bytes")
    return dek


def get_vault_dek() -> bytes:
    """Resolve the plaintext DEK from the team's Feature 0.1 implementation.

    Preferred integration contract::

        app.extensions["mini_vault_dek_provider"] = callable_returning_dek

    The compatibility fallbacks make this branch easy to merge with the supplied
    core branch, which exposes ``vault_obj.dek`` and ``vault_obj.is_locked``.
    The DEK is read only from memory and is never persisted by this module.
    """

    provider = current_app.extensions.get("mini_vault_dek_provider")
    if callable(provider):
        try:
            return _validate_dek(provider())
        except (VaultLockedError, VaultConfigurationError):
            raise
        except Exception as exc:  # do not leak provider internals
            raise VaultLockedError("Vault is locked") from exc

    core = current_app.extensions.get("mini_vault_core")
    if core is not None:
        if bool(getattr(core, "is_locked", True)):
            raise VaultLockedError("Vault is locked")
        return _validate_dek(getattr(core, "dek", None))

    # Compatibility with the other branch currently used by the team.
    try:
        from src.core.vault import vault_obj  # type: ignore
    except (ImportError, ModuleNotFoundError):
        vault_obj = None

    if vault_obj is not None:
        if bool(getattr(vault_obj, "is_locked", True)):
            raise VaultLockedError("Vault is locked")
        return _validate_dek(getattr(vault_obj, "dek", None))

    # Deterministic injection used only by tests. The production app never sets it.
    test_dek = current_app.config.get("TEST_VAULT_DEK")
    if current_app.testing and test_dek is not None:
        return _validate_dek(test_dek)

    raise VaultLockedError("Vault is locked")
