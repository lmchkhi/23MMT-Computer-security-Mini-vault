from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

from .errors import TransitError
from .manager import transit_key_obj


@dataclass(frozen=True)
class EncryptResult:
    key_name: str
    ciphertext: str


@dataclass(frozen=True)
class DecryptResult:
    key_name: str
    plaintext_b64: str
    plaintext: bytes


def _strict_b64decode(value: object, *, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise TransitError("INVALID_BASE64", f"{field_name} must be valid base64", 400)
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TransitError(
            "INVALID_BASE64", f"{field_name} must be valid base64", 400
        ) from exc


def _payload_limit() -> int:
    return int(current_app.config.get("TRANSIT_MAX_PLAINTEXT_BYTES", 1024 * 1024))


def _ciphertext_aad(key_name: str, owner_email: str) -> bytes:
    return f"mini-vault:transit:v1:{key_name}:{owner_email}".encode("utf-8")


def _translate_key_error(exc: ValueError) -> TransitError:
    code = str(exc)
    if code == "VAULT_LOCKED":
        return TransitError("VAULT_LOCKED", "Vault is locked", 423)
    if code == "INVALID_KEY_USAGE":
        return TransitError(
            "INVALID_KEY_USAGE",
            "The named key cannot be used for encryption or decryption",
            409,
        )
    if code in {"KEY_NOT_FOUND_OR_DENIED", "NOT_FOUND_OR_PERMISSION_DENIED"}:
        return TransitError(
            "KEY_NOT_FOUND_OR_DENIED",
            "The named key is unavailable",
            404,
        )
    if code == "INVALID_KEY_NAME":
        return TransitError("INVALID_KEY_NAME", "Key name is invalid", 400)
    if code in {"KEY_MATERIAL_CORRUPTED", "INVALID_VAULT_DEK"}:
        return TransitError(
            "KEY_MATERIAL_ERROR",
            "Stored key material could not be authenticated",
            500,
        )
    return TransitError("KEY_OPERATION_FAILED", "Unable to use named key", 409)


def _owned_encryption_key(*, owner_email: str, key_name: object) -> tuple[str, bytes]:
    if not isinstance(key_name, str) or not key_name:
        raise TransitError("INVALID_KEY_NAME", "Key name is required", 400)
    try:
        key = transit_key_obj.read_key(
            owner_email=owner_email,
            key_name=key_name,
            key_usage="ENCRYPT_DECRYPT",
        )
    except ValueError as exc:
        raise _translate_key_error(exc) from exc
    return key_name, key


def encrypt_for_user(
    *, owner_email: str, key_name: object, plaintext_b64: object
) -> EncryptResult:
    plaintext = _strict_b64decode(plaintext_b64, field_name="plaintext_b64")
    if len(plaintext) > _payload_limit():
        raise TransitError(
            "PAYLOAD_TOO_LARGE", "Plaintext exceeds the configured size limit", 413
        )

    normalized_key_name, key = _owned_encryption_key(
        owner_email=owner_email, key_name=key_name
    )
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(
        nonce,
        plaintext,
        _ciphertext_aad(normalized_key_name, owner_email),
    )
    encoded = base64.b64encode(nonce + encrypted).decode("ascii")
    return EncryptResult(
        key_name=normalized_key_name,
        ciphertext=f"vault:{normalized_key_name}:{encoded}",
    )


def _parse_ciphertext(value: object) -> tuple[str, bytes]:
    if not isinstance(value, str):
        raise TransitError("MALFORMED_CIPHERTEXT", "Ciphertext format is invalid", 400)

    prefix, separator, remainder = value.strip().partition(":")
    if separator != ":" or prefix != "vault":
        raise TransitError("MALFORMED_CIPHERTEXT", "Ciphertext format is invalid", 400)
    key_name, separator, payload_b64 = remainder.partition(":")
    if separator != ":" or not key_name or not payload_b64:
        raise TransitError("MALFORMED_CIPHERTEXT", "Ciphertext format is invalid", 400)

    try:
        combined = base64.b64decode(payload_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TransitError(
            "MALFORMED_CIPHERTEXT", "Ciphertext format is invalid", 400
        ) from exc

    if len(combined) < 28:  # 12-byte nonce + 16-byte GCM tag
        raise TransitError("MALFORMED_CIPHERTEXT", "Ciphertext is truncated", 400)
    return key_name, combined


def decrypt_for_user(*, owner_email: str, ciphertext: object) -> DecryptResult:
    key_name, combined = _parse_ciphertext(ciphertext)
    _, key = _owned_encryption_key(owner_email=owner_email, key_name=key_name)
    nonce, encrypted = combined[:12], combined[12:]

    try:
        plaintext = AESGCM(key).decrypt(
            nonce,
            encrypted,
            _ciphertext_aad(key_name, owner_email),
        )
    except InvalidTag as exc:
        raise TransitError(
            "CIPHERTEXT_INTEGRITY_ERROR",
            "Ciphertext authentication failed; the data may have been modified",
            400,
        ) from exc

    return DecryptResult(
        key_name=key_name,
        plaintext_b64=base64.b64encode(plaintext).decode("ascii"),
        plaintext=plaintext,
    )
