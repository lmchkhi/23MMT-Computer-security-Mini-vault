from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

from .errors import TransitError
from .key_store import get_owned_encryption_key, unwrap_key_material


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
        raise TransitError(
            "INVALID_BASE64", f"{field_name} must be valid base64", 400
        )
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TransitError(
            "INVALID_BASE64", f"{field_name} must be valid base64", 400
        ) from exc


def _payload_limit() -> int:
    return int(current_app.config.get("TRANSIT_MAX_PLAINTEXT_BYTES", 1024 * 1024))


def _ciphertext_aad(key_name: str) -> bytes:
    return f"mini-vault:transit:v1:{key_name}".encode("utf-8")


def encrypt_for_user(
    *, owner_email: object, key_name: object, plaintext_b64: object
) -> EncryptResult:
    plaintext = _strict_b64decode(plaintext_b64, field_name="plaintext_b64")
    if len(plaintext) > _payload_limit():
        raise TransitError(
            "PAYLOAD_TOO_LARGE",
            "Plaintext exceeds the configured size limit",
            413,
        )

    record = get_owned_encryption_key(owner_email, key_name)
    key_material = unwrap_key_material(record)
    nonce = os.urandom(12)
    encrypted = AESGCM(key_material).encrypt(
        nonce,
        plaintext,
        _ciphertext_aad(record.key_name),
    )
    encoded = base64.b64encode(nonce + encrypted).decode("ascii")
    return EncryptResult(
        key_name=record.key_name,
        ciphertext=f"vault:{record.key_name}:{encoded}",
    )


def _parse_ciphertext(value: object) -> tuple[str, bytes]:
    if not isinstance(value, str):
        raise TransitError(
            "MALFORMED_CIPHERTEXT", "Ciphertext format is invalid", 400
        )

    prefix, separator, remainder = value.strip().partition(":")
    if separator != ":" or prefix != "vault":
        raise TransitError(
            "MALFORMED_CIPHERTEXT", "Ciphertext format is invalid", 400
        )
    key_name, separator, payload_b64 = remainder.partition(":")
    if separator != ":" or not key_name or not payload_b64:
        raise TransitError(
            "MALFORMED_CIPHERTEXT", "Ciphertext format is invalid", 400
        )

    try:
        combined = base64.b64decode(payload_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TransitError(
            "MALFORMED_CIPHERTEXT", "Ciphertext format is invalid", 400
        ) from exc

    # 12-byte nonce + optional ciphertext + 16-byte GCM tag.
    if len(combined) < 28:
        raise TransitError(
            "MALFORMED_CIPHERTEXT", "Ciphertext is truncated", 400
        )
    return key_name, combined


def decrypt_for_user(
    *, owner_email: object, ciphertext: object
) -> DecryptResult:
    key_name, combined = _parse_ciphertext(ciphertext)
    record = get_owned_encryption_key(owner_email, key_name)
    key_material = unwrap_key_material(record)
    nonce, encrypted = combined[:12], combined[12:]

    try:
        plaintext = AESGCM(key_material).decrypt(
            nonce,
            encrypted,
            _ciphertext_aad(record.key_name),
        )
    except InvalidTag as exc:
        raise TransitError(
            "CIPHERTEXT_INTEGRITY_ERROR",
            "Ciphertext authentication failed; the data may have been modified",
            400,
        ) from exc

    return DecryptResult(
        key_name=record.key_name,
        plaintext_b64=base64.b64encode(plaintext).decode("ascii"),
        plaintext=plaintext,
    )
