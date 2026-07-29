from __future__ import annotations

import base64
import binascii
import os
import re
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from src.auth.validation import normalize_email
from src.extensions import db
from src.vault_bridge import (
    VaultConfigurationError,
    VaultLockedError,
    get_vault_dek,
)

from .errors import TransitError
from .models import TransitNamedKey

ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT"
_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def now_timestamp() -> int:
    clock = current_app.config.get("TRANSIT_CLOCK", time.time)
    return int(clock())


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


def _key_aad(owner_email: str, key_name: str, key_usage: str) -> bytes:
    return (
        f"mini-vault:key-wrap:v1:{owner_email}:{key_name}:{key_usage}"
    ).encode("utf-8")


def wrap_key_material(
    *, owner_email: str, key_name: str, key_usage: str, key_material: bytes
) -> str:
    """Helper for Feature 2.1 to persist key material using the in-memory DEK."""

    if not isinstance(key_material, bytes) or len(key_material) != 32:
        raise ValueError("AES-256 named key material must be exactly 32 bytes")

    owner = normalize_email(owner_email)
    name = validate_key_name(key_name)
    try:
        dek = get_vault_dek()
    except VaultLockedError as exc:
        raise TransitError("VAULT_LOCKED", "Vault is locked", 423) from exc
    except VaultConfigurationError as exc:
        raise TransitError("VAULT_CONFIGURATION_ERROR", str(exc), 500) from exc

    nonce = os.urandom(12)
    wrapped = AESGCM(dek).encrypt(
        nonce,
        key_material,
        _key_aad(owner, name, key_usage),
    )
    return base64.b64encode(nonce + wrapped).decode("ascii")


def unwrap_key_material(record: TransitNamedKey) -> bytes:
    try:
        combined = base64.b64decode(
            record.encrypted_key_material_b64, validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise TransitError(
            "KEY_MATERIAL_CORRUPTED",
            "Named key material could not be authenticated",
            500,
        ) from exc

    if len(combined) < 12 + 16 + 1:
        raise TransitError(
            "KEY_MATERIAL_CORRUPTED",
            "Named key material could not be authenticated",
            500,
        )

    try:
        dek = get_vault_dek()
    except VaultLockedError as exc:
        raise TransitError("VAULT_LOCKED", "Vault is locked", 423) from exc
    except VaultConfigurationError as exc:
        raise TransitError("VAULT_CONFIGURATION_ERROR", str(exc), 500) from exc

    nonce, wrapped = combined[:12], combined[12:]
    try:
        key_material = AESGCM(dek).decrypt(
            nonce,
            wrapped,
            _key_aad(record.owner_email, record.key_name, record.key_usage),
        )
    except InvalidTag as exc:
        raise TransitError(
            "KEY_MATERIAL_CORRUPTED",
            "Named key material could not be authenticated",
            500,
        ) from exc

    if len(key_material) != 32:
        raise TransitError(
            "KEY_MATERIAL_CORRUPTED",
            "Named key material could not be authenticated",
            500,
        )
    return key_material


def get_owned_encryption_key(owner_email: object, key_name: object) -> TransitNamedKey:
    owner = normalize_email(owner_email)
    name = validate_key_name(key_name)

    # Query by owner and name in one operation. A caller cannot distinguish a
    # missing key from a key owned by somebody else.
    record = db.session.scalar(
        select(TransitNamedKey).where(
            TransitNamedKey.owner_email == owner,
            TransitNamedKey.key_name == name,
        )
    )
    if record is None or record.revoked_at is not None:
        current_app.logger.warning(
            "TRANSIT_KEY_ACCESS_DENIED requester=%s key_name=%s",
            owner or "<unknown>",
            name,
        )
        raise TransitError(
            "KEY_NOT_FOUND_OR_DENIED",
            "Named key is unavailable",
            404,
        )

    if record.key_usage != ENCRYPT_DECRYPT:
        raise TransitError(
            "INVALID_KEY_USAGE",
            "Named key is not permitted for encrypt/decrypt operations",
            409,
            {"required_key_usage": ENCRYPT_DECRYPT},
        )
    return record


def list_owned_encryption_keys(owner_email: object) -> list[dict[str, object]]:
    owner = normalize_email(owner_email)
    rows = db.session.scalars(
        select(TransitNamedKey)
        .where(
            TransitNamedKey.owner_email == owner,
            TransitNamedKey.key_usage == ENCRYPT_DECRYPT,
            TransitNamedKey.revoked_at.is_(None),
        )
        .order_by(TransitNamedKey.key_name.asc())
    ).all()
    return [row.to_public_dict() for row in rows]


def bootstrap_demo_key(
    *, owner_email: object, key_name: object = "demo-key"
) -> dict[str, object]:
    """Development-only bridge until Feature 2.1 is merged.

    This deliberately has no public API. The web button is disabled by default
    and must be enabled with ``ENABLE_TRANSIT_DEMO_KEY=true``. It exists only so
    Feature 2.2 can be demonstrated against the real DEK before the teammate's
    named-key management branch lands.
    """

    if not bool(current_app.config.get("ENABLE_TRANSIT_DEMO_KEY", False)):
        raise TransitError("NOT_FOUND", "Endpoint not found", 404)

    owner = normalize_email(owner_email)
    name = validate_key_name(key_name)
    existing = db.session.scalar(
        select(TransitNamedKey).where(
            TransitNamedKey.owner_email == owner,
            TransitNamedKey.key_name == name,
        )
    )
    if existing is not None and existing.revoked_at is None:
        return existing.to_public_dict()

    timestamp = now_timestamp()
    wrapped_material = wrap_key_material(
        owner_email=owner,
        key_name=name,
        key_usage=ENCRYPT_DECRYPT,
        key_material=os.urandom(32),
    )
    if existing is not None:
        existing.key_usage = ENCRYPT_DECRYPT
        existing.encrypted_key_material_b64 = wrapped_material
        existing.updated_at = timestamp
        existing.revoked_at = None
        record = existing
    else:
        record = TransitNamedKey(
            owner_email=owner,
            key_name=name,
            key_usage=ENCRYPT_DECRYPT,
            encrypted_key_material_b64=wrapped_material,
            created_at=timestamp,
            updated_at=timestamp,
            revoked_at=None,
        )
        db.session.add(record)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise TransitError(
            "KEY_ALREADY_EXISTS", "Named key already exists", 409
        ) from exc
    return record.to_public_dict()
