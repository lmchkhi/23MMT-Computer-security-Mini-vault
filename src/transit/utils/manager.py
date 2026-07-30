from __future__ import annotations

import base64
import binascii
import os
import secrets
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app, has_app_context
from sqlalchemy.exc import IntegrityError

from src.app import db
from src.core import vault_obj
from src.storage.kv.models import NamedKey

from .errors import TransitError
from .misc import validate_key_name


class TransitKeyManager:
    allowed_key_type = ("ENCRYPT_DECRYPT", "SIGN_VERIFY")

    def __init__(self, core_vault=None):
        self.core = vault_obj if core_vault is None else core_vault

    def _active_dek(self) -> bytes:
        """Return the active DEK without persisting or exposing it.

        Tests inject ``TEST_VAULT_DEK`` through Flask config.  Production falls
        back to Feature 0.1's in-memory vault state.  Looking this up on every
        operation also lets a test lock the vault at runtime by setting the
        configured value to ``None``.
        """

        if has_app_context() and "TEST_VAULT_DEK" in current_app.config:
            configured_dek = current_app.config.get("TEST_VAULT_DEK")
            if configured_dek is None:
                raise ValueError("VAULT_LOCKED")
            if not isinstance(configured_dek, (bytes, bytearray)) or len(configured_dek) != 32:
                raise ValueError("INVALID_VAULT_DEK")
            return bytes(configured_dek)

        if self.core.is_locked or self.core.dek is None:
            raise ValueError("VAULT_LOCKED")
        return self.core.dek

    @staticmethod
    def _now() -> int:
        if has_app_context():
            clock = current_app.config.get("TRANSIT_CLOCK", time.time)
            return int(clock())
        return int(time.time())

    def check(self, key_name: object, key_usage: str) -> bytes:
        dek = self._active_dek()
        if key_usage not in self.allowed_key_type:
            raise ValueError("INVALID_KEY_USAGE")
        try:
            validate_key_name(key_name=key_name)
        except TransitError as exc:
            raise ValueError("INVALID_KEY_NAME") from exc
        return dek

    def create_key(
        self,
        key_name: str,
        owner_email: str,
        key_usage: str = "ENCRYPT_DECRYPT",
    ) -> dict[str, object]:
        """Create an AES-256 named key and wrap it with the active DEK."""

        dek = self.check(key_name=key_name, key_usage=key_usage)
        existing_key = NamedKey.query.filter_by(
            key_name=key_name, owner_email=owner_email
        ).first()
        if existing_key:
            raise ValueError(f"Lỗi: Key '{key_name}' đã tồn tại!")

        raw_aes_key = secrets.token_bytes(32)
        nonce = os.urandom(12)
        encrypted_key = AESGCM(dek).encrypt(
            nonce, raw_aes_key, owner_email.encode("utf-8")
        )
        encrypted_key_material_b64 = base64.b64encode(
            nonce + encrypted_key
        ).decode("ascii")

        timestamp = self._now()
        new_key = NamedKey(
            key_name=key_name,
            owner_email=owner_email,
            key_usage=key_usage,
            encrypted_key_material_b64=encrypted_key_material_b64,
            public_key_b64=None,
            created_at=timestamp,
            updated_at=timestamp,
            revoked_at=None,
        )
        db.session.add(new_key)
        try:
            db.session.commit()
        except IntegrityError as exc:
            db.session.rollback()
            raise ValueError(f"Lỗi: Key '{key_name}' đã tồn tại!") from exc

        return {
            "key_name": new_key.key_name,
            "owner_email": new_key.owner_email,
            "key_usage": new_key.key_usage,
            "status": "created",
        }

    def list_keys(
        self, owner_email: str, key_usage: str | None = None
    ) -> list[dict[str, object]]:
        self._active_dek()
        query = NamedKey.query.filter_by(owner_email=owner_email, revoked_at=None)
        if key_usage is not None:
            if key_usage not in self.allowed_key_type:
                raise ValueError("INVALID_KEY_USAGE")
            query = query.filter_by(key_usage=key_usage)

        return [key.to_public_dict() for key in query.all()]

    def read_key(self, key_name: str, key_usage: str, owner_email: str) -> bytes:
        dek = self.check(key_name=key_name, key_usage=key_usage)

        # Query by owner and name first.  This preserves the generic response for
        # cross-user access while still allowing a real usage mismatch to be
        # reported as INVALID_KEY_USAGE to the key owner.
        key = NamedKey.query.filter_by(
            key_name=key_name,
            owner_email=owner_email,
            revoked_at=None,
        ).first()
        if key is None:
            raise ValueError("KEY_NOT_FOUND_OR_DENIED")
        if key.key_usage != key_usage:
            raise ValueError("INVALID_KEY_USAGE")

        try:
            combined = base64.b64decode(
                key.encrypted_key_material_b64, validate=True
            )
        except (binascii.Error, ValueError, TypeError) as exc:
            raise ValueError("KEY_MATERIAL_CORRUPTED") from exc
        if len(combined) < 28:
            raise ValueError("KEY_MATERIAL_CORRUPTED")

        nonce, ciphertext = combined[:12], combined[12:]
        try:
            raw_key = AESGCM(dek).decrypt(
                nonce, ciphertext, owner_email.encode("utf-8")
            )
        except InvalidTag as exc:
            raise ValueError("KEY_MATERIAL_CORRUPTED") from exc
        if len(raw_key) != 32:
            raise ValueError("KEY_MATERIAL_CORRUPTED")
        return raw_key

    def revoke_key(self, key_name: str, owner_email: str) -> dict[str, object]:
        self._active_dek()
        key = NamedKey.query.filter_by(
            key_name=key_name, owner_email=owner_email, revoked_at=None
        ).first()
        if key is None:
            raise ValueError("KEY_NOT_FOUND_OR_DENIED")

        db.session.delete(key)
        db.session.commit()
        return {"status": "revoked", "key_name": key_name}


transit_key_obj = TransitKeyManager()
