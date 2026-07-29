from __future__ import annotations

from sqlalchemy import BigInteger, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from src.extensions import db


class TransitNamedKey(db.Model):
    """Shared persistence contract between Feature 2.1 and Feature 2.2.

    Feature 2.2 only consumes these records. Key creation, listing, and revocation
    APIs remain Feature 2.1's responsibility. The encrypted key material is never
    returned by this model's public representation.
    """

    __tablename__ = "transit_named_keys"
    __table_args__ = (
        UniqueConstraint(
            "owner_email", "key_name", name="uq_transit_owner_key_name"
        ),
        Index("idx_transit_named_keys_owner", "owner_email"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_email: Mapped[str] = mapped_column(String(254), nullable=False)
    key_name: Mapped[str] = mapped_column(String(64), nullable=False)
    key_usage: Mapped[str] = mapped_column(String(32), nullable=False)
    encrypted_key_material_b64: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    def to_public_dict(self) -> dict[str, object]:
        return {
            "key_name": self.key_name,
            "owner_email": self.owner_email,
            "key_usage": self.key_usage,
            "revoked": self.revoked_at is not None,
            "created_at": self.created_at,
        }
