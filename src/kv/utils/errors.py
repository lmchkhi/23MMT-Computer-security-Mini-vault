from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class KvAccessError(Exception):
    code: str
    message: str
    status_code: int
    details: dict[str, Any] = field(default_factory=dict)

    def to_response(self) -> tuple[dict[str, object], int]:
        error: dict[str, object] = {"code": self.code, "message": self.message}
        if self.details:
            error["details"] = self.details
        return {"error": error}, self.status_code
