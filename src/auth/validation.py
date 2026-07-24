from __future__ import annotations

import re

EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def normalize_email(email: object) -> str:
    if not isinstance(email, str):
        return ""
    return email.strip().lower()


def validate_email(email: str) -> list[str]:
    if not email:
        return ["Email is required"]
    if len(email) > 254:
        return ["Email is too long"]
    if not EMAIL_PATTERN.fullmatch(email):
        return ["Email format is invalid"]
    return []


def validate_passphrase(passphrase: object) -> list[str]:
    if not isinstance(passphrase, str):
        return ["Passphrase is required"]

    errors: list[str] = []
    if len(passphrase) < 12:
        errors.append("Passphrase must contain at least 12 characters")
    if not any(character.islower() for character in passphrase):
        errors.append("Passphrase must contain a lowercase letter")
    if not any(character.isupper() for character in passphrase):
        errors.append("Passphrase must contain an uppercase letter")
    if not any(character.isdigit() for character in passphrase):
        errors.append("Passphrase must contain a number")
    if not any(
        not character.isalnum() and not character.isspace()
        for character in passphrase
    ):
        errors.append("Passphrase must contain a special character")
    return errors
