from __future__ import annotations

import re

EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def normalize_email(email: object) -> str:
    if not isinstance(email, str):
        return ""
    return email.strip().lower()


def validate_email(email: str) -> list[str]:
    """
    Validate the given input is a valid email

    Requirement for a valid email:
    - Email is not empty string
    - Email is not too long (> 254)
    - Input email have email format
    
    Args:
        email (str): input string to be check

    Returns:
        list[str]: list of error message
    """
    # Email need to be given be correct length and is a valid email
    if not email:
        return ["Email is required"]
    
    if len(email) > 254:
        return ["Email is too long"]
    
    if not EMAIL_PATTERN.fullmatch(email):
        return ["Email format is invalid"]
    
    # Validate is complete and there is not error (though the commenter would use another way to return error)
    return []


def validate_passphrase(passphrase: object) -> list[str]:
    """
    Validate a passphrase and return a list of validation errors.

    Requirements:
    - Must be a string
    - Must be at least 12 characters long
    - Must contain at least one lowercase letter
    - Must contain at least one uppercase letter
    - Must contain at least one digit
    - Must contain at least one special character
    """
    
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
