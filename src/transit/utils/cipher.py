
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, padding, utils
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import os
from src.core import vault_obj
import base64
class CipherOperation():
    def __init__(self, vault=None):
        pass
    @classmethod
    def aesgcm(cls, key, nonce, plaintext: bytes, associated_data: bytes | None):
        aesgcm = aead.AESGCM(key) #type:ignore
        encrypted_key = aesgcm.encrypt(nonce, plaintext, associated_data=associated_data)
        return encrypted_key
    
    @classmethod
    def rsa_gen(cls, encrypt_key) -> dict:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        r = {}
        r['private_key'] = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(encrypt_key)
        )
        r['public_key'] = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        return r
    @classmethod
    def rsa_sign(cls, secret_key, key_obj, plaintext_to_sign, is_pre_hash: bool = False):
        if len(plaintext_to_sign) > 4096:
            raise ValueError("Plaintext is too long")
        key: rsa.RSAPrivateKey = serialization.load_pem_private_key(key_obj, secret_key)
        if is_pre_hash:
            signiture = key.sign(
                bytes(plaintext_to_sign, 'utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(hashes.SHA256())
                )
        else:
            signiture = key.sign(
                bytes(plaintext_to_sign, 'utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        return signiture
        
    @classmethod
    def rsa_verify(cls, public_obj, message, signiture, is_prehash: bool = False):
        public_key = serialization.load_pem_public_key(public_obj)
        try:
            public_key.verify(
                signiture,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(hashes.SHA256()) if is_prehash else hashes.SHA256()
            )
        except InvalidSignature:
            return False
        return True

