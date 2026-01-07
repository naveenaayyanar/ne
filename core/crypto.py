"""
High-security cryptographic primitives for NE Steganography Suite.

Requirements (recommended):
 - cryptography
 - argon2-cffi
 - secrets

This module provides:
 - Argon2id KDF (via argon2-cffi)
 - AES-256-GCM authenticated encryption
 - Optional RSA key generation + hybrid-wrap utilities
 - Secure memory wiping helpers

Security notes:
 - All secrets are handled as bytes.
 - Use Argon2id with high memory/time params for defense-in-depth.
 - AES-GCM provides confidentiality + integrity; HMAC used for
   ancillary integrity checks where needed.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from argon2.low_level import hash_secret_raw, Type
import secrets
import os
import ctypes
from typing import Tuple

# Argon2id recommended parameters (tunable)
ARGON2_TIME_COST = 4          # iterations
ARGON2_MEMORY_COST = 1 << 18  # 256 MB (adjust according to target machines)
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32          # bytes


def derive_key(password: bytes, salt: bytes = None,
               time_cost=ARGON2_TIME_COST,
               memory_cost=ARGON2_MEMORY_COST,
               parallelism=ARGON2_PARALLELISM,
               hash_len=ARGON2_HASH_LEN) -> Tuple[bytes, bytes]:
    """
    Derive a symmetric key from a password using Argon2id.
    Returns (key, salt). If salt is None a new random 16-byte salt is returned.
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID
    )
    return key, salt


def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b'') -> Tuple[bytes, bytes]:
    """
    AES-256-GCM encryption.
    Returns (nonce, ciphertext_with_tag)
    """
    if len(key) != 32:
        raise ValueError("AES-GCM key must be 32 bytes (AES-256).")
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit recommended
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ct


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b'') -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def generate_rsa_keypair(bits: int = 4096) -> Tuple[bytes, bytes]:
    """
    Generate RSA keypair for optional key exchange.
    Returns (private_pem, public_pem) as bytes in PEM format.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


def rsa_wrap_key(pub_pem: bytes, key_to_wrap: bytes) -> bytes:
    """
    Wrap (encrypt) symmetric key using recipient's RSA public key (OAEP-SHA256).
    """
    pub = serialization.load_pem_public_key(pub_pem)
    wrapped = pub.encrypt(
        key_to_wrap,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped


def rsa_unwrap_key(priv_pem: bytes, wrapped_key: bytes) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    key = priv.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return key


def secure_wipe(b: bytearray):
    """
    Attempt to zero memory of a mutable bytearray. Best-effort.
    """
    if not isinstance(b, (bytearray, memoryview)):
        raise TypeError("secure_wipe expects a bytearray or memoryview")
    for i in range(len(b)):
        b[i] = 0
    # Attempt to prevent optimization away
    ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(b)), 0, len(b))
