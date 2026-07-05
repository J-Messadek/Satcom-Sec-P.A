"""Chiffrement symétrique AES-256-CBC : confidentialité du flux, sans authentification.

Complète la Défense 2 (HMAC + IDS) : l'authentification protège l'intégrité d'un flux
en clair, tandis qu'AES-256-CBC protège la confidentialité. Les deux mécanismes sont
indépendants — chiffrer ne remplace pas l'authentification (voir `tamper_and_decrypt`,
qui montre qu'une altération du flux chiffré se déchiffre "silencieusement", sans erreur
détectable côté récepteur si aucun HMAC n'est vérifié en plus)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

KEY_SIZE = 32  # AES-256 : clé de 32 octets
BLOCK_SIZE = AES.block_size  # 16 octets


def derive_key(passphrase: str) -> bytes:
    """Dérive une clé AES-256 à partir d'une phrase secrète.

    Démo pédagogique : un simple SHA-256 de la phrase. En production, préférer une
    fonction de dérivation dédiée (PBKDF2, scrypt, Argon2) avec un sel aléatoire."""
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
    """Chiffre `plaintext` en AES-256-CBC (padding PKCS7). Retourne (iv, ciphertext)."""
    iv = iv if iv is not None else get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(plaintext, BLOCK_SIZE))


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Déchiffre un flux AES-256-CBC et retire le padding PKCS7.

    Lève ValueError si le padding est invalide (signe d'une altération du ciphertext,
    ou d'une mauvaise clé/IV) : CBC seul ne garantit pas l'intégrité, il ne fait que
    parfois la trahir via une erreur de padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)


def decrypt_raw(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Déchiffre sans retirer le padding, pour visualiser un flux même altéré."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)


@dataclass
class TamperResult:
    ciphertext: bytes
    byte_index: int
    recovered: bytes
    padding_valid: bool
    corrupted_blocks: tuple[int, int]


def tamper_and_decrypt(ciphertext: bytes, key: bytes, iv: bytes, byte_index: int) -> TamperResult:
    """Simule l'altération d'un octet du ciphertext en transit (bruit ou MITM), puis déchiffre.

    Illustre la propagation d'erreur propre au mode CBC : le bloc directement modifié est
    entièrement détruit au déchiffrement, le bloc suivant subit un flip du même bit
    (diffusion en chaîne via le XOR différé), et le reste du message reste intact."""
    tampered = bytearray(ciphertext)
    tampered[byte_index] ^= 0xFF
    tampered = bytes(tampered)

    raw = decrypt_raw(tampered, key, iv)
    try:
        recovered = unpad(raw, BLOCK_SIZE)
        padding_valid = True
    except ValueError:
        recovered = raw
        padding_valid = False

    block = byte_index // BLOCK_SIZE
    return TamperResult(
        ciphertext=tampered,
        byte_index=byte_index,
        recovered=recovered,
        padding_valid=padding_valid,
        corrupted_blocks=(block, block + 1),
    )
