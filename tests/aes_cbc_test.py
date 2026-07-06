# =============================================================
# aes_cbc_test.py – Chiffrement AES-256-CBC (src.crypto.aes_cbc)
#
# Valide le round-trip chiffrement/déchiffrement, la dérivation de
# clé, et la propagation d'erreur caractéristique du mode CBC en
# cas d'altération du ciphertext (bit-flip / MITM).
#
# Lancer depuis la racine du dépôt : pytest
# =============================================================

import pytest

from src.crypto.aes_cbc import (
    KEY_SIZE,
    BLOCK_SIZE,
    derive_key,
    encrypt,
    decrypt,
    decrypt_raw,
    tamper_and_decrypt,
)


def test_derive_key_length():
    key = derive_key("correct horse battery staple")
    assert len(key) == KEY_SIZE == 32


def test_roundtrip_text():
    key = derive_key("ma-cle-secrete")
    plaintext = b"Commande satellite : ouverture du panneau solaire."
    iv, ciphertext = encrypt(plaintext, key)

    assert len(iv) == BLOCK_SIZE
    assert ciphertext != plaintext
    assert decrypt(ciphertext, key, iv) == plaintext


def test_roundtrip_binary_image_like_payload():
    key = derive_key("clef-image")
    plaintext = bytes(range(256)) * 20  # ressemble à un flux de pixels
    iv, ciphertext = encrypt(plaintext, key)

    assert len(ciphertext) % BLOCK_SIZE == 0
    assert decrypt(ciphertext, key, iv) == plaintext


def test_wrong_key_fails_or_garbles():
    key = derive_key("bonne-cle")
    wrong_key = derive_key("mauvaise-cle")
    plaintext = b"Donnee sensible" * 4
    iv, ciphertext = encrypt(plaintext, key)

    with pytest.raises(ValueError):
        decrypt(ciphertext, wrong_key, iv)

    # Sans retrait du padding, le déchiffrement "réussit" mais produit du bruit.
    garbled = decrypt_raw(ciphertext, wrong_key, iv)
    assert garbled != plaintext


def test_tamper_corrupts_two_blocks_only():
    key = derive_key("clef-tamper")
    # 3 blocs bien remplis pour observer clairement la propagation d'erreur.
    plaintext = (b"A" * BLOCK_SIZE) + (b"B" * BLOCK_SIZE) + (b"C" * BLOCK_SIZE)
    iv, ciphertext = encrypt(plaintext, key)

    # On altère un octet du 1er bloc chiffré.
    result = tamper_and_decrypt(ciphertext, key, iv, byte_index=2)

    assert result.corrupted_blocks == (0, 1)
    recovered = result.recovered
    # Bloc 0 : entièrement détruit par le déchiffrement du bloc altéré.
    assert recovered[0:BLOCK_SIZE] != plaintext[0:BLOCK_SIZE]
    # Bloc 1 : un seul bit diffère (XOR différé propre à CBC).
    diff = sum(a != b for a, b in zip(recovered[BLOCK_SIZE:2 * BLOCK_SIZE],
                                      plaintext[BLOCK_SIZE:2 * BLOCK_SIZE]))
    assert diff == 1
    # Bloc 2 (et au-delà) : intact, CBC ne propage pas plus loin qu'un bloc.
    assert recovered[2 * BLOCK_SIZE:3 * BLOCK_SIZE] == plaintext[2 * BLOCK_SIZE:3 * BLOCK_SIZE]


def test_tamper_last_block_breaks_padding():
    key = derive_key("clef-tamper-2")
    plaintext = b"message court"
    iv, ciphertext = encrypt(plaintext, key)

    result = tamper_and_decrypt(ciphertext, key, iv, byte_index=len(ciphertext) - 1)
    assert result.padding_valid is False
