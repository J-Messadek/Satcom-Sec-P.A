# =============================================================
# hmac_auth.py – Défense 2 / Module 1 : Authentification HMAC-SHA256
#
# Fournit les primitives cryptographiques pour tagguer et vérifier
# l'intégrité des paquets CCSDS. Chaque paquet reçoit un tag
# HMAC-SHA256 calculé sur (en-tête brut ‖ payload).
#
# Principe :
#   Tx : tag = HMAC(key, rawHeader ‖ payload)  → transmis hors-bande
#   Rx : recompute tag, compare en temps constant → accepte ou rejette
# =============================================================

import hmac
import hashlib
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.config import DEFAULT_HMAC_KEY, HMAC_DIGEST_SIZE


def computeHmacTag(
    rawHeader: bytes,
    payload: bytes,
    key: bytes = DEFAULT_HMAC_KEY,
) -> bytes:
    """
    Calcule le tag HMAC-SHA256 d'un paquet CCSDS.

    Le matériau authentifié est la concaténation de l'en-tête primaire
    brut (6 octets) et du payload, ce qui couvre l'intégralité des
    champs fonctionnels du paquet (APID, seqCount, données).

    Args:
        rawHeader:  En-tête primaire CCSDS brut (6 octets).
        payload:    Données utiles du paquet.
        key:        Clé HMAC secrète (défaut : DEFAULT_HMAC_KEY).

    Returns:
        Tag HMAC-SHA256 de 32 octets.
    """
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(rawHeader)
    mac.update(payload)
    return mac.digest()


def verifyHmacTag(
    rawHeader: bytes,
    payload: bytes,
    receivedTag: bytes,
    key: bytes = DEFAULT_HMAC_KEY,
) -> bool:
    """
    Vérifie un tag HMAC-SHA256 en comparaison en temps constant.

    La comparaison en temps constant (hmac.compare_digest) empêche
    les attaques par timing qui exploiteraient un simple == octet par octet.

    Args:
        rawHeader:   En-tête primaire CCSDS brut (6 octets).
        payload:     Données utiles du paquet.
        receivedTag: Tag reçu à vérifier (32 octets).
        key:         Clé HMAC secrète.

    Returns:
        True si le tag est valide, False sinon.
    """
    expected = computeHmacTag(rawHeader, payload, key)
    return hmac.compare_digest(expected, receivedTag)
