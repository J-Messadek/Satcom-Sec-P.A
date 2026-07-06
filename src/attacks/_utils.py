# =============================================================
# _utils.py – Utilitaires internes partagés par les attaques
#
# Ces helpers reconstruisent un paquet CCSDS valide avec un
# CRC recalculé, simulant ce qu'un attaquant ferait pour que
# le récepteur accepte la trame falsifiée.
# =============================================================

import struct
import binascii
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.config import (
    HEADER_SIZE, CRC_SIZE,
    APID_MASK, SEQ_COUNT_MASK, VERSION_MASK,
    TYPE_MASK, SEC_HDR_MASK, SEQ_FLAGS_MASK,
)


def rebuildPacket(
    apid: int,
    seqFlags: int,
    seqCount: int,
    version: int,
    packetType: int,
    secHdrFlag: int,
    payload: bytes,
) -> bytes:
    """
    Reconstruit un paquet CCSDS complet avec un CRC fraîchement calculé.

    Args:
        apid:        Application Process ID (11 bits).
        seqFlags:    Flags de séquençage (2 bits).
        seqCount:    Compteur de séquence (14 bits).
        version:     Version CCSDS (3 bits).
        packetType:  Type de paquet – 0=TM, 1=TC (1 bit).
        secHdrFlag:  Secondary Header Flag (1 bit).
        payload:     Données utiles brutes.

    Returns:
        Paquet CCSDS complet : header(6) + payload + CRC(2).
    """
    dataLength = len(payload) - 1
    word1 = (
        (version   & VERSION_MASK)   << 13 |
        (packetType & TYPE_MASK)      << 12 |
        (secHdrFlag & SEC_HDR_MASK)   << 11 |
        (apid       & APID_MASK)
    )
    word2 = (seqFlags & SEQ_FLAGS_MASK) << 14 | (seqCount & SEQ_COUNT_MASK)
    header = struct.pack(">HHH", word1, word2, dataLength)
    packet = header + payload
    crc = binascii.crc_hqx(packet, 0xFFFF)
    return packet + struct.pack(">H", crc)


def offsetInStream(packets: list, targetSeq: int) -> int:
    """
    Retourne l'offset en octets du paquet ciblé dans le flux brut.

    Args:
        packets:   Liste de paquets parsés (dicts avec 'seqCount', 'totalSize').
        targetSeq: seqCount du paquet à localiser.

    Returns:
        Offset en octets, ou -1 si non trouvé.
    """
    offset = 0
    for pkt in packets:
        if pkt["seqCount"] == targetSeq:
            return offset
        offset += pkt["totalSize"]
    return -1
