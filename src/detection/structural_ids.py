# =============================================================
# structural_ids.py – Défense 2 / Module 2 : IDS structurel CCSDS
#
# Analyse la structure d'un flux de paquets CCSDS pour détecter
# des anomalies comportementales indépendamment du HMAC :
#   – CRC invalide           (CRC_FAIL)
#   – APID inattendu         (APID_SPOOF)
#   – Numéro de séquence dup (DUPLICATE_SEQ)
#   – Saut de séquence       (SEQ_GAP)
#   – Paquet hors-ordre      (SEQ_REORDER)
# =============================================================

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.config import (
    ALERT_CRC_FAIL, ALERT_APID_SPOOF,
    ALERT_DUPLICATE_SEQ, ALERT_SEQ_GAP, ALERT_SEQ_REORDER,
)


def detectStructuralAnomalies(
    packets: list,
    expectedApid: int | None = None,
) -> list:
    """
    Analyse un flux de paquets parsés et retourne les alertes structurelles.

    Fonctionne sur les dicts retournés par frameParser.parseStream().
    Ne nécessite aucune clé cryptographique — c'est un IDS passif.

    Args:
        packets:      Liste de paquets parsés (dicts).
        expectedApid: APID autorisé. Si None, l'APID n'est pas vérifié.

    Returns:
        Liste d'alertes, chacune étant un dict :
        {
            "type":     str   – type d'alerte (ALERT_*),
            "seqCount": int   – seqCount du paquet incriminé,
            "detail":   str   – message explicatif,
        }
    """
    alerts      = []
    seenSeqs    = set()
    prevSeq     = None

    for pkt in packets:
        seq = pkt["seqCount"]

        # --- CRC_FAIL ---
        if not pkt.get("crcValid", False):
            alerts.append({
                "type":     ALERT_CRC_FAIL,
                "seqCount": seq,
                "detail":   f"reçu {pkt.get('receivedCrc'):#06x}, calculé {pkt.get('computedCrc'):#06x}",
            })

        # --- APID_SPOOF ---
        if expectedApid is not None and pkt["apid"] != expectedApid:
            alerts.append({
                "type":     ALERT_APID_SPOOF,
                "seqCount": seq,
                "detail":   f"APID {pkt['apid']} ≠ attendu {expectedApid}",
            })

        # --- DUPLICATE_SEQ ---
        if seq in seenSeqs:
            alerts.append({
                "type":     ALERT_DUPLICATE_SEQ,
                "seqCount": seq,
                "detail":   f"seqCount={seq} déjà vu",
            })

        # --- SEQ_GAP & SEQ_REORDER ---
        if prevSeq is not None:
            expected = (prevSeq + 1) & 0x3FFF   # wrap-around 14 bits
            if seq != expected:
                alertType = ALERT_SEQ_GAP if seq > prevSeq else ALERT_SEQ_REORDER
                alerts.append({
                    "type":     alertType,
                    "seqCount": seq,
                    "detail":   f"attendu {expected}, reçu {seq} (précédent {prevSeq})",
                })

        seenSeqs.add(seq)
        prevSeq = seq

    return alerts
