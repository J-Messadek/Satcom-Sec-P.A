# =============================================================
# stream_pipeline.py – Défense 2 / Module 3 : Pipeline Tx/Rx HMAC
#
# Orchestre le tagging côté émetteur et la vérification côté
# récepteur sur un flux complet de paquets CCSDS.
#
#   Tx : tagStream(rawStream, key)
#        → liste de paquets avec leur tag HMAC, transmis hors-bande
#
#   Rx : verifyStream(rawStream, taggedPackets, key, expectedApid)
#        → rapport complet : validité globale, alertes HMAC, alertes IDS
# =============================================================

import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.config import DEFAULT_HMAC_KEY, ALERT_HMAC_FAIL, ALERT_HMAC_UNKNOWN
from src.receiver.frame_parser import parse_stream, HEADER_SIZE
from src.detection.hmac_auth import computeHmacTag, verifyHmacTag
from src.detection.structural_ids import detectStructuralAnomalies


def tagStream(
    rawStream: bytes,
    key: bytes = DEFAULT_HMAC_KEY,
) -> list:
    """
    Côté émetteur : calcule un tag HMAC pour chaque paquet du flux.

    Retourne une liste de dicts contenant les métadonnées du paquet
    et son tag HMAC, destinés à être transmis hors-bande au récepteur.

    Args:
        rawStream:  Flux de paquets CCSDS bruts.
        key:        Clé HMAC secrète.

    Returns:
        Liste de dicts :
        {
            "seqCount":  int,
            "apid":      int,
            "hmacTag":   bytes (32 octets),
            "_rawHeader": bytes (6 octets, usage interne),
        }
    """
    packets = parse_stream(rawStream)
    tagged  = []

    for pkt in packets:
        rawHeader = struct.pack(
            ">HHH",
            (pkt["version"] & 0x07) << 13 |
            (pkt["packetType"] & 0x01) << 12 |
            (pkt["secHdrFlag"] & 0x01) << 11 |
            (pkt["apid"] & 0x7FF),
            (pkt["seqFlags"] & 0x03) << 14 | (pkt["seqCount"] & 0x3FFF),
            len(pkt["payload"]) - 1,
        )
        tag = computeHmacTag(rawHeader, pkt["payload"], key)
        tagged.append({
            "seqCount":   pkt["seqCount"],
            "apid":       pkt["apid"],
            "hmacTag":    tag,
            "_rawHeader": rawHeader,
        })

    return tagged


def verifyStream(
    rawStream: bytes,
    taggedPackets: list,
    key: bytes = DEFAULT_HMAC_KEY,
    expectedApid: int | None = None,
) -> dict:
    """
    Côté récepteur : vérifie chaque paquet du flux contre son tag HMAC.

    Compare chaque paquet reçu avec le tag hors-bande correspondant.
    Complète la vérification par l'IDS structurel.

    Args:
        rawStream:      Flux de paquets CCSDS reçus (potentiellement altérés).
        taggedPackets:  Tags hors-bande produits par tagStream().
        key:            Clé HMAC secrète.
        expectedApid:   APID autorisé (optionnel, pour l'IDS).

    Returns:
        {
            "allValid":         bool  – True si aucune anomalie détectée,
            "hmacAlerts":       list  – alertes HMAC (HMAC_FAIL / HMAC_UNKNOWN),
            "structuralAlerts": list  – alertes IDS structurel,
            "verifiedPackets":  list  – paquets valides uniquement,
        }
    """
    receivedPkts = parse_stream(rawStream)

    # Index des tags hors-bande par seqCount
    tagMap = {t["seqCount"]: t for t in taggedPackets}

    hmacAlerts      = []
    verifiedPackets = []

    for pkt in receivedPkts:
        seq = pkt["seqCount"]
        rawHeader = struct.pack(
            ">HHH",
            (pkt["version"] & 0x07) << 13 |
            (pkt["packetType"] & 0x01) << 12 |
            (pkt["secHdrFlag"] & 0x01) << 11 |
            (pkt["apid"] & 0x7FF),
            (pkt["seqFlags"] & 0x03) << 14 | (seq & 0x3FFF),
            len(pkt["payload"]) - 1,
        )

        if seq not in tagMap:
            # Paquet inconnu : injection potentielle
            hmacAlerts.append({
                "type":     ALERT_HMAC_UNKNOWN,
                "seqCount": seq,
                "detail":   f"seqCount={seq} absent du tag map (injection ?)",
            })
        else:
            knownTag = tagMap[seq]["hmacTag"]
            if not verifyHmacTag(rawHeader, pkt["payload"], knownTag, key):
                hmacAlerts.append({
                    "type":     ALERT_HMAC_FAIL,
                    "seqCount": seq,
                    "detail":   f"seqCount={seq} : tag HMAC invalide (contenu altéré)",
                })
            else:
                verifiedPackets.append(pkt)

    structuralAlerts = detectStructuralAnomalies(receivedPkts, expectedApid)

    return {
        "allValid":         len(hmacAlerts) == 0 and len(structuralAlerts) == 0,
        "hmacAlerts":       hmacAlerts,
        "structuralAlerts": structuralAlerts,
        "verifiedPackets":  verifiedPackets,
    }
