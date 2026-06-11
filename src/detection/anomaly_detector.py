# =============================================================
# anomalyDetector.py  –  Défense 2 : Détection d'anomalies
#
# Système de détection combinant :
#   - HMAC-SHA256  : authentifie l'origine et l'intégrité de chaque trame
#   - IDS structurel : détecte les anomalies sur les champs du header
#     (APID inattendu, seqCount incohérent, doublon, injection)
#
# L'HMAC est la défense principale contre l'Attaque 2 :
#   → Même si l'attaquant recalcule le CRC, il ne peut pas
#     produire un HMAC valide sans connaître la clé secrète.
#
# Référence rapport académique :
#   "Validation CRC-32 + authentification HMAC des en-têtes →
#    Détection 100% des altérations testées."
# =============================================================

import hmac
import hashlib
import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.receiver.frameParser import HEADER_SIZE

# ---- Constants -----------------------------------------------
HMAC_SIZE = 32    # SHA-256 → 32 bytes


# ==============================================================
# HMAC tag generation & verification
# ==============================================================

def computeHmacTag(rawHeader: bytes, payload: bytes, key: bytes) -> bytes:
    """
    Compute HMAC-SHA256 over the 6-byte header + payload.

    Args:
        rawHeader: Exactly 6 raw header bytes.
        payload:   Payload bytes.
        key:       Shared secret key (bytes).

    Returns:
        32-byte HMAC digest.
    """
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(rawHeader)
    mac.update(payload)
    return mac.digest()


def verifyHmacTag(rawHeader: bytes, payload: bytes,
                  receivedTag: bytes, key: bytes) -> bool:
    """
    Verify the HMAC tag of a received packet.
    Uses constant-time comparison to prevent timing attacks.

    Returns:
        True → packet is authentic (not altered).
        False → packet has been tampered with.
    """
    expectedTag = computeHmacTag(rawHeader, payload, key)
    return hmac.compare_digest(expectedTag, receivedTag)


# ==============================================================
# Build a stream with HMAC tags embedded
# ==============================================================

def tagStream(rawStream: bytes, key: bytes) -> list[dict]:
    """
    Parse a stream and attach an HMAC tag to each packet dict.
    Called on the transmitter side before sending.

    Args:
        rawStream: Raw bytes from the transmitter.
        key:       Shared HMAC key.

    Returns:
        List of packet dicts with 'hmacTag' field added.
    """
    from src.receiver.frameParser import parseStream
    packets = parseStream(rawStream)
    tagged  = []
    offset  = 0
    for pkt in packets:
        rawHeader = rawStream[offset: offset + HEADER_SIZE]
        tag       = computeHmacTag(rawHeader, pkt["payload"], key)
        tagged.append({**pkt, "hmacTag": tag, "_rawHeader": rawHeader})
        offset += pkt["totalSize"]
    return tagged


# ==============================================================
# IDS – structural anomaly detection (without HMAC key)
# ==============================================================

def detectStructuralAnomalies(packets: list[dict],
                               expectedApid: int = None) -> list[dict]:
    """
    Stateless structural checks on a list of parsed packets.
    Does NOT require the HMAC key — useful as a first-pass filter.

    Checks performed:
      - CRC validity
      - Unexpected APID (if expectedApid provided)
      - Duplicate seqCount
      - Out-of-order seqCount jumps (gap > 1)

    Args:
        packets:      List of parsed packet dicts.
        expectedApid: If set, flag packets with a different APID.

    Returns:
        List of alert dicts with keys 'seqCount', 'type', 'detail'.
    """
    alerts        = []
    seenSeqCounts = set()
    prevSeq       = None

    for pkt in packets:
        seq = pkt["seqCount"]

        # 1. CRC failure
        if not pkt.get("crcValid", False):
            alerts.append({
                "seqCount": seq,
                "type":     "CRC_FAIL",
                "detail":   f"CRC mismatch: received={pkt.get('receivedCrc'):#06x} "
                            f"computed={pkt.get('computedCrc'):#06x}"
            })

        # 2. APID mismatch
        if expectedApid is not None and pkt["apid"] != expectedApid:
            alerts.append({
                "seqCount": seq,
                "type":     "APID_SPOOF",
                "detail":   f"Unexpected APID {pkt['apid']} (expected {expectedApid})"
  })

        # 3. Duplicate sequence number
        if seq in seenSeqCounts:
            alerts.append({
                "seqCount": seq,
                "type":     "DUPLICATE_SEQ",
                "detail":   f"seqCount={seq} seen more than once (replay?)"
            })
        seenSeqCounts.add(seq)

        # 4. Non-contiguous sequence (gap > 1)
        if prevSeq is not None and seq != prevSeq + 1:
            gap = seq - prevSeq
            if gap > 1:
                alerts.append({
                    "seqCount": seq,
                    "type":     "SEQ_GAP",
                    "detail":   f"Gap of {gap - 1} between seqCount={prevSeq} and {seq}"
                })
            elif gap < 0:
                alerts.append({
                    "seqCount": seq,
                    "type":     "SEQ_REORDER",
                    "detail":   f"Out-of-order: seqCount={seq} after {prevSeq}"
                })
        prevSeq = seq

    return alerts


# ==============================================================
# Full verification pipeline (HMAC + structural IDS)
# ==============================================================

def verifyStream(rawStream: bytes, taggedPackets: list[dict],
                 key: bytes, expectedApid: int = None) -> dict:
    """
    Full defense pipeline: HMAC verification + structural IDS.

    Args:
        rawStream:      The stream received from the channel
                        (possibly tampered by an attacker).
        taggedPackets:  Original packets with HMAC tags (from transmitter).
        key:            Shared HMAC key.
        expectedApid:   Expected APID for structural checks.

    Returns:
        dict with keys:
          'allValid'         (bool)  – True only if all HMAC checks pass
          'hmacAlerts'       (list)  – packets that failed HMAC
          'structuralAlerts' (list)  – structural anomalies detected
          'verifiedPackets'  (list) – packets that passed all checks
    """
    from src.receiver.frameParser import parseStream

    receivedPackets = parseStream(rawStream)
    structAlerts    = detectStructuralAnomalies(receivedPackets, expectedApid)
    hmacAlerts      = []
    verifiedPackets = []

    # Build a lookup of HMAC tags by seqCount
    tagMap = {p["seqCount"]: p for p in taggedPackets}

    offset = 0
    for pkt in receivedPackets:
        rawHeader = rawStream[offset: offset + HEADER_SIZE]
        seq       = pkt["seqCount"]
        offset   += pkt["totalSize"]

        if seq not in tagMap:
            hmacAlerts.append({
                "seqCount": seq,
                "type":    "HMAC_UNKNOWN",
                "detail":  f"seqCount={seq} has no known HMAC tag (injected?)"
  })
            continue

        expectedTag = tagMap[seq]["hmacTag"]
        if not verifyHmacTag(rawHeader, pkt["payload"], expectedTag, key):
            hmacAlerts.append({
                "seqCount": seq,
                "type":    "HMAC_FAIL",
                "detail":  f"seqCount={seq} HMAC mismatch — packet was tampered"
            })
        else:
            verifiedPackets.append(pkt)

    return {
        "allValid":          len(hmacAlerts) == 0,
        "hmacAlerts":        hmacAlerts,
        "structuralAlerts":  structAlerts,
        "verifiedPackets":   verifiedPackets,
    }
