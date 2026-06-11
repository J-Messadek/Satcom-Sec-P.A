# =============================================================
# anomaly_detector.py  –  Défense 2 : Détection d'anomalies
#
# Système de détection combinant :
#   - HMAC-SHA256   : authentifie l'origine et l'intégrité de chaque trame
#   - IDS structurel : détecte les anomalies sur les champs du header
#     (APID inattendu, seqCount incohérent, doublon, injection)
#
# L'HMAC est la défense principale contre l'Attaque 2 : même si l'attaquant
# recalcule le CRC, il ne peut pas produire un HMAC valide sans la clé secrète.
# =============================================================

import hmac
import hashlib

from ..receiver.frame_parser import parse_stream, HEADER_SIZE

# ---- Constants -----------------------------------------------
HMAC_SIZE = 32  # SHA-256 → 32 bytes


# ==============================================================
# HMAC tag generation & verification
# ==============================================================

def compute_hmac_tag(raw_header: bytes, payload: bytes, key: bytes) -> bytes:
    """Compute HMAC-SHA256 over the 6-byte header + payload (32-byte digest)."""
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(raw_header)
    mac.update(payload)
    return mac.digest()


def verify_hmac_tag(raw_header: bytes, payload: bytes,
                    received_tag: bytes, key: bytes) -> bool:
    """
    Verify the HMAC tag of a received packet (constant-time comparison).

    Returns:
        True  → packet is authentic (not altered).
        False → packet has been tampered with.
    """
    expected_tag = compute_hmac_tag(raw_header, payload, key)
    return hmac.compare_digest(expected_tag, received_tag)


# ==============================================================
# Build a stream with HMAC tags embedded
# ==============================================================

def tag_stream(raw_stream: bytes, key: bytes) -> list[dict]:
    """
    Parse a stream and attach an HMAC tag to each packet dict.
    Called on the transmitter side before sending.
    """
    packets = parse_stream(raw_stream)
    tagged = []
    offset = 0
    for pkt in packets:
        raw_header = raw_stream[offset : offset + HEADER_SIZE]
        tag = compute_hmac_tag(raw_header, pkt["payload"], key)
        tagged.append({**pkt, "hmacTag": tag, "_rawHeader": raw_header})
        offset += pkt["totalSize"]
    return tagged


# ==============================================================
# IDS – structural anomaly detection (without HMAC key)
# ==============================================================

def detect_structural_anomalies(packets: list[dict],
                                expected_apid: int = None) -> list[dict]:
    """
    Stateless structural checks on a list of parsed packets.
    Does NOT require the HMAC key — useful as a first-pass filter.

    Checks: CRC validity, unexpected APID, duplicate seqCount,
    out-of-order / gapped seqCount.

    Returns:
        List of alert dicts with keys 'seqCount', 'type', 'detail'.
    """
    alerts = []
    seen_seq_counts = set()
    prev_seq = None

    for pkt in packets:
        seq = pkt["seqCount"]

        # 1. CRC failure
        if not pkt.get("crcValid", False):
            alerts.append({
                "seqCount": seq,
                "type": "CRC_FAIL",
                "detail": f"CRC mismatch: received={pkt.get('receivedCrc'):#06x} "
                          f"computed={pkt.get('computedCrc'):#06x}",
            })

        # 2. APID mismatch
        if expected_apid is not None and pkt["apid"] != expected_apid:
            alerts.append({
                "seqCount": seq,
                "type": "APID_SPOOF",
                "detail": f"Unexpected APID {pkt['apid']} (expected {expected_apid})",
            })

        # 3. Duplicate sequence number
        if seq in seen_seq_counts:
            alerts.append({
                "seqCount": seq,
                "type": "DUPLICATE_SEQ",
                "detail": f"seqCount={seq} seen more than once (replay?)",
            })
        seen_seq_counts.add(seq)

        # 4. Non-contiguous sequence (gap > 1 or reorder)
        if prev_seq is not None and seq != prev_seq + 1:
            gap = seq - prev_seq
            if gap > 1:
                alerts.append({
                    "seqCount": seq,
                    "type": "SEQ_GAP",
                    "detail": f"Gap of {gap - 1} between seqCount={prev_seq} and {seq}",
                })
            elif gap < 0:
                alerts.append({
                    "seqCount": seq,
                    "type": "SEQ_REORDER",
                    "detail": f"Out-of-order: seqCount={seq} after {prev_seq}",
                })
        prev_seq = seq

    return alerts


# ==============================================================
# Full verification pipeline (HMAC + structural IDS)
# ==============================================================

def verify_stream(raw_stream: bytes, tagged_packets: list[dict],
                  key: bytes, expected_apid: int = None) -> dict:
    """
    Full defense pipeline: HMAC verification + structural IDS.

    Returns:
        dict with keys:
          'allValid'         (bool)  – True only if all HMAC checks pass
          'hmacAlerts'       (list)  – packets that failed HMAC
          'structuralAlerts' (list)  – structural anomalies detected
          'verifiedPackets'  (list)  – packets that passed all checks
    """
    received_packets = parse_stream(raw_stream)
    struct_alerts = detect_structural_anomalies(received_packets, expected_apid)
    hmac_alerts = []
    verified_packets = []

    # Lookup of HMAC tags by seqCount.
    tag_map = {p["seqCount"]: p for p in tagged_packets}

    offset = 0
    for pkt in received_packets:
        raw_header = raw_stream[offset : offset + HEADER_SIZE]
        seq = pkt["seqCount"]
        offset += pkt["totalSize"]

        if seq not in tag_map:
            hmac_alerts.append({
                "seqCount": seq,
                "type": "HMAC_UNKNOWN",
                "detail": f"seqCount={seq} has no known HMAC tag (injected?)",
            })
            continue

        expected_tag = tag_map[seq]["hmacTag"]
        if not verify_hmac_tag(raw_header, pkt["payload"], expected_tag, key):
            hmac_alerts.append({
                "seqCount": seq,
                "type": "HMAC_FAIL",
                "detail": f"seqCount={seq} HMAC mismatch — packet was tampered",
            })
        else:
            verified_packets.append(pkt)

    return {
        "allValid": len(hmac_alerts) == 0,
        "hmacAlerts": hmac_alerts,
        "structuralAlerts": struct_alerts,
        "verifiedPackets": verified_packets,
    }
