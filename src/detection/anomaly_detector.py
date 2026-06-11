"""Défense 2 — authentification HMAC-SHA256 + IDS structurel.

Le HMAC est la défense principale : sans la clé secrète, l'attaquant ne peut pas
produire une empreinte valide, même en reforgeant le CRC."""

import hmac
import hashlib

from ..receiver.frame_parser import parse_stream, HEADER_SIZE


def compute_hmac_tag(raw_header: bytes, payload: bytes, key: bytes) -> bytes:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(raw_header)
    mac.update(payload)
    return mac.digest()


def verify_hmac_tag(raw_header: bytes, payload: bytes, received_tag: bytes, key: bytes) -> bool:
    return hmac.compare_digest(compute_hmac_tag(raw_header, payload, key), received_tag)


def tag_stream(raw_stream: bytes, key: bytes) -> list[dict]:
    """Côté émetteur : associe une empreinte HMAC à chaque trame."""
    packets = parse_stream(raw_stream)
    tagged = []
    offset = 0
    for pkt in packets:
        raw_header = raw_stream[offset : offset + HEADER_SIZE]
        tagged.append({**pkt, "hmacTag": compute_hmac_tag(raw_header, pkt["payload"], key)})
        offset += pkt["totalSize"]
    return tagged


def detect_structural_anomalies(packets: list[dict], expected_apid: int = None) -> list[dict]:
    """Contrôles structurels sans clé : CRC, APID, doublons, sauts de séquence."""
    alerts = []
    seen = set()
    prev_seq = None

    for pkt in packets:
        seq = pkt["seqCount"]

        if not pkt.get("crcValid", False):
            alerts.append({"seqCount": seq, "type": "CRC_FAIL",
                           "detail": f"received={pkt.get('receivedCrc'):#06x} "
                                     f"computed={pkt.get('computedCrc'):#06x}"})

        if expected_apid is not None and pkt["apid"] != expected_apid:
            alerts.append({"seqCount": seq, "type": "APID_SPOOF",
                           "detail": f"APID {pkt['apid']} inattendu (attendu {expected_apid})"})

        if seq in seen:
            alerts.append({"seqCount": seq, "type": "DUPLICATE_SEQ",
                           "detail": f"seqCount={seq} vu plusieurs fois (rejeu ?)"})
        seen.add(seq)

        if prev_seq is not None and seq != prev_seq + 1:
            gap = seq - prev_seq
            if gap > 1:
                alerts.append({"seqCount": seq, "type": "SEQ_GAP",
                               "detail": f"trou de {gap - 1} entre {prev_seq} et {seq}"})
            elif gap < 0:
                alerts.append({"seqCount": seq, "type": "SEQ_REORDER",
                               "detail": f"seqCount={seq} après {prev_seq}"})
        prev_seq = seq

    return alerts


def verify_stream(raw_stream: bytes, tagged_packets: list[dict],
                  key: bytes, expected_apid: int = None) -> dict:
    """Pipeline de défense complet : IDS structurel + vérification HMAC."""
    received = parse_stream(raw_stream)
    structural_alerts = detect_structural_anomalies(received, expected_apid)
    tag_map = {p["seqCount"]: p for p in tagged_packets}

    hmac_alerts = []
    verified = []
    offset = 0
    for pkt in received:
        raw_header = raw_stream[offset : offset + HEADER_SIZE]
        seq = pkt["seqCount"]
        offset += pkt["totalSize"]

        if seq not in tag_map:
            hmac_alerts.append({"seqCount": seq, "type": "HMAC_UNKNOWN",
                                "detail": f"seqCount={seq} sans empreinte connue (injectée ?)"})
        elif not verify_hmac_tag(raw_header, pkt["payload"], tag_map[seq]["hmacTag"], key):
            hmac_alerts.append({"seqCount": seq, "type": "HMAC_FAIL",
                                "detail": f"seqCount={seq} : empreinte HMAC invalide (falsifiée)"})
        else:
            verified.append(pkt)

    return {
        "allValid": len(hmac_alerts) == 0,
        "hmacAlerts": hmac_alerts,
        "structuralAlerts": structural_alerts,
        "verifiedPackets": verified,
    }
