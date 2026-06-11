# =============================================================
# frame_alteration_test.py  –  Attaque 2 + Défense 2
#
# Valide les 5 vecteurs d'attaque (attacks.frame_alteration) et les
# 2 niveaux de défense (detection.anomaly_detector) :
#   Défense A : IDS structurel (sans clé HMAC)
#   Défense B : HMAC-SHA256 (authentification cryptographique)
#
# Lancer depuis la racine du dépôt :  pytest
# =============================================================

import random

from src.protocol.frame import build_packet
from src.receiver.frame_parser import parse_stream
from src.attacks.frame_alteration import (
    alter_apid,
    alter_seq_count,
    fuzz_payload,
    fuzz_header,
    inject_packet,
)
from src.detection.anomaly_detector import (
    tag_stream,
    verify_stream,
    detect_structural_anomalies,
)

SHARED_KEY = b"secret-hmac-key!"  # 16 bytes, partagé entre Tx et Rx


def _build_stream(payloads: list[bytes], start_seq: int = 0,
                  apid: int = 0x42) -> bytes:
    """Build a raw CCSDS stream from a list of payloads (consecutive seqCounts)."""
    return b"".join(
        build_packet(payload, start_seq + i, apid=apid)
        for i, payload in enumerate(payloads)
    )


# ==============================================================
# Test 1 – APID spoofing
# ==============================================================

def test_alter_apid():
    raw = _build_stream([b"hello", b"world", b"test!"], apid=0x42)

    # --- Sans défense : le CRC passe toujours après altération ---
    modified = alter_apid(raw, target_seq=1, fake_apid=0x7FF, verbose=False)
    parsed_mod = parse_stream(modified)
    altered_pkt = next(p for p in parsed_mod if p["seqCount"] == 1)
    assert altered_pkt["apid"] == 0x7FF
    assert altered_pkt["crcValid"] is True

    # --- Avec IDS : APID_SPOOF détecté ---
    alerts = detect_structural_anomalies(parsed_mod, expected_apid=0x42)
    assert any(a["type"] == "APID_SPOOF" for a in alerts)

    # --- Avec HMAC : HMAC_FAIL détecté ---
    tagged = tag_stream(raw, SHARED_KEY)
    result = verify_stream(modified, tagged, SHARED_KEY, expected_apid=0x42)
    assert any(a["type"] == "HMAC_FAIL" for a in result["hmacAlerts"])
    assert result["allValid"] is False


# ==============================================================
# Test 2 – Sequence counter manipulation
# ==============================================================

def test_alter_seq_count():
    raw = _build_stream([b"alpha", b"bravo", b"charlie"], apid=0x10)
    modified = alter_seq_count(raw, target_seq=1, new_seq=99, verbose=False)

    parsed_mod = parse_stream(modified)
    assert any(p["seqCount"] == 99 for p in parsed_mod)
    assert all(p["crcValid"] for p in parsed_mod)

    alerts = detect_structural_anomalies(parsed_mod)
    assert any(a["type"] in ("SEQ_GAP", "SEQ_REORDER") for a in alerts)

    tagged = tag_stream(raw, SHARED_KEY)
    result = verify_stream(modified, tagged, SHARED_KEY)
    assert result["allValid"] is False
    assert len(result["hmacAlerts"]) > 0


# ==============================================================
# Test 3 – Payload fuzzing
# ==============================================================

def test_fuzz_payload():
    raw = _build_stream([b"AAAAAA", b"BBBBBB", b"CCCCCC"])
    modified = fuzz_payload(raw, target_seq=1, num_flips=3, verbose=False)

    parsed_mod = parse_stream(modified)
    orig = parse_stream(raw)
    assert parsed_mod[1]["payload"] != orig[1]["payload"]
    assert parsed_mod[1]["crcValid"] is True

    tagged = tag_stream(raw, SHARED_KEY)
    result = verify_stream(modified, tagged, SHARED_KEY)
    assert result["allValid"] is False
    assert any(a["type"] == "HMAC_FAIL" for a in result["hmacAlerts"])


# ==============================================================
# Test 4 – Full header fuzzing
# ==============================================================

def test_fuzz_header():
    raw = _build_stream([b"X" * 10, b"Y" * 10, b"Z" * 10], apid=0x55)
    modified = fuzz_header(raw, target_seq=0, verbose=False)

    parsed_mod = parse_stream(modified)
    assert parsed_mod[0]["crcValid"] is True
    assert detect_structural_anomalies(parsed_mod, expected_apid=0x55)

    tagged = tag_stream(raw, SHARED_KEY)
    result = verify_stream(modified, tagged, SHARED_KEY)
    assert result["allValid"] is False


# ==============================================================
# Test 5 – Packet injection
# ==============================================================

def test_inject_packet():
    raw = _build_stream([b"one!", b"two!", b"thre"], apid=0x20)
    modified = inject_packet(
        raw, fake_payload=b"FAKE", fake_seq=1, insert_after_seq=0, verbose=False
    )

    parsed_mod = parse_stream(modified)
    assert len(parsed_mod) == 4
    assert all(p["crcValid"] for p in parsed_mod)
    assert any(a["type"] == "DUPLICATE_SEQ" for a in detect_structural_anomalies(parsed_mod))

    tagged = tag_stream(raw, SHARED_KEY)
    result = verify_stream(modified, tagged, SHARED_KEY)
    assert any(a["type"] in ("HMAC_FAIL", "HMAC_UNKNOWN") for a in result["hmacAlerts"])
    assert result["allValid"] is False


# ==============================================================
# Test 6 – Full defense pipeline (multiple attacks)
# ==============================================================

def test_full_defense_pipeline():
    payloads = [f"msg-{i:03d}".encode() for i in range(10)]
    raw = _build_stream(payloads, start_seq=0, apid=0x30)
    tagged = tag_stream(raw, SHARED_KEY)

    modified = alter_apid(raw, target_seq=3, fake_apid=0x777, verbose=False)
    modified = fuzz_payload(modified, target_seq=7, num_flips=2, verbose=False)

    result = verify_stream(modified, tagged, SHARED_KEY, expected_apid=0x30)
    assert result["allValid"] is False
    assert len(result["hmacAlerts"]) >= 2
    assert any(a["type"] == "APID_SPOOF" for a in result["structuralAlerts"])
    assert len(result["verifiedPackets"]) == 8


# ==============================================================
# Test 7 – Image-like pipeline (1 altered packet rejected)
# ==============================================================

def test_image_pipeline():
    random.seed(42)
    payloads = [bytes(random.randint(0, 255) for _ in range(256)) for _ in range(100)]
    raw = _build_stream(payloads, start_seq=0, apid=0x99)
    tagged = tag_stream(raw, SHARED_KEY)

    modified = fuzz_payload(raw, target_seq=50, num_flips=5, verbose=False)
    result = verify_stream(modified, tagged, SHARED_KEY, expected_apid=0x99)

    assert result["allValid"] is False
    assert len(result["hmacAlerts"]) == 1
    assert result["hmacAlerts"][0]["seqCount"] == 50
    assert len(result["verifiedPackets"]) == 99

    reconstructed = b"".join(p["payload"] for p in result["verifiedPackets"])
    original = b"".join(payloads[i] for i in range(100) if i != 50)
    assert reconstructed == original
