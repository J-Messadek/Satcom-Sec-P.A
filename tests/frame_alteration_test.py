# =============================================================
# frame_alteration_test.py  –  Attaque 2 + Défense 2
#
# Valide les 5 vecteurs d'attaque (frameAlteration.py) et
# les 2 niveaux de défense (anomalyDetector.py) :
#   Défense A : IDS structurel (sans clé HMAC)
#   Défense B : HMAC-SHA256 (authentification cryptographique)
#
# 7 tests couverts :
#   1. alterApid          → CRC passe, IDS détecte APID_SPOOF + HMAC_FAIL
#   2. alterSeqCount      → CRC passe, IDS détecte SEQ_GAP + HMAC_FAIL
#   3. fuzzPayload        → CRC passe, HMAC_FAIL détecté
#   4. fuzzHeader         → CRC passe, IDS détecte anomalies + HMAC_FAIL
#   5. injectPacket       → CRC passe, IDS détecte DUPLICATE_SEQ + HMAC_UNKNOWN
#   6. verifyStream       → pipeline complet (tag → attack → verify → alertes)
#   7. testImagePipeline  → flux image, trame altérée détectée + rejet partiel
# =============================================================

import sys
import os
import struct
import binascii

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.receiver.frameParser  import parseStream, HEADER_SIZE, CRC_SIZE
from src.attacks.frameAlteration import (
    alterApid, alterSeqCount, fuzzPayload, fuzzHeader, injectPacket
)
from src.detection.anomalyDetector import (
    computeHmacTag, verifyHmacTag,
    tagStream, verifyStream, detectStructuralAnomalies
)


# ==============================================================
# Helper – build a minimal CCSDS raw stream
# ==============================================================

def _buildStream(payloads: list[bytes], startSeq: int = 0,
                 apid: int = 0x42) -> bytes:
    """
    Build a raw CCSDS stream from a list of payloads.
    All packets share the same APID and get consecutive seqCounts.
    """
    raw = b""
    for i, payload in enumerate(payloads):
        dataLength = len(payload) - 1          # CCSDS convention
        word1 = (0 & 0x7) << 13 | (0 & 0x1) << 12 | (0 & 0x1) << 11 | (apid & 0x7FF)
        word2 = (3 & 0x3) << 14 | ((startSeq + i) & 0x3FFF)
        header = struct.pack(">HHH", word1, word2, dataLength)
        pkt    = header + payload
        crc    = binascii.crc_hqx(pkt, 0xFFFF)
        raw   += pkt + struct.pack(">H", crc)
    return raw


SHARED_KEY = b"secret-hmac-key!"   # 16 bytes, shared between Tx and Rx


# ==============================================================
# Test 1 – APID spoofing
# ==============================================================

def testAlterApid():
    raw     = _buildStream([b"hello", b"world", b"test!"], apid=0x42)
    packets = parseStream(raw)

    # --- Without defense : CRC still passes after alteration ---
    modified = alterApid(raw, targetSeq=1, fakeApid=0x7FF, verbose=False)
    parsedMod = parseStream(modified)
    alteredPkt = next(p for p in parsedMod if p["seqCount"] == 1)
    assert alteredPkt["apid"]     == 0x7FF,   "APID should be altered"
    assert alteredPkt["crcValid"] == True,    "CRC should pass (reforged)"

    # --- With IDS : APID_SPOOF detected ---
    alerts = detectStructuralAnomalies(parsedMod, expectedApid=0x42)
    spoofAlerts = [a for a in alerts if a["type"] == "APID_SPOOF"]
    assert len(spoofAlerts) > 0, "IDS should detect APID_SPOOF"

    # --- With HMAC : HMAC_FAIL detected ---
    tagged   = tagStream(raw, SHARED_KEY)
    result   = verifyStream(modified, tagged, SHARED_KEY, expectedApid=0x42)
    hmacFail = [a for a in result["hmacAlerts"] if a["type"] == "HMAC_FAIL"]
    assert len(hmacFail) > 0,       "HMAC should detect the alteration"
    assert result["allValid"] == False, "allValid should be False"

    print("✓ Test 1 – alterApid : CRC passe, IDS + HMAC détectent l'attaque")

# =============================================================
# Test 2 – Sequence counter manipulation
# =============================================================

def testAlterSeqCount():
    raw      = _buildStream([b"alpha", b"bravo", b"charlie"], apid=0x10)
    modified = alterSeqCount(raw, targetSeq=1, newSeq=99, verbose=False)

    parsedMod = parseStream(modified)
    assert any(p["seqCount"] == 99 for p in parsedMod), "seqCount should be 99"
    assert all(p["crcValid"] for p in parsedMod),       "CRC should pass"

    # IDS detects gap
    alerts   = detectStructuralAnomalies(parsedMod)
    seqAlerts = [a for a in alerts if a["type"] in ("SEQ_GAP", "SEQ_REORDER")]
    assert len(seqAlerts) > 0, "IDS should detect sequence anomaly"

    tagged = tagStream(raw, SHARED_KEY)
    result = verifyStream(modified, tagged, SHARED_KEY)
    assert result["allValid"] == False
    assert len(result["hmacAlerts"]) > 0, "HMAC should detect the altered seqCount"

    print("✓ Test 2 – alterSeqCount : CRC passe, IDS SEQ_GAP + HMAC détecté")


def testFuzzPayload():
    raw      = _buildStream([b"AAAAAA", b"BBBBBB", b"CCCCCC"])
    modified = fuzzPayload(raw, targetSeq=1, numFlips=3, verbose=False)
    parsedMod = parseStream(modified)
    orig      = parseStream(raw)
    assert parsedMod[1]["payload"] != orig[1]["payload"]
    assert parsedMod[1]["crcValid"] == True
    tagged = tagStream(raw, SHARED_KEY)
    result = verifyStream(modified, tagged, SHARED_KEY)
    assert result["allValid"] == False
    assert any(a["type"] == "HMAC_FAIL" for a in result["hmacAlerts"])
    print("✓ Test 3 – fuzzPayload : CRC passe, HMAC_FAIL détecté")


def testFuzzHeader():
    raw      = _buildStream([b"X" * 10, b"Y" * 10, b"Z" * 10], apid=0x55)
    modified = fuzzHeader(raw, targetSeq=0, verbose=False)
    parsedMod = parseStream(modified)
    assert parsedMod[0]["crcValid"] == True
    alerts = detectStructuralAnomalies(parsedMod, expectedApid=0x55)
    assert len(alerts) > 0
    tagged = tagStream(raw, SHARED_KEY)
    result = verifyStream(modified, tagged, SHARED_KEY)
    assert result["allValid"] == False
    print("✓ Test 4 – fuzzHeader : CRC passe, IDS + HMAC détectent l'attaque")


def testInjectPacket():
    raw      = _buildStream([b"one!", b"two!", b"thre"], apid=0x20)
    modified = injectPacket(raw, fakePayload=b"FAKE", fakeSeq=1, insertAfterSeq=0, verbose=False)
    parsedMod = parseStream(modified)
    assert len(parsedMod) == 4
    assert all(p["crcValid"] for p in parsedMod)
    alerts = detectStructuralAnomalies(parsedMod)
    assert any(a["type"] == "DUPLICATE_SEQ" for a in alerts)
    tagged = tagStream(raw, SHARED_KEY)
    result = verifyStream(modified, tagged, SHARED_KEY)
    assert any(a["type"] in ("HMAC_FAIL", "HMAC_UNKNOWN") for a in result["hmacAlerts"])
    assert result["allValid"] == False
    print("✓ Test 5 – injectPacket : CRC passe, IDS DUPLICATE_SEQ + HMAC détecté")


def testFullDefensePipeline():
    payloads = [f"msg-{i:03d}".encode() for i in range(10)]
    raw      = _buildStream(payloads, startSeq=0, apid=0x30)
    tagged   = tagStream(raw, SHARED_KEY)
    modified = alterApid(raw, targetSeq=3, fakeApid=0x777, verbose=False)
    modified = fuzzPayload(modified, targetSeq=7, numFlips=2, verbose=False)
    result = verifyStream(modified, tagged, SHARED_KEY, expectedApid=0x30)
    assert result["allValid"] == False
    assert len(result["hmacAlerts"]) >= 2
    assert any(a["type"] == "APID_SPOOF" for a in result["structuralAlerts"])
    assert len(result["verifiedPackets"]) == 8
    print("✓ Test 6 – pipeline complet : 2 HMAC_FAIL, 1 APID_SPOOF, 8 paquets valides")


def testImagePipeline():
    import random
    random.seed(42)
    payloads = [bytes(random.randint(0, 255) for _ in range(256)) for _ in range(100)]
    raw    = _buildStream(payloads, startSeq=0, apid=0x99)
    tagged = tagStream(raw, SHARED_KEY)
    modified = fuzzPayload(raw, targetSeq=50, numFlips=5, verbose=False)
    result = verifyStream(modified, tagged, SHARED_KEY, expectedApid=0x99)
    assert result["allValid"] == False
    assert len(result["hmacAlerts"]) == 1
    assert result["hmacAlerts"][0]["seqCount"] == 50
    assert len(result["verifiedPackets"]) == 99
    reconstructed = b"".join(p["payload"] for p in result["verifiedPackets"])
    original = b"".join(payloads[i] for i in range(100) if i != 50)
    assert reconstructed == original
    print(f"✓ Test 7 – image pipeline : 100 paquets, 1 altépé détecté/rejeté, 99 reconstruits")


if __name__ == "__main__":
    tests = [testAlterApid, testAlterSeqCount, testFuzzPayload, testFuzzHeader,
             testInjectPacket, testFullDefensePipeline, testImagePipeline]
    passed = failed = 0
    print("\n══════════════════════════════════════════════════")
    print("  Attaque 2 + Défense 2 – Test Suite")
    print("══════════════════════════════════════════════════")
    for t in tests:
        try:
            t(); passed += 1
        except Exception as e:
            print(f"✗ {t.__name__}: {e}"); failed += 1
    print(f"══════════════════════════════════════════════════\n  Résultat : {passed}/{len(tests)} tests passés")
    import sys; sys.exit(0 if failed == 0 else 1)
