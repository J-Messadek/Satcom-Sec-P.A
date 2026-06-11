"""Chaîne de transmission appelable (émission → canal → réception)."""

from __future__ import annotations

from dataclasses import dataclass, field

from .attacks.frame_alteration import (
    alter_apid,
    alter_seq_count,
    fuzz_header,
    fuzz_payload,
    inject_packet,
)
from .channel.jamming import JammingReport, SatelliteJammer
from .channel.reed_solomon import ReedSolomonProtector
from .detection.anomaly_detector import tag_stream, verify_stream
from .encoding.encoder import send_payload
from .protocol.frame import build_packet
from .receiver.data_reconstructor import reconstruct_data
from .receiver.frame_parser import parse_stream

DEFAULT_HMAC_KEY = b"secret-hmac-key!"

ATTACKS = {
    "alter_apid": "Usurpation d'APID",
    "alter_seq_count": "Manipulation du seqCount",
    "fuzz_payload": "Corruption du payload",
    "fuzz_header": "Fuzzing complet du header",
    "inject_packet": "Injection d'une fausse trame",
}


@dataclass
class TransmissionResult:
    original: bytes
    received: bytes
    matches_original: bool
    byte_errors: int
    byte_error_rate: float
    jamming_enabled: bool
    reed_solomon_enabled: bool
    ecc_symbols: int | None
    jam_report: JammingReport | None


@dataclass
class AttackResult:
    attack: str
    num_packets: int
    crc_still_valid: bool
    all_valid: bool
    verified_count: int
    structural_alerts: list[dict] = field(default_factory=list)
    hmac_alerts: list[dict] = field(default_factory=list)


def _build_jammer(snr_db, intensity, mode, seed) -> SatelliteJammer:
    return SatelliteJammer.from_mapping({
        "channel_simulation": {
            "enable_jamming": True,
            "default_snr": snr_db,
            "jamming_intensity": intensity,
            "jamming": {"mode": mode, "seed": seed},
        }
    })


def _count_byte_errors(received: bytes, original: bytes) -> int:
    paired = sum(a != b for a, b in zip(received, original))
    return paired + abs(len(received) - len(original))


def run_transmission(
    image_bytes: bytes,
    *,
    jamming: bool = False,
    snr_db: float = 12.0,
    intensity: float = 0.02,
    mode: str = "barrage",
    seed: int | None = 2026,
    reed_solomon: bool = False,
    ecc_symbols: int = 32,
) -> TransmissionResult:
    rs = ReedSolomonProtector(ecc_symbols) if reed_solomon else None

    packets = send_payload(image_bytes, preprocessor=rs.encode if rs else None)
    raw_stream = b"".join(packets)

    jam_report = None
    if jamming:
        raw_stream, jam_report = _build_jammer(snr_db, intensity, mode, seed).jam_bytes(raw_stream)

    parsed = parse_stream(raw_stream)
    if rs:
        for pkt in parsed:
            pkt["payload"], _ = rs.decode(pkt["payload"])

    received = reconstruct_data(parsed, discard_invalid=not (jamming or reed_solomon))
    byte_errors = _count_byte_errors(received, image_bytes)

    return TransmissionResult(
        original=image_bytes,
        received=received,
        matches_original=received == image_bytes,
        byte_errors=byte_errors,
        byte_error_rate=byte_errors / max(len(image_bytes), 1),
        jamming_enabled=jamming,
        reed_solomon_enabled=reed_solomon,
        ecc_symbols=ecc_symbols if reed_solomon else None,
        jam_report=jam_report,
    )


def run_attack_defense(
    attack: str,
    *,
    num_packets: int = 8,
    apid: int = 0x42,
    target_seq: int = 1,
    fake_apid: int = 0x7FF,
    new_seq: int = 99,
    num_flips: int = 3,
    insert_after: int = 0,
    key: bytes = DEFAULT_HMAC_KEY,
) -> AttackResult:
    """Émet un flux signé (HMAC), applique une attaque, exécute les défenses."""
    if attack not in ATTACKS:
        raise ValueError(f"Attaque inconnue : {attack!r}")

    payloads = [f"PKT-{i:03d}".encode() for i in range(num_packets)]
    raw = b"".join(build_packet(p, i, apid=apid) for i, p in enumerate(payloads))
    tagged = tag_stream(raw, key)

    if attack == "alter_apid":
        modified = alter_apid(raw, target_seq, fake_apid, verbose=False)
    elif attack == "alter_seq_count":
        modified = alter_seq_count(raw, target_seq, new_seq, verbose=False)
    elif attack == "fuzz_payload":
        modified = fuzz_payload(raw, target_seq, num_flips, verbose=False)
    elif attack == "fuzz_header":
        modified = fuzz_header(raw, target_seq, verbose=False)
    else:
        modified = inject_packet(raw, b"FORGED!!", fake_seq=target_seq,
                                 insert_after_seq=insert_after, verbose=False)

    verdict = verify_stream(modified, tagged, key, expected_apid=apid)
    parsed = parse_stream(modified)

    return AttackResult(
        attack=attack,
        num_packets=num_packets,
        crc_still_valid=bool(parsed) and all(p["crcValid"] for p in parsed),
        all_valid=verdict["allValid"],
        verified_count=len(verdict["verifiedPackets"]),
        structural_alerts=verdict["structuralAlerts"],
        hmac_alerts=verdict["hmacAlerts"],
    )
