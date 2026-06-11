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
from .channel.jamming import SatelliteJammer
from .channel.reed_solomon import ReedSolomonProtector
from .detection.anomaly_detector import tag_stream, verify_stream
from .protocol.frame import build_packet
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
class ChannelResult:
    output: bytes
    byte_errors: int
    byte_error_rate: float
    flipped_bits: int
    effective_snr_db: float
    corrected: bool
    ecc_symbols: int | None
    status: str


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


def attack_image(image_bytes: bytes, *, snr_db=8.0, intensity=0.15,
                 mode="barrage", seed=2026) -> ChannelResult:
    """Image transmise sans protection : le brouillage corrompt les octets."""
    corrupted, report = _build_jammer(snr_db, intensity, mode, seed).jam_bytes(image_bytes)
    errors = _count_byte_errors(corrupted, image_bytes)
    return ChannelResult(
        output=corrupted,
        byte_errors=errors,
        byte_error_rate=errors / max(len(image_bytes), 1),
        flipped_bits=report.flipped_bits,
        effective_snr_db=report.effective_snr_db,
        corrected=False,
        ecc_symbols=None,
        status="jammed",
    )


def defend_image(image_bytes: bytes, *, snr_db=8.0, intensity=0.15,
                 mode="barrage", seed=2026, ecc_symbols=32) -> ChannelResult:
    """Même canal protégé par Reed-Solomon : les erreurs sont corrigées."""
    jammer = _build_jammer(snr_db, intensity, mode, seed)
    report = ReedSolomonProtector(ecc_symbols).simulate_protection(image_bytes, jammer.jam_bytes)
    recovered = report["recovered_data"]
    return ChannelResult(
        output=recovered,
        byte_errors=report["residual_byte_errors"],
        byte_error_rate=report["residual_byte_errors"] / max(len(image_bytes), 1),
        flipped_bits=report["errors_detected"],
        effective_snr_db=report["jam_report"].effective_snr_db,
        corrected=report["recovered_matches_original"],
        ecc_symbols=ecc_symbols,
        status=report["status"],
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
