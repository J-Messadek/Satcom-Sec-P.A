# =========================
# Démonstration pédagogique :
#   1. Construction de trames CCSDS (header + payload + CRC).
#   2. Transmission d'une image à travers le canal, avec protections
#      (Reed-Solomon / brouillage) activables depuis la configuration.
# =========================

import sys
from pathlib import Path

import yaml
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.protocol.frame import build_packet, SEQ_FLAG_UNSEGMENTED
from src.channel import reed_solomon as sm
from src.channel import jamming as jm

CONFIG_PATH = ROOT / "config" / "exemple_config.yml"
with CONFIG_PATH.open("r", encoding="utf-8") as f:
    config = yaml.safe_load(f)


# =========================
# 1. Démonstration : deux paquets de télémétrie dans un flux CCSDS
# =========================
demo_stream = (
    build_packet(b"hello world how are you", seq_count=1, seq_flags=SEQ_FLAG_UNSEGMENTED)
    + build_packet(b"fine and you", seq_count=2, seq_flags=SEQ_FLAG_UNSEGMENTED)
)
print(f"[CCSDS] Flux de démonstration : {len(demo_stream)} octets")


# =========================
# 2. Transmission de l'image à travers le canal
# =========================
reed_enabled = config["activation"]["reed_solomon"]
jam_enabled = config["activation"]["jamming"]

image_path = ROOT / config["data_paths"]["input_image"]
output_image_path = ROOT / config["data_paths"]["output_image"]
output_image_path.parent.mkdir(parents=True, exist_ok=True)

original_packet = image_path.read_bytes()

packet = original_packet
jam_report = None
rs_report = None

if reed_enabled:
    rs_config = config.get("channel_simulation", {}).get("reed_solomon", {})
    protector = sm.ReedSolomonProtector(ecc_symbols=int(rs_config.get("ecc_symbols", 32)))

    if jam_enabled:
        jammer = jm.SatelliteJammer.from_mapping(config)
        rs_report = protector.simulate_protection(original_packet, jammer.jam_bytes)
        packet = rs_report["recovered_data"]
        jam_report = rs_report.get("jam_report")
    else:
        encoded_packet = protector.encode(original_packet)
        packet, _ = protector.decode(encoded_packet)
elif jam_enabled:
    jammer = jm.SatelliteJammer.from_mapping(config)
    packet, jam_report = jammer.jam_bytes(original_packet)

output_image_path.write_bytes(packet)


# =========================
# 3. Diagnostic
# =========================
print(f"Image reconstruite sauvegardée dans : {output_image_path}")

if jam_report is not None:
    active_modes = ", ".join(jam_report.active_modes) or jam_report.mode
    print(
        "[Jamming] "
        f"mode={jam_report.mode} "
        f"modes={active_modes} "
        f"bits_inversés={jam_report.flipped_bits} "
        f"BER={jam_report.estimated_ber:.6f} "
        f"sévérité={jam_report.severity}"
    )

if rs_report is not None:
    print(
        "[Reed-Solomon] "
        f"statut={rs_report['status']} "
        f"capacité={rs_report['correction_capacity']} octets "
        f"résiduel={rs_report['residual_byte_errors']} octet(s)"
    )

try:
    Image.open(output_image_path).show()
except Exception as e:
    print("Impossible d'afficher l'image :", e)
