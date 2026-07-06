"""Démo : transmission d'une image à travers le canal, protections (Reed-Solomon /
brouillage) activables depuis config/exemple_config.yml."""

import sys
from pathlib import Path

import yaml
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.protocol.frame import build_packet, SEQ_FLAG_UNSEGMENTED
from src.channel import reed_solomon as sm
from src.channel import jamming as jm

with (ROOT / "config" / "exemple_config.yml").open("r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

demo_stream = (
    build_packet(b"hello world how are you", 1, SEQ_FLAG_UNSEGMENTED)
    + build_packet(b"fine and you", 2, SEQ_FLAG_UNSEGMENTED)
)
print(f"[CCSDS] Flux de démonstration : {len(demo_stream)} octets")

reed_enabled = config["activation"]["reed_solomon"]
jam_enabled = config["activation"]["jamming"]

image_path = ROOT / config["data_paths"]["input_image"]
output_image_path = ROOT / config["data_paths"]["output_image"]
output_image_path.parent.mkdir(parents=True, exist_ok=True)

original = image_path.read_bytes()
packet = original
jam_report = None
rs_report = None

if reed_enabled:
    ecc = int(config.get("channel_simulation", {}).get("reed_solomon", {}).get("ecc_symbols", 32))
    protector = sm.ReedSolomonProtector(ecc_symbols=ecc)
    if jam_enabled:
        jammer = jm.SatelliteJammer.from_mapping(config)
        rs_report = protector.simulate_protection(original, jammer.jam_bytes)
        packet = rs_report["recovered_data"]
        jam_report = rs_report.get("jam_report")
    else:
        packet, _ = protector.decode(protector.encode(original))
elif jam_enabled:
    packet, jam_report = jm.SatelliteJammer.from_mapping(config).jam_bytes(original)

output_image_path.write_bytes(packet)
print(f"Image reconstruite : {output_image_path}")

if jam_report is not None:
    print(f"[Jamming] mode={jam_report.mode} bits_inversés={jam_report.flipped_bits} "
          f"BER={jam_report.estimated_ber:.6f} sévérité={jam_report.severity}")
if rs_report is not None:
    print(f"[Reed-Solomon] statut={rs_report['status']} "
          f"capacité={rs_report['correction_capacity']} octets "
          f"résiduel={rs_report['residual_byte_errors']} octet(s)")

try:
    Image.open(output_image_path).show()
except Exception as e:
    print("Impossible d'afficher l'image :", e)
