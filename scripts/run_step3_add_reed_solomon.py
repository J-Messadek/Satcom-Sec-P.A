"""Étape 3 : transmission avec bruit spatial + correction Reed-Solomon."""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.encoding.encoder import send_image
from src.receiver.frame_parser import parse_stream
from src.receiver.data_reconstructor import reconstruct
from src.channel.jamming import SatelliteJammer
from src.channel.reed_solomon import ReedSolomonProtector

with open(ROOT / "config" / "exemple_config.yml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

jammer = SatelliteJammer.from_mapping(config)
rs = ReedSolomonProtector()
image_path = ROOT / "data" / "input" / "image_source.bmp"
output_path = ROOT / "data" / "output" / "received_image_with_jamming_&_rs.bmp"

raw_stream = b"".join(send_image(str(image_path), preprocessor=rs.encode))
raw_stream, report = jammer.jam_bytes(raw_stream)

parsed = parse_stream(raw_stream)
for pkt in parsed:
    pkt["payload"], _ = rs.decode(pkt["payload"])

reconstruct(parsed, str(output_path), discard_invalid=False)
