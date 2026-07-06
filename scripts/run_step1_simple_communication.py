"""Étape 1 : transmission simple (émetteur → récepteur, sans bruit)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.encoding.encoder import send_image
from src.receiver.frame_parser import parse_stream
from src.receiver.data_reconstructor import reconstruct

image_path = ROOT / "data" / "input" / "image_source.bmp"
output_path = ROOT / "data" / "output" / "received_image_without_jamming.bmp"

packets = send_image(str(image_path))
parsed = parse_stream(b"".join(packets))
reconstruct(parsed, str(output_path))
