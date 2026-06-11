# Étape 2 : transmission avec bruit spatial / brouillage.

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.encoding.encoder import send_image
from src.receiver.frame_parser import parse_stream
from src.receiver.data_reconstructor import reconstruct
from src.channel.jamming import SatelliteJammer

with open(ROOT / "config" / "exemple_config.yml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

jammer = SatelliteJammer.from_mapping(config)

image_path = ROOT / "data" / "input" / "image_source.bmp"
output_path = ROOT / "data" / "output" / "received_image_with_jamming.bmp"

# 1. Émettre l'image → liste de paquets
packets = send_image(str(image_path))

# 2. Coller les paquets en un seul flux
raw_stream = b"".join(packets)

# 3. Appliquer le bruit spatial
raw_stream, report = jammer.jam_bytes(raw_stream)

# 4. Parser le flux → liste de paquets lisibles
parsed = parse_stream(raw_stream)

# 5. Reconstruire l'image (on ne jette pas les trames invalides pour visualiser le bruit)
reconstruct(parsed, str(output_path), discard_invalid=False)
