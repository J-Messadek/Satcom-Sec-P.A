# Branchement de l'encodeur au décodeur avec le bruit spatial


import sys
import os
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.encoding.encoder import send_image
from src.receiver.frameParser import parseStream
from src.receiver.dataReconstructor import reconstruct
from src.channel.jamming import SatelliteJammer

# Charger la config
with open("../config/exemple_config.yml", "r") as f:
    config = yaml.safe_load(f)

jammer = SatelliteJammer.from_mapping(config)


image_path = "../data/input/image_source.bmp"
# 1. Envoyer l'image → liste de paquets
packets = send_image(image_path)

# 2. Coller les paquets en un seul bloc
raw_stream = b"".join(packets)

# 3. Appliquer le bruit spatial
raw_stream, report = jammer.jam_bytes(raw_stream)

# 4. Parser le bloc → liste de paquets lisibles
parsed = parseStream(raw_stream)

# 5. Reconstruire l'image
reconstruct(
    parsed, "../data/output/received_image_with_jamming2.bmp", discardInvalid=False
)
