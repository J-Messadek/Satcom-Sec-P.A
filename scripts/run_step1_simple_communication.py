# Branchement de l'encodeur au décodeur


import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.encoding.encoder import send_image
from src.receiver.frameParser import parseStream
from src.receiver.dataReconstructor import reconstruct


image_path = "../data/input/image_source.bmp"
# 1. Envoyer l'image → liste de paquets
packets = send_image(image_path)

# 2. Coller les paquets en un seul bloc
raw_stream = b"".join(packets)

# 3. Parser le bloc → liste de paquets lisibles
parsed = parseStream(raw_stream)

# 4. Reconstruire l'image
reconstruct(parsed, "../data/output/received_image_without_jamming.bmp")
