"""Émetteur : découpe une image en paquets CCSDS de 512 octets."""

from ..protocol.frame import (
    build_packet,
    SEQ_FLAG_FIRST,
    SEQ_FLAG_LAST,
    SEQ_FLAG_CONTINUATION,
)

CHUNK_SIZE = 512  # taille du payload de chaque paquet, en octets


def read_image_as_bytes(image_path):
    with open(image_path, "rb") as f:
        return f.read()


def send_image(image_path, preprocessor=None):
    """Retourne la liste des paquets CCSDS représentant l'image.

    `preprocessor` (optionnel) est appliqué à chaque bloc de payload avant
    encapsulation — par exemple l'encodage Reed-Solomon.
    """
    payload = read_image_as_bytes(image_path)
    size_payload = len(payload)

    packets = []
    seq_count = 0
    for i in range(0, size_payload, CHUNK_SIZE):
        payload_part = payload[i : i + CHUNK_SIZE]

        if preprocessor:
            payload_part = preprocessor(payload_part)

        if i == 0:
            seq_flags = SEQ_FLAG_FIRST
        elif i + CHUNK_SIZE >= size_payload:
            seq_flags = SEQ_FLAG_LAST
        else:
            seq_flags = SEQ_FLAG_CONTINUATION

        packets.append(build_packet(payload_part, seq_count, seq_flags))
        seq_count += 1

    return packets
