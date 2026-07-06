"""Émetteur : découpe une charge utile en paquets CCSDS de 512 octets."""

from ..protocol.frame import (
    build_packet,
    SEQ_FLAG_FIRST,
    SEQ_FLAG_LAST,
    SEQ_FLAG_CONTINUATION,
)

CHUNK_SIZE = 512


def read_image_as_bytes(image_path):
    with open(image_path, "rb") as f:
        return f.read()


def send_image(image_path, preprocessor=None):
    return send_payload(read_image_as_bytes(image_path), preprocessor)


def send_payload(payload, preprocessor=None):
    """`preprocessor` (ex. encodage Reed-Solomon) est appliqué à chaque bloc."""
    size = len(payload)
    packets = []
    for seq_count, i in enumerate(range(0, size, CHUNK_SIZE)):
        chunk = payload[i : i + CHUNK_SIZE]
        if preprocessor:
            chunk = preprocessor(chunk)

        if i == 0:
            seq_flags = SEQ_FLAG_FIRST
        elif i + CHUNK_SIZE >= size:
            seq_flags = SEQ_FLAG_LAST
        else:
            seq_flags = SEQ_FLAG_CONTINUATION

        packets.append(build_packet(chunk, seq_count, seq_flags))
    return packets
