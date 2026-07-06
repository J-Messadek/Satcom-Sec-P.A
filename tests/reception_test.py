# =============================================================
# reception_test.py
#
# Tests de bout en bout du récepteur : construit des trames avec
# l'émetteur (protocol.frame) puis exécute la chaîne de réception
# (parse → validate → reconstruct).
#
# Lancer depuis la racine du dépôt :  pytest
# =============================================================

import os

from src.protocol.frame import build_packet
from src.receiver.frame_parser import parse_stream
from src.receiver.data_reconstructor import reconstruct


def test_single_frame():
    pkt = build_packet(b"hello", seq_count=1)
    packets = parse_stream(pkt)
    assert packets[0]["crcValid"]
    assert packets[0]["payload"] == b"hello"


def test_text_frames():
    stream = build_packet(b"hello", 1) + build_packet(b"world", 2)
    packets = parse_stream(stream)
    assert reconstruct(packets) == b"helloworld"


def test_corrupted_frame():
    pkt = bytearray(build_packet(b"hello", 1))
    pkt[6] ^= 0xFF  # flip a payload byte → CRC must fail
    packets = parse_stream(bytes(pkt))
    assert not packets[0]["crcValid"]


def test_image_reconstruction(tmp_path):
    image_path = os.path.join(
        os.path.dirname(__file__), "..", "data", "input", "image_source.png"
    )
    if not os.path.exists(image_path):
        import pytest

        pytest.skip("image_source.png not available")

    with open(image_path, "rb") as f:
        image_bytes = f.read()

    blocks = [image_bytes[i : i + 256] for i in range(0, len(image_bytes), 256)]
    stream = b"".join(build_packet(b, i + 1) for i, b in enumerate(blocks))
    packets = parse_stream(stream)

    result = reconstruct(packets, str(tmp_path / "received_image.png"))
    assert result == image_bytes
