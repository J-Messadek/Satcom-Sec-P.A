# =============================================================
# reception_test.py  –  Étudiant B
#
# End-to-end test: uses the transmitter from creation-tram1.py
# (BSG / Étudiant A) to build frames, then runs the full
# reception pipeline (parse → validate → reconstruct).
#
# Run from the project root:
#   python tests/reception_test.py
# =============================================================

import struct
import binascii
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.receiver.frameParser       import parseStream
from src.receiver.frameValidator    import validateCrc
from src.receiver.dataReconstructor import reconstruct

VERSION = 0; PACKET_TYPE = 0; SEC_HDR_FLAG = 0; APID = 1; SEQ_FLAGS = 0b11

def buildPacket(payload, seqCount):
    packetLength = len(payload) - 1
    word1 = (VERSION << 13) | (PACKET_TYPE << 12) | (SEC_HDR_FLAG << 11) | APID
    word2 = (SEQ_FLAGS << 14) | seqCount
    primaryHeader = struct.pack(">HHH", word1, word2, packetLength)
    packet = primaryHeader + payload
    crc = binascii.crc_hqx(packet, 0xFFFF)
    return packet + struct.pack(">H", crc)

def testSingleFrame():
    print("===== TEST B – Single frame 'hello' =====")
    pkt = buildPacket(b"hello", seqCount=1)
    packets = parseStream(pkt)
    assert packets[0]["crcValid"] and packets[0]["payload"] == b"hello"
    print("[PASS]\n")

def testTextFrames():
    print("===== TEST A – Two frames 'hello'+'world' =====")
    stream = buildPacket(b"hello", 1) + buildPacket(b"world", 2)
    packets = parseStream(stream)
    result = reconstruct(packets)
    assert result == b"helloworld"
    print("[PASS]\n")

def testCorruptedFrame():
    print("===== TEST C– Corrupted frame =====")
    pkt = bytearray(buildPacket(b"hello", 1)); pkt[6] ^= 0xFF; pkt = bytes(pkt)
    packets = parseStream(pkt)
    assert not packets[0]["crcValid"]
    print("[PASS]\n")

def testImageReconstruction():
    print("===== TEST!D– Image reconstruction =====")
    imagePath = os.path.join(os.path.dirname(__file__), "..", "data", "input", "image_source.png")
    if not os.path.exists(imagePath): print("[SKIP]\n"); return
    with open(imagePath, "rb") as f: imageBytes = f.read()
    blocks = [imageBytes[i:i+256] for i in range(0, len(imageBytes), 256)]
    stream = b"".join(buildPacket(b, i+1) for i,b in enumerate(blocks))
    packets = parseStream(stream)
    result = reconstruct(packets, os.path.join(os.path.dirname(__file__),"..","data","output","received_image.png"))
    assert result == imageBytes; print("[PASS]\n")

if __name__ == "__main__":
    testSingleFrame(); testTextFrames(); testCorruptedFrame(); testImageReconstruction()
    print("====== All tests passed. ======")
