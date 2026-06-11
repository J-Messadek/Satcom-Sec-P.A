# =============================================================
# frameParser.py
# Parses raw binary data into structured CCSDS frames.
# Extracts header fields, payload and CRC from a byte stream.
# =============================================================

import struct
import binascii

# ---- Constants -----------------------------------------------
HEADER_SIZE = 6  # Primary header: 3 x 16-bit words
CRC_SIZE = 2  # CRC-16 (CCITT / crc_hqx) appended at the end
MIN_PACKET = HEADER_SIZE + CRC_SIZE  # Minimum valid packet size (no payload)


def parseHeader(rawHeader: bytes) -> dict:
    """
    Decode the 6-byte CCSDS primary header.

    Args:
        rawHeader: Exactly 6 bytes.

    Returns:
        dict with keys: version, packetType, secHdrFlag,
                        apid, seqFlags, seqCount, dataLength
    """
    if len(rawHeader) < HEADER_SIZE:
        raise ValueError(
            f"Header too short: {len(rawHeader)} bytes (expected {HEADER_SIZE})"
        )

    word1, word2, dataLength = struct.unpack(">HHH", rawHeader)

    version = (word1 >> 13) & 0x07
    packetType = (word1 >> 12) & 0x01
    secHdrFlag = (word1 >> 11) & 0x01
    apid = word1 & 0x07FF

    seqFlags = (word2 >> 14) & 0x03
    seqCount = word2 & 0x3FFF

    return {
        "version": version,
        "packetType": packetType,
        "secHdrFlag": secHdrFlag,
        "apid": apid,
        "seqFlags": seqFlags,
        "seqCount": seqCount,
        "dataLength": dataLength,  # len(payload) - 1 per CCSDS spec
    }


def parsePacket(rawData: bytes, offset: int = 0) -> dict | None:
    """
    Extract one CCSDS packet starting at `offset` inside `rawData`.

    The packet layout is:
        [6 bytes header] [N bytes payload] [2 bytes CRC]
    where N = header.dataLength + 1.

    Args:
        rawData: Full byte stream (may contain multiple packets).
        offset:  Byte position where this packet starts.

    Returns:
        dict with header fields + 'payload' (bytes) + 'crcValid' (bool)
        + 'totalSize' (int), or None if not enough bytes remain.
    """
    if offset + MIN_PACKET > len(rawData):
        return None

    rawHeader = rawData[offset : offset + HEADER_SIZE]
    header = parseHeader(rawHeader)

    payloadSize = header["dataLength"] + 1  # CCSDS: dataLength = len(payload) - 1
    totalSize = HEADER_SIZE + payloadSize + CRC_SIZE

    if offset + totalSize > len(rawData):
        return None  # Incomplete packet

    payload = rawData[offset + HEADER_SIZE : offset + HEADER_SIZE + payloadSize]
    crcBytes = rawData[offset + HEADER_SIZE + payloadSize : offset + totalSize]

    receivedCrc = struct.unpack(">H", crcBytes)[0]
    computedCrc = binascii.crc_hqx(rawHeader + payload, 0xFFFF)
    crcValid = receivedCrc == computedCrc

    return {
        **header,
        "payload": payload,
        "receivedCrc": receivedCrc,
        "computedCrc": computedCrc,
        "crcValid": crcValid,
        "totalSize": totalSize,
    }


def parseStream(rawData: bytes) -> list[dict]:
    """
    Parse an entire byte stream containing one or more concatenated packets.

    Args:
        rawData: Raw bytes (output from the transmitter).

    Returns:
        List of parsed packet dicts (same structure as parsePacket output).
    """
    packets = []
    offset = 0

    while offset < len(rawData):
        packet = parsePacket(rawData, offset)
        if packet is None:
            print(
                f"[WARNING] Could not parse packet at offset {offset}. Remaining bytes: {len(rawData) - offset}"
            )
            break
        packets.append(packet)
        offset += packet["totalSize"]

    return packets
