# =============================================================
# frame_parser.py
# Parses raw binary data into structured CCSDS frames.
# Extracts header fields, payload and CRC from a byte stream.
# =============================================================

import struct
import binascii

# ---- Constants -----------------------------------------------
HEADER_SIZE = 6  # Primary header: 3 x 16-bit words
CRC_SIZE = 2  # CRC-16 (CCITT / crc_hqx) appended at the end
MIN_PACKET = HEADER_SIZE + CRC_SIZE  # Minimum valid packet size (no payload)


def parse_header(raw_header: bytes) -> dict:
    """
    Decode the 6-byte CCSDS primary header.

    Args:
        raw_header: Exactly 6 bytes.

    Returns:
        dict with keys: version, packetType, secHdrFlag,
                        apid, seqFlags, seqCount, dataLength
    """
    if len(raw_header) < HEADER_SIZE:
        raise ValueError(
            f"Header too short: {len(raw_header)} bytes (expected {HEADER_SIZE})"
        )

    word1, word2, data_length = struct.unpack(">HHH", raw_header)

    return {
        "version": (word1 >> 13) & 0x07,
        "packetType": (word1 >> 12) & 0x01,
        "secHdrFlag": (word1 >> 11) & 0x01,
        "apid": word1 & 0x07FF,
        "seqFlags": (word2 >> 14) & 0x03,
        "seqCount": word2 & 0x3FFF,
        "dataLength": data_length,  # len(payload) - 1 per CCSDS spec
    }


def parse_packet(raw_data: bytes, offset: int = 0) -> dict | None:
    """
    Extract one CCSDS packet starting at `offset` inside `raw_data`.

    The packet layout is:
        [6 bytes header] [N bytes payload] [2 bytes CRC]
    where N = header.dataLength + 1.

    Returns:
        dict with header fields + 'payload' (bytes) + 'crcValid' (bool)
        + 'totalSize' (int), or None if not enough bytes remain.
    """
    if offset + MIN_PACKET > len(raw_data):
        return None

    raw_header = raw_data[offset : offset + HEADER_SIZE]
    header = parse_header(raw_header)

    payload_size = header["dataLength"] + 1  # CCSDS: dataLength = len(payload) - 1
    total_size = HEADER_SIZE + payload_size + CRC_SIZE

    if offset + total_size > len(raw_data):
        return None  # Incomplete packet

    payload = raw_data[offset + HEADER_SIZE : offset + HEADER_SIZE + payload_size]
    crc_bytes = raw_data[offset + HEADER_SIZE + payload_size : offset + total_size]

    received_crc = struct.unpack(">H", crc_bytes)[0]
    computed_crc = binascii.crc_hqx(raw_header + payload, 0xFFFF)

    return {
        **header,
        "payload": payload,
        "receivedCrc": received_crc,
        "computedCrc": computed_crc,
        "crcValid": received_crc == computed_crc,
        "totalSize": total_size,
    }


def parse_stream(raw_data: bytes) -> list[dict]:
    """
    Parse an entire byte stream containing one or more concatenated packets.

    Returns:
        List of parsed packet dicts (same structure as parse_packet output).
    """
    packets = []
    offset = 0

    while offset < len(raw_data):
        packet = parse_packet(raw_data, offset)
        if packet is None:
            print(
                f"[WARNING] Could not parse packet at offset {offset}. "
                f"Remaining bytes: {len(raw_data) - offset}"
            )
            break
        packets.append(packet)
        offset += packet["totalSize"]

    return packets
