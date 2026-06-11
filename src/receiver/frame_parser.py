"""Décodage d'un flux binaire en trames CCSDS structurées."""

import struct
import binascii

HEADER_SIZE = 6
CRC_SIZE = 2
MIN_PACKET = HEADER_SIZE + CRC_SIZE


def parse_header(raw_header: bytes) -> dict:
    if len(raw_header) < HEADER_SIZE:
        raise ValueError(f"Header too short: {len(raw_header)} bytes (expected {HEADER_SIZE})")

    word1, word2, data_length = struct.unpack(">HHH", raw_header)
    return {
        "version": (word1 >> 13) & 0x07,
        "packetType": (word1 >> 12) & 0x01,
        "secHdrFlag": (word1 >> 11) & 0x01,
        "apid": word1 & 0x07FF,
        "seqFlags": (word2 >> 14) & 0x03,
        "seqCount": word2 & 0x3FFF,
        "dataLength": data_length,  # CCSDS : len(payload) - 1
    }


def parse_packet(raw_data: bytes, offset: int = 0) -> dict | None:
    """Extrait un paquet [header | payload | CRC]. None si octets insuffisants."""
    if offset + MIN_PACKET > len(raw_data):
        return None

    raw_header = raw_data[offset : offset + HEADER_SIZE]
    header = parse_header(raw_header)

    payload_size = header["dataLength"] + 1
    total_size = HEADER_SIZE + payload_size + CRC_SIZE
    if offset + total_size > len(raw_data):
        return None

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
    packets = []
    offset = 0
    while offset < len(raw_data):
        packet = parse_packet(raw_data, offset)
        if packet is None:
            break
        packets.append(packet)
        offset += packet["totalSize"]
    return packets
