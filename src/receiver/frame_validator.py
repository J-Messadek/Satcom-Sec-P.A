"""Validation d'intégrité des trames (CRC calculé par le parseur)."""


def validate_crc(packet: dict) -> bool:
    return packet.get("crcValid", False)
