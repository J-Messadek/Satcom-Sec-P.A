"""Validation des trames : CRC (intégrité) et HMAC-SHA256 (authenticité)."""

import hmac
import hashlib


def validate_crc(packet: dict) -> bool:
    return packet.get("crcValid", False)


def compute_hmac(header_bytes: bytes, payload: bytes, secret_key: bytes) -> bytes:
    mac = hmac.new(secret_key, digestmod=hashlib.sha256)
    mac.update(header_bytes)
    mac.update(payload)
    return mac.digest()


def validate_hmac(header_bytes: bytes, payload: bytes,
                  received_hmac: bytes, secret_key: bytes) -> bool:
    expected = compute_hmac(header_bytes, payload, secret_key)
    return hmac.compare_digest(expected, received_hmac)  # constant-time


def validate_packet(packet: dict, raw_data: bytes = None,
                    secret_key: bytes = None, hmac_tag: bytes = None) -> dict:
    crc_ok = validate_crc(packet)
    hmac_ok = None
    if secret_key is not None and hmac_tag is not None and raw_data is not None:
        hmac_ok = validate_hmac(raw_data[0:6], packet["payload"], hmac_tag, secret_key)
    return {
        "crcOk": crc_ok,
        "hmacOk": hmac_ok,
        "valid": crc_ok and (hmac_ok is not False),
    }
