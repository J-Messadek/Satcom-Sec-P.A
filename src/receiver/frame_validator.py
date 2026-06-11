# =============================================================
# frame_validator.py
# Validates the integrity and authenticity of received frames.
#
# Two levels of protection:
#   - CRC-16  : fast bit-error detection (from transmitter)
#   - HMAC-SHA256 : cryptographic authentication (Attaque 2 / Défense 2)
# =============================================================

import hmac
import hashlib

# ---- Constants -----------------------------------------------
HMAC_DIGEST_SIZE = 32  # SHA-256 produces 32 bytes


# ==============================================================
# Level 1 – CRC validation (already computed in frame_parser)
# ==============================================================

def validate_crc(packet: dict) -> bool:
    """
    Check whether the CRC embedded in the packet matches the recomputed one.

    Returns:
        True if CRC is valid, False if the frame has been altered or corrupted.
    """
    return packet.get("crcValid", False)


# ==============================================================
# Level 2 – HMAC-SHA256 authentication (Défense 2)
# ==============================================================

def compute_hmac(header_bytes: bytes, payload: bytes, secret_key: bytes) -> bytes:
    """Compute a HMAC-SHA256 over the header + payload (32-byte digest)."""
    mac = hmac.new(secret_key, digestmod=hashlib.sha256)
    mac.update(header_bytes)
    mac.update(payload)
    return mac.digest()


def validate_hmac(header_bytes: bytes, payload: bytes,
                  received_hmac: bytes, secret_key: bytes) -> bool:
    """
    Verify that the received HMAC matches the one we would compute.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    expected = compute_hmac(header_bytes, payload, secret_key)
    return hmac.compare_digest(expected, received_hmac)


# ==============================================================
# High-level helper
# ==============================================================

def validate_packet(packet: dict, raw_data: bytes = None,
                    secret_key: bytes = None, hmac_tag: bytes = None) -> dict:
    """
    Run all available validation checks on a parsed packet.

    Returns:
        dict with keys:
            'crcOk'  (bool),
            'hmacOk' (bool | None)  – None if HMAC not checked,
            'valid'  (bool)         – True only if all checked layers pass.
    """
    crc_ok = validate_crc(packet)
    hmac_ok = None

    if secret_key is not None and hmac_tag is not None and raw_data is not None:
        header_bytes = raw_data[0:6]
        hmac_ok = validate_hmac(header_bytes, packet["payload"], hmac_tag, secret_key)

    return {
        "crcOk": crc_ok,
        "hmacOk": hmac_ok,
        "valid": crc_ok and (hmac_ok is not False),
    }
