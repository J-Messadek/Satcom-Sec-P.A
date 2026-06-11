# =============================================================
# frameValidator.py
# Validates the integrity and authenticity of received frames.
#
# Two levels of protection:
#   - CRC-16  : fast bit-error detection (from transmitter)
#   - HMAC-SHA256 : cryptographic authentication (Attaque 2 / Défense 2)
# =============================================================

import hmac
import hashlib

# ---- Constants -----------------------------------------------
HMAC_DIGEST_SIZE = 32   # SHA-256 produces 32 bytes


# ==============================================================
# Level 1 – CRC validation (already computed in frameParser)
# ==============================================================

def validateCrc(packet: dict) -> bool:
    """
    Check whether the CRC embedded in the packet matches the recomputed one.

    Args:
        packet: Dict returned by frameParser.parsePacket().

    Returns:
        True if CRC is valid, False if the frame has been altered or corrupted.
    """
    return packet.get("crcValid", False)


# ==============================================================
# Level 2 – HMAC-SHA256 authentication (Défense 2)
# ==============================================================

def computeHmac(headerBytes: bytes, payload: bytes, secretKey: bytes) -> bytes:
    """
    Compute a HMAC-SHA256 over the header + payload.

    Args:
        headerBytes: Raw 6-byte primary header.
        payload:     Raw payload bytes.
        secretKey:   Shared secret key (bytes).

    Returns:
        32-byte HMAC digest.
    """
    mac = hmac.new(secretKey, digestmod=hashlib.sha256)
    mac.update(headerBytes)
    mac.update(payload)
    return mac.digest()


def validateHmac(headerBytes: bytes, payload: bytes,
                 receivedHmac: bytes, secretKey: bytes) -> bool:
    """
    Verify that the received HMAC matches the one we would compute.
    Uses hmac.compare_digest to prevent timing attacks.

    Args:
        headerBytes:  Raw 6-byte primary header.
        payload:      Raw payload bytes.
        receivedHmac: HMAC tag received alongside the packet.
        secretKey:    Shared secret key (bytes).

    Returns:
        True if the HMAC is valid (frame is authentic), False otherwise.
    """
    expected = computeHmac(headerBytes, payload, secretKey)
    return hmac.compare_digest(expected, receivedHmac)


# ==============================================================
# High-level helper
# ==============================================================

def validatePacket(packet: dict, rawData: bytes = None,
                   secretKey: bytes = None, hmacTag: bytes = None) -> dict:
    """
    Run all available validation checks on a parsed packet.

    Args:
        packet:    Dict from frameParser.parsePacket().
        rawData:   Full raw byte stream (used to extract raw header).
        secretKey: If provided, also run HMAC validation.
        hmacTag:   HMAC tag to verify against (required if secretKey given).

    Returns:
        dict with keys:
            'crcOk'    (bool),
            'hmacOk'   (bool | None),   None if HMAC not checked
            'valid'    (bool)            True only if all checked layers pass
    """
    crcOk  = validateCrc(packet)
    hmacOk = None

    if secretKey is not None and hmacTag is not None and rawData is not None:
        offset     = 0
        headerBytes = rawData[offset: offset + 6]
        hmacOk      = validateHmac(headerBytes, packet["payload"], hmacTag, secretKey)

    valid = crcOk and (hmacOk is not False)

    return {
        "crcOk":  crcOk,
        "hmacOk": hmacOk,
        "valid":  valid,
    }
