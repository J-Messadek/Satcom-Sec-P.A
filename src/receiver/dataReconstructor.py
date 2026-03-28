# =============================================================
# dataReconstructor.py
# Reconstructs the original data (text or binary image) from
# a list of validated CCSDS packets.
#
# Steps:
#   1. Sort packets by sequence number (seqCount).
#   2. Detect and report any missing or duplicate packets.
#   3. Concatenate payloads in order.
#   4. (Optional) Write the result to a file.
# =============================================================

import os


def sortPackets(packets: list[dict]) -> list[dict]:
    """
    Sort a list of parsed packets by their sequence counter (seqCount).
    """
    return sorted(packets, key=lambda p: p["seqCount"])


def detectMissing(packets: list[dict]) -> list[int]:
    """
    Identify missing sequence numbers in the received stream.
    """
    if not packets:
        return []
    seqNumbers = [p["seqCount"] for p in packets]
    firstSeq   = seqNumbers[0]
    lastSeq    = seqNumbers[-1]
    expected   = set(range(firstSeq, lastSeq + 1))
    received   = set(seqNumbers)
    return sorted(expected - received)


def reconstructData(packets: list[dict], discardInvalid: bool = True) -> bytes:
    """Reassemble payload data from a list of packets."""
    sortedPackets = sortPackets(packets)
    missing = detectMissing(sortedPackets)
    if missing:
        print(f"[WARNING] Missing sequence numbers: {missing}")
    rawData = b""
    for pkt in sortedPackets:
        if discardInvalid and not pkt.get("crcValid", False):
            print(f"[WARNING] Discarding invalid frame seqCount={pkt['seqCount']} (CRC mismatch)")
            continue
        rawData += pkt["payload"]
    return rawData


def saveToFile(data: bytes, outputPath: str) -> None:
    os.makedirs(os.path.dirname(outputPath), exist_ok=True)
    with open(outputPath, "wb") as f:
        f.write(data)
    print(f"[OK] Reconstructed data saved to: {outputPath}")


def reconstruct(packets: list[dict], outputPath: str = None, discardInvalid: bool = True) -> bytes:
    """Full reconstruction pipeline: sort → validate → concatenate → (save)."""
    data = reconstructData(packets, discardInvalid=discardInvalid)
    if outputPath:
        saveToFile(data, outputPath)
    print(f"[INFO] Reconstruction complete: {len(packets)} packets → {len(data)} bytes")
    return data
