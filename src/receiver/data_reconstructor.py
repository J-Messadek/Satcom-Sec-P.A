# =============================================================
# data_reconstructor.py
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


def sort_packets(packets: list[dict]) -> list[dict]:
    """Sort a list of parsed packets by their sequence counter (seqCount)."""
    return sorted(packets, key=lambda p: p["seqCount"])


def detect_missing(packets: list[dict]) -> list[int]:
    """Identify missing sequence numbers in the received stream."""
    if not packets:
        return []
    seq_numbers = [p["seqCount"] for p in packets]
    expected = set(range(seq_numbers[0], seq_numbers[-1] + 1))
    return sorted(expected - set(seq_numbers))


def reconstruct_data(packets: list[dict], discard_invalid: bool = True) -> bytes:
    """Reassemble payload data from a list of packets."""
    sorted_packets = sort_packets(packets)
    missing = detect_missing(sorted_packets)
    if missing:
        print(f"[WARNING] Missing sequence numbers: {missing}")

    raw_data = b""
    for pkt in sorted_packets:
        if discard_invalid and not pkt.get("crcValid", False):
            print(
                f"[WARNING] Discarding invalid frame seqCount={pkt['seqCount']} "
                f"(CRC mismatch)"
            )
            continue
        raw_data += pkt["payload"]
    return raw_data


def save_to_file(data: bytes, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(data)
    print(f"[OK] Reconstructed data saved to: {output_path}")


def reconstruct(packets: list[dict], output_path: str = None,
                discard_invalid: bool = True) -> bytes:
    """Full reconstruction pipeline: sort → validate → concatenate → (save)."""
    data = reconstruct_data(packets, discard_invalid=discard_invalid)
    if output_path:
        save_to_file(data, output_path)
    print(f"[INFO] Reconstruction complete: {len(packets)} packets → {len(data)} bytes")
    return data
