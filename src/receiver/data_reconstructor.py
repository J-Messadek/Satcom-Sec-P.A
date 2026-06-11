"""Reconstruction des données à partir des trames CCSDS reçues."""

import os


def sort_packets(packets: list[dict]) -> list[dict]:
    return sorted(packets, key=lambda p: p["seqCount"])


def detect_missing(packets: list[dict]) -> list[int]:
    if not packets:
        return []
    seq = [p["seqCount"] for p in packets]
    return sorted(set(range(seq[0], seq[-1] + 1)) - set(seq))


def reconstruct_data(packets: list[dict], discard_invalid: bool = True) -> bytes:
    ordered = sort_packets(packets)
    kept = (p for p in ordered if not discard_invalid or p.get("crcValid", False))
    return b"".join(p["payload"] for p in kept)


def save_to_file(data: bytes, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(data)


def reconstruct(packets: list[dict], output_path: str = None,
                discard_invalid: bool = True) -> bytes:
    data = reconstruct_data(packets, discard_invalid=discard_invalid)
    if output_path:
        save_to_file(data, output_path)
    print(f"[INFO] {len(packets)} paquets → {len(data)} octets"
          + (f" → {output_path}" if output_path else ""))
    return data
