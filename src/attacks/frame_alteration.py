"""Attaque 2 — altération de trames : l'attaquant modifie une trame et reforge
le CRC pour masquer la falsification (la couche CRC seule est alors trompée)."""

import random

from ..protocol.frame import build_packet
from ..receiver.frame_parser import parse_stream


def _rebuild_packet(pkt: dict, *, apid=None, seq_count=None, payload=None) -> bytes:
    """Reconstruit une trame valide (CRC recalculé) à partir d'une trame parsée."""
    return build_packet(
        payload if payload is not None else pkt["payload"],
        seq_count if seq_count is not None else pkt["seqCount"],
        pkt["seqFlags"],
        apid=apid if apid is not None else pkt["apid"],
        version=pkt["version"],
        packet_type=pkt["packetType"],
        sec_hdr_flag=pkt["secHdrFlag"],
    )


def _offset_in_stream(packets: list[dict], target_seq: int) -> int:
    offset = 0
    for pkt in packets:
        if pkt["seqCount"] == target_seq:
            return offset
        offset += pkt["totalSize"]
    return -1


def _splice(raw_stream: bytes, packets: list[dict], target_seq: int, new_pkt: bytes) -> bytes:
    pkt = next((p for p in packets if p["seqCount"] == target_seq), None)
    if pkt is None:
        return raw_stream
    offset = _offset_in_stream(packets, target_seq)
    result = bytearray(raw_stream)
    result[offset : offset + pkt["totalSize"]] = new_pkt
    return bytes(result)


def alter_apid(raw_stream: bytes, target_seq: int, fake_apid: int, verbose: bool = True) -> bytes:
    packets = parse_stream(raw_stream)
    pkt = next((p for p in packets if p["seqCount"] == target_seq), None)
    if pkt is None:
        return raw_stream
    if verbose:
        print(f"[ATTACK] APID spoof seq={target_seq}: {pkt['apid']} → {fake_apid}")
    return _splice(raw_stream, packets, target_seq, _rebuild_packet(pkt, apid=fake_apid))


def alter_seq_count(raw_stream: bytes, target_seq: int, new_seq: int, verbose: bool = True) -> bytes:
    packets = parse_stream(raw_stream)
    pkt = next((p for p in packets if p["seqCount"] == target_seq), None)
    if pkt is None:
        return raw_stream
    if verbose:
        print(f"[ATTACK] seqCount {target_seq} → {new_seq}")
    return _splice(raw_stream, packets, target_seq, _rebuild_packet(pkt, seq_count=new_seq))


def fuzz_payload(raw_stream: bytes, target_seq: int, num_flips: int = 1, verbose: bool = True) -> bytes:
    packets = parse_stream(raw_stream)
    pkt = next((p for p in packets if p["seqCount"] == target_seq), None)
    if pkt is None:
        return raw_stream

    payload = bytearray(pkt["payload"])
    for _ in range(min(num_flips, len(payload))):
        pos = random.randint(0, len(payload) - 1)
        payload[pos] ^= random.randint(1, 0xFF)

    if verbose:
        print(f"[ATTACK] payload fuzz seq={target_seq}: {num_flips} flip(s)")
    return _splice(raw_stream, packets, target_seq, _rebuild_packet(pkt, payload=bytes(payload)))


def fuzz_header(raw_stream: bytes, target_seq: int, verbose: bool = True) -> bytes:
    packets = parse_stream(raw_stream)
    pkt = next((p for p in packets if p["seqCount"] == target_seq), None)
    if pkt is None:
        return raw_stream

    forged = build_packet(
        pkt["payload"],
        random.randint(0, 0x3FFF),
        random.randint(0, 3),
        apid=random.randint(0, 0x7FF),
        version=random.randint(0, 7),
        packet_type=random.randint(0, 1),
        sec_hdr_flag=random.randint(0, 1),
    )
    if verbose:
        print(f"[ATTACK] header fuzz seq={target_seq}")
    return _splice(raw_stream, packets, target_seq, forged)


def inject_packet(raw_stream: bytes, fake_payload: bytes, fake_seq: int,
                  insert_after_seq: int, verbose: bool = True) -> bytes:
    packets = parse_stream(raw_stream)
    ref = packets[0] if packets else {
        "apid": 1, "seqFlags": 3, "version": 0, "packetType": 0, "secHdrFlag": 0,
    }
    fake = build_packet(
        fake_payload, fake_seq, ref["seqFlags"],
        apid=ref["apid"], version=ref["version"],
        packet_type=ref["packetType"], sec_hdr_flag=ref["secHdrFlag"],
    )

    insert_offset = 0
    for pkt in packets:
        insert_offset += pkt["totalSize"]
        if pkt["seqCount"] == insert_after_seq:
            break

    if verbose:
        print(f"[ATTACK] injected seq={fake_seq} after seq={insert_after_seq}")
    return raw_stream[:insert_offset] + fake + raw_stream[insert_offset:]
