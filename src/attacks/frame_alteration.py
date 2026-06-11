# =============================================================
# frame_alteration.py  –  Attaque 2 : Altération de trames
#
# Simule un attaquant qui modifie les en-têtes CCSDS d'une trame
# en transit, puis recalcule le CRC pour masquer l'altération.
#
# Vecteurs d'attaque couverts :
#   1. Altération de l'APID        → fausse l'identité de la source
#   2. Altération du seqCount      → désordonne la reconstruction
#   3. Fuzzing du payload          → corrompt les données utiles
#   4. Fuzzing aléatoire du header → perturbation non ciblée
#   5. Injection d'une fausse trame complète dans le flux
#
# Résultat sans défense :
#   → Le CRC est reforgé par l'attaquant → la validation CRC passe.
# Résultat avec Défense 2 (HMAC-SHA256) :
#   → L'attaquant ne connaît pas la clé secrète → HMAC invalide → trame rejetée.
# =============================================================

import random

from ..protocol.frame import build_packet
from ..receiver.frame_parser import parse_stream


# ==============================================================
# Internal helpers
# ==============================================================

def _rebuild_packet(apid: int, seq_flags: int, seq_count: int,
                    version: int, packet_type: int, sec_hdr_flag: int,
                    payload: bytes) -> bytes:
    """Reconstruct a valid CCSDS packet with a freshly computed CRC."""
    return build_packet(
        payload, seq_count, seq_flags,
        apid=apid, version=version,
        packet_type=packet_type, sec_hdr_flag=sec_hdr_flag,
    )


def _offset_in_stream(packets: list[dict], target_seq: int) -> int:
    """Return the byte offset of the target_seq packet inside the stream."""
    offset = 0
    for pkt in packets:
        if pkt["seqCount"] == target_seq:
            return offset
        offset += pkt["totalSize"]
    return -1


# ==============================================================
# Attack 1 – APID spoofing
# ==============================================================

def alter_apid(raw_stream: bytes, target_seq: int,
               fake_apid: int, verbose: bool = True) -> bytes:
    """
    Replace the APID of a specific packet with a forged value.
    CRC is recomputed so the receiver's CRC check still passes.
    """
    packets = parse_stream(raw_stream)
    result = bytearray(raw_stream)

    for pkt in packets:
        if pkt["seqCount"] != target_seq:
            continue

        offset = _offset_in_stream(packets, target_seq)
        new_pkt = _rebuild_packet(
            apid=fake_apid,
            seq_flags=pkt["seqFlags"], seq_count=pkt["seqCount"],
            version=pkt["version"], packet_type=pkt["packetType"],
            sec_hdr_flag=pkt["secHdrFlag"], payload=pkt["payload"],
        )
        result[offset : offset + pkt["totalSize"]] = new_pkt

        if verbose:
            print(f"[ATTACK-2] APID spoof seqCount={target_seq}: "
                  f"{pkt['apid']} → {fake_apid}  (CRC reforged)")
        break

    return bytes(result)


# ==============================================================
# Attack 2 – Sequence counter manipulation
# ==============================================================

def alter_seq_count(raw_stream: bytes, target_seq: int,
                    new_seq: int, verbose: bool = True) -> bytes:
    """Replace the seqCount of a packet to disrupt reassembly order."""
    packets = parse_stream(raw_stream)
    result = bytearray(raw_stream)

    for pkt in packets:
        if pkt["seqCount"] != target_seq:
            continue

        offset = _offset_in_stream(packets, target_seq)
        new_pkt = _rebuild_packet(
            apid=pkt["apid"], seq_flags=pkt["seqFlags"], seq_count=new_seq,
            version=pkt["version"], packet_type=pkt["packetType"],
            sec_hdr_flag=pkt["secHdrFlag"], payload=pkt["payload"],
        )
        result[offset : offset + pkt["totalSize"]] = new_pkt

        if verbose:
            print(f"[ATTACK-2] seqCount alteration: {target_seq} → {new_seq}  "
                  f"(CRC reforged)")
        break

    return bytes(result)


# ==============================================================
# Attack 3 – Payload fuzzing (random bit flip in payload)
# ==============================================================

def fuzz_payload(raw_stream: bytes, target_seq: int,
                 num_flips: int = 1, verbose: bool = True) -> bytes:
    """Flip random bits in the payload of a packet, then recompute CRC."""
    packets = parse_stream(raw_stream)
    result = bytearray(raw_stream)

    for pkt in packets:
        if pkt["seqCount"] != target_seq:
            continue

        offset = _offset_in_stream(packets, target_seq)
        fuzzed_payload = bytearray(pkt["payload"])

        flipped_positions = []
        for _ in range(min(num_flips, len(fuzzed_payload))):
            pos = random.randint(0, len(fuzzed_payload) - 1)
            fuzzed_payload[pos] ^= random.randint(1, 0xFF)
            flipped_positions.append(pos)

        new_pkt = _rebuild_packet(
            apid=pkt["apid"], seq_flags=pkt["seqFlags"], seq_count=pkt["seqCount"],
            version=pkt["version"], packet_type=pkt["packetType"],
            sec_hdr_flag=pkt["secHdrFlag"], payload=bytes(fuzzed_payload),
        )
        result[offset : offset + pkt["totalSize"]] = new_pkt

        if verbose:
            print(f"[ATTACK-2] Payload fuzz seqCount={target_seq}: "
                  f"{num_flips} flip(s) at positions {flipped_positions}  "
                  f"(CRC reforged)")
        break

    return bytes(result)


# ==============================================================
# Attack 4 – Full header fuzzing (random header values)
# ==============================================================

def fuzz_header(raw_stream: bytes, target_seq: int,
                verbose: bool = True) -> bytes:
    """Randomize all primary-header fields and recompute CRC."""
    packets = parse_stream(raw_stream)
    result = bytearray(raw_stream)

    for pkt in packets:
        if pkt["seqCount"] != target_seq:
            continue

        offset = _offset_in_stream(packets, target_seq)
        new_pkt = _rebuild_packet(
            apid=random.randint(0, 0x7FF),
            seq_flags=random.randint(0, 3),
            seq_count=random.randint(0, 0x3FFF),
            version=random.randint(0, 7),
            packet_type=random.randint(0, 1),
            sec_hdr_flag=random.randint(0, 1),
            payload=pkt["payload"],
        )
        result[offset : offset + pkt["totalSize"]] = new_pkt

        if verbose:
            print(f"[ATTACK-2] Full header fuzz seqCount={target_seq}  "
                  f"(CRC reforged)")
        break

    return bytes(result)


# ==============================================================
# Attack 5 – Packet injection (insert a forged packet)
# ==============================================================

def inject_packet(raw_stream: bytes, fake_payload: bytes,
                  fake_seq: int, insert_after_seq: int,
                  verbose: bool = True) -> bytes:
    """Inject a completely forged packet into the stream after a given seqCount."""
    packets = parse_stream(raw_stream)

    # Build the fake packet (reuse apid/flags from the first real packet).
    ref = packets[0] if packets else {
        "apid": 1, "seqFlags": 3, "version": 0, "packetType": 0, "secHdrFlag": 0,
    }
    fake = _rebuild_packet(
        apid=ref["apid"], seq_flags=ref["seqFlags"], seq_count=fake_seq,
        version=ref["version"], packet_type=ref["packetType"],
        sec_hdr_flag=ref["secHdrFlag"], payload=fake_payload,
    )

    # Find insertion point.
    insert_offset = 0
    for pkt in packets:
        insert_offset += pkt["totalSize"]
        if pkt["seqCount"] == insert_after_seq:
            break

    result = raw_stream[:insert_offset] + fake + raw_stream[insert_offset:]

    if verbose:
        print(f"[ATTACK-2] Injected fake packet seqCount={fake_seq} "
              f"after seqCount={insert_after_seq}  ({len(fake)} bytes)")

    return result
