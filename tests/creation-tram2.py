# =========================
# Ce fichier a pour but de motrer comment une trame CCSDS standard est crée.
# Dorénavant on envoi une image
#
# =========================

import struct
import binascii

version = 0
packet_type = 0  # télémétrie
sec_hdr_flag = 0
apid = 1
seq_count = 0
i = 0


def build_packet(payload, seq_count, seq_flags):
    packet_length = len(payload) - 1

    first_16bits = (version << 13) | (packet_type << 12) | (sec_hdr_flag << 11) | apid

    second_16bits = (seq_flags << 14) | seq_count

    primary_header = struct.pack(">HHH", first_16bits, second_16bits, packet_length)

    packet = primary_header + payload
    crc = binascii.crc_hqx(packet, 0xFFFF)
    packet += struct.pack(">H", crc)
    return packet


def read_image_as_bytes(image_path):
    with open(image_path, "rb") as f:
        return f.read()


payload = read_image_as_bytes("../data/input/image_source.png")
size_payload = len(payload)
print(f"Size of payload: {size_payload} bytes")

while i < size_payload:
    payload_part = payload[i : i + 1000]  # on envoi des paquets de 1000 bytes

    if i == 0:
        seq_flags = 0b01  # début de la trame
    elif i + len(payload_part) >= size_payload:
        seq_flags = 0b10  # fin de la trame
    else:
        seq_flags = 0b00  # trame intermédiaire

    packet = build_packet(payload_part, seq_count, seq_flags)

    seq_count += 1
    i += 1000
    print(packet, seq_count)

print("All packets sent.")
