import struct
import binascii

version = 0
packet_type = 0  # télémétrie
sec_hdr_flag = 0
apid = 1


def build_packet(payload, seq_count, seq_flags):
    packet_length = len(payload) - 1

    first_16bits = (version << 13) | (packet_type << 12) | (sec_hdr_flag << 11) | apid

    second_16bits = (seq_flags << 14) | seq_count

    primary_header = struct.pack(">HHH", first_16bits, second_16bits, packet_length)

    packet = primary_header + payload
    crc = binascii.crc_hqx(packet, 0xFFFF)
    packet += struct.pack(">H", crc)
    return packet
