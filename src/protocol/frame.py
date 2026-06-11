"""Construction des trames CCSDS : [header 6o | payload | CRC-16 2o]."""

import struct
import binascii

DEFAULT_VERSION = 0
DEFAULT_PACKET_TYPE = 0  # 0 = télémétrie
DEFAULT_SEC_HDR_FLAG = 0
DEFAULT_APID = 1

SEQ_FLAG_CONTINUATION = 0b00
SEQ_FLAG_FIRST = 0b01
SEQ_FLAG_LAST = 0b10
SEQ_FLAG_UNSEGMENTED = 0b11


def build_packet(
    payload,
    seq_count,
    seq_flags=SEQ_FLAG_UNSEGMENTED,
    *,
    apid=DEFAULT_APID,
    version=DEFAULT_VERSION,
    packet_type=DEFAULT_PACKET_TYPE,
    sec_hdr_flag=DEFAULT_SEC_HDR_FLAG,
):
    word1 = (
        ((version & 0x07) << 13)
        | ((packet_type & 0x01) << 12)
        | ((sec_hdr_flag & 0x01) << 11)
        | (apid & 0x7FF)
    )
    word2 = ((seq_flags & 0x03) << 14) | (seq_count & 0x3FFF)

    header = struct.pack(">HHH", word1, word2, len(payload) - 1)
    packet = header + bytes(payload)
    return packet + struct.pack(">H", binascii.crc_hqx(packet, 0xFFFF))
