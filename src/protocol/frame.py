"""Construction des trames CCSDS (Space Packet Protocol).

Source unique de construction de paquets pour tout le projet : émetteur
(`encoding`), scénarios (`scripts`) et attaques (`attacks`) doivent passer par
`build_packet` plutôt que de réimplémenter le header.

Format d'un paquet :
    [6 octets header primaire] [N octets payload] [2 octets CRC-16/CCITT]
"""

import struct
import binascii

# Champs CCSDS par défaut
DEFAULT_VERSION = 0
DEFAULT_PACKET_TYPE = 0  # 0 = télémétrie
DEFAULT_SEC_HDR_FLAG = 0
DEFAULT_APID = 1

# Indicateurs de séquence (seq_flags)
SEQ_FLAG_CONTINUATION = 0b00  # trame intermédiaire
SEQ_FLAG_FIRST = 0b01  # début de trame
SEQ_FLAG_LAST = 0b10  # fin de trame
SEQ_FLAG_UNSEGMENTED = 0b11  # paquet complet (non segmenté)


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
    """Construit un paquet CCSDS complet (header + payload + CRC).

    Les champs d'en-tête sont optionnels afin de couvrir aussi la
    reconstruction de paquets forgés (cf. `attacks`).
    """
    packet_length = len(payload) - 1  # CCSDS : len(payload) - 1

    word1 = (
        ((version & 0x07) << 13)
        | ((packet_type & 0x01) << 12)
        | ((sec_hdr_flag & 0x01) << 11)
        | (apid & 0x7FF)
    )
    word2 = ((seq_flags & 0x03) << 14) | (seq_count & 0x3FFF)

    primary_header = struct.pack(">HHH", word1, word2, packet_length)
    packet = primary_header + bytes(payload)

    crc = binascii.crc_hqx(packet, 0xFFFF)
    return packet + struct.pack(">H", crc)
