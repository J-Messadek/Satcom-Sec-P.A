# =========================
# Ce fichier a pour but de motrer comment une trame CCSDS standard est crée. 
# =========================

import struct
import binascii

# =========================
# 1. Donnée à transmettre
# =========================
payload = b"hello"

# =========================
# 2. Champs CCSDS
# =========================
version = 0
packet_type = 0      # télémétrie
sec_hdr_flag = 0
apid = 1

seq_flags = 0b11     # paquet complet
seq_count = 1

packet_length = len(payload) - 1

# =========================
# 3. Construction du header
# =========================
first_16bits = (
    (version << 13) |
    (packet_type << 12) |
    (sec_hdr_flag << 11) |
    apid
)

second_16bits = (
    (seq_flags << 14) |
    seq_count
)

primary_header = struct.pack(
    ">HHH",
    first_16bits,
    second_16bits,
    packet_length
)

# =========================
# 4. Assemblage du paquet
# =========================
packet = primary_header + payload

# =========================
# 5. CRC
# =========================
crc = binascii.crc_hqx(packet, 0xFFFF)
packet += struct.pack(">H", crc)

# =========================
# 6. Affichage
# =========================
print(packet.hex())
