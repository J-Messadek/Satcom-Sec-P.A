# =========================
# Ce fichier a pour but de motrer comment une trame CCSDS standard est crée.
# On envoi 2 paquets de télémétrie (payload "hello" et "world") dans une même trame.
# Puis on affiche la trame complète (header + payload + CRC) en binaire.
# =========================

import struct
import binascii

# =========================
# 1. Données à transmettre
# =========================
payload_1 = b"hello"
payload_2 = b"world"

# =========================
# 2. Champs CCSDS
# =========================
version = 0
packet_type = 0  # télémétrie
sec_hdr_flag = 0
apid = 1

seq_flags = 0b11  # paquet complet
seq_count = 1


# =========================
# 3. Construction du header + paquet
# =========================
def build_packet(payload, seq_count):
    packet_length = len(payload) - 1

    first_16bits = (version << 13) | (packet_type << 12) | (sec_hdr_flag << 11) | apid

    second_16bits = (seq_flags << 14) | seq_count

    primary_header = struct.pack(">HHH", first_16bits, second_16bits, packet_length)

    packet = primary_header + payload

    crc = binascii.crc_hqx(packet, 0xFFFF)
    packet += struct.pack(">H", crc)
    return packet


packet_1 = build_packet(payload_1, seq_count)
packet_2 = build_packet(payload_2, seq_count + 1)

# =========================
# 4. Assemblage des deux trames
# =========================
packet = packet_1 + packet_2

# =========================
# 6. Affichage
# =========================
print(packet)
