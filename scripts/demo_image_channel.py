# =========================
# Ce fichier a pour but de motrer comment une trame CCSDS standard est crée.
# On envoi 2 paquets de télémétrie (payload "hello" et "world") dans une même trame.
# Puis on affiche la trame complète (header + payload + CRC) en binaire.
# =========================

import struct
import binascii
from pathlib import Path

import yaml
from PIL import Image

from channel import reed_solomon as sm
from channel import jamming as jm

with open("config/exemple_config.yml", "r") as f:
    config = yaml.safe_load(f)


# =========================
# 1. Données à transmettre
# =========================
payload_1 = b"hello world how are you"
payload_2 = b"fine and you"

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
# 4. Transmission image + protections canal
# =========================
isactivatedreed = config["activation"]["reed_solomon"]
isactivatedjam = config["activation"]["jamming"]

image_path = Path(config["data_paths"]["input_image"])
output_image_path = Path(config["data_paths"]["output_image"])
output_image_path.parent.mkdir(parents=True, exist_ok=True)

with image_path.open("rb") as img:
    original_packet = img.read()

packet = original_packet
jam_report = None
rs_report = None

if isactivatedreed:
    rs_config = config.get("channel_simulation", {}).get("reed_solomon", {})
    sm_protector = sm.ReedSolomonProtector(ecc_symbols=int(rs_config.get("ecc_symbols", 32)))

    if isactivatedjam:
        jammer = jm.SatelliteJammer.from_yaml("config/exemple_config.yml")
        rs_report = sm_protector.simulate_protection(original_packet, jammer.jam_bytes)
        packet = rs_report["recovered_data"]
        jam_report = rs_report.get("jam_report")
    else:
        encoded_packet = sm_protector.encode(original_packet)
        packet, _ = sm_protector.decode(encoded_packet)
elif isactivatedjam:
    jammer = jm.SatelliteJammer.from_yaml("config/exemple_config.yml")
    packet, jam_report = jammer.jam_bytes(original_packet)

with output_image_path.open("wb") as received_file:
    received_file.write(packet)

# =========================
# 6. Affichage / diagnostic
# =========================
print(f"Image reconstruite sauvegardée dans : {output_image_path}")

if jam_report is not None:
    active_modes = ", ".join(jam_report.active_modes) or jam_report.mode
    print(
        "[Jamming] "
        f"mode={jam_report.mode} "
        f"modes={active_modes} "
        f"bits_inversés={jam_report.flipped_bits} "
        f"BER={jam_report.estimated_ber:.6f} "
        f"sévérité={jam_report.severity}"
    )

if rs_report is not None:
    print(
        "[Reed-Solomon] "
        f"statut={rs_report['status']} "
        f"capacité={rs_report['correction_capacity']} octets "
        f"résiduel={rs_report['residual_byte_errors']} octet(s)"
    )

try:
    received_image = Image.open(output_image_path)
    received_image.show()
except Exception as e:
    print("Impossible d'afficher l'image :", e)