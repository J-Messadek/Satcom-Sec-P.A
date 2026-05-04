from src.protocol.frame import build_packet  # ✅ ça marche


def read_image_as_bytes(image_path):
    with open(image_path, "rb") as f:
        return f.read()


def send_image(image_path, preprocessor=None):
    i = 0
    seq_count = 0
    packets = []
    payload = read_image_as_bytes(image_path)
    size_payload = len(payload)
    while i < size_payload:
        payload_part = payload[i : i + 512]  # on envoi des paquets de 512 bytes

        if preprocessor:
            payload_part = preprocessor(payload_part)

        if i == 0:
            seq_flags = 0b01  # début de la trame
        elif i + len(payload[i : i + 512]) >= size_payload:
            seq_flags = 0b10  # fin de la trame
        else:
            seq_flags = 0b00  # trame intermédiaire

        packet = build_packet(payload_part, seq_count, seq_flags)

        seq_count += 1
        i += 512
        packets.append(packet)
    return packets
