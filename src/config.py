# =============================================================
# config.py – Configuration centrale du projet Satcom-Sec-P.A
#
# Centralise toutes les constantes CCSDS, les paramètres de
# sécurité et les valeurs par défaut utilisées par les modules
# d'attaque, de défense et de réception.
# =============================================================

# --------------------------------------------------------------
# Constantes CCSDS (Space Packet Protocol – CCSDS 133.0-B-2)
# --------------------------------------------------------------

HEADER_SIZE   = 6    # Taille de l'en-tête primaire CCSDS en octets (3 × 16 bits)
CRC_SIZE      = 2    # Taille du CRC-16 en octets (CRC-HQX / CCITT)
MIN_PACKET    = HEADER_SIZE + 1 + CRC_SIZE  # Taille minimale d'un paquet valide

# Valeurs par défaut pour la construction de paquets
DEFAULT_VERSION     = 0     # Version CCSDS (3 bits)
DEFAULT_PACKET_TYPE = 0     # 0 = Télémétrie, 1 = Télécommande
DEFAULT_SEC_HDR     = 0     # Secondary Header Flag
DEFAULT_APID        = 0x64  # Application Process ID par défaut (100)
DEFAULT_SEQ_FLAGS   = 0b11  # 0b11 = paquet autonome (unsegmented)

# Champs de masquage CCSDS
APID_MASK      = 0x07FF
SEQ_COUNT_MASK = 0x3FFF
VERSION_MASK   = 0x07
TYPE_MASK      = 0x01
SEC_HDR_MASK   = 0x01
SEQ_FLAGS_MASK = 0x03

# --------------------------------------------------------------
# Paramètres de sécurité – Défense 2 (HMAC-SHA256)
# --------------------------------------------------------------

# Clé HMAC par défaut (32 octets).
# ⚠️  En production : charger depuis une variable d'environnement
#     ou un fichier de secrets, JAMAIS en dur dans le code.
DEFAULT_HMAC_KEY: bytes = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6' \
                           b'\xab\xf7\x15\x88\x09\xcf\x4f\x3c' \
                           b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6' \
                           b'\xab\xf7\x15\x88\x09\xcf\x4f\x3c'

HMAC_DIGEST_SIZE = 32  # SHA-256 → 32 octets

# --------------------------------------------------------------
# Types d'alertes IDS structurel
# --------------------------------------------------------------

ALERT_CRC_FAIL      = "CRC_FAIL"       # CRC invalide
ALERT_APID_SPOOF    = "APID_SPOOF"     # APID inattendu
ALERT_DUPLICATE_SEQ = "DUPLICATE_SEQ"  # Numéro de séquence dupliqué
ALERT_SEQ_GAP       = "SEQ_GAP"        # Saut dans la séquence
ALERT_SEQ_REORDER   = "SEQ_REORDER"    # Paquet hors-ordre

ALERT_HMAC_FAIL     = "HMAC_FAIL"      # Tag HMAC invalide (contenu altéré)
ALERT_HMAC_UNKNOWN  = "HMAC_UNKNOWN"   # Paquet sans tag connu (injection)
