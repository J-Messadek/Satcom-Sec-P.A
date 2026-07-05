# =====================================================================
# src/attacks/__init__.py
# Package des attaques – Étudiant B (A1/A2) + Étudiant A (A1) + Étudiant C (A3)
#
# Structure modulaire :
#   mitm.py            – Attaque 1 : interception MITM + AES-CTR (Étudiant B)
#   alter_apid.py      – Attaque 2 / Vecteur 1 : usurpation d'APID
#   alter_seq_count.py – Attaque 2 / Vecteur 2 : manipulation du seqCount
#   fuzz_payload.py    – Attaque 2 / Vecteur 3 : fuzzing du payload
#   fuzz_header.py     – Attaque 2 / Vecteur 4 : fuzzing de l'en-tête
#   inject_packet.py   – Attaque 2 / Vecteur 5 : injection de paquet
#   _utils.py          – Helpers internes partagés (rebuildPacket, offsetInStream)
# =====================================================================

# Attaque 1 (mitm.py) – module d'Étudiant A, disponible après merge
try:
    from .mitm import intercept, tamper, replay
except ImportError:
    pass  # A1 sera disponible après fusion de la branche Étudiant A sur dev

# Attaque 2 – modules Étudiant B
from .alter_apid       import alterApid
from .alter_seq_count  import alterSeqCount
from .fuzz_payload     import fuzzPayload
from .fuzz_header      import fuzzHeader
from .inject_packet    import injectPacket

__all__ = [
    # Attaque 1 (optionnel avant merge)
    "intercept", "tamper", "replay",
    # Attaque 2
    "alterApid", "alterSeqCount",
    "fuzzPayload", "fuzzHeader", "injectPacket",
]
