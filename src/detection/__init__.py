# =============================================================
# src/detection/__init__.py
# Package de détection – Défense 2 (HMAC + IDS structurel) – Étudiant B
#
# Structure modulaire :
#   hmac_auth.py       – Primitives HMAC-SHA256 (compute / verify)
#   structural_ids.py  – IDS structurel CCSDS (CRC, APID, séquence)
#   stream_pipeline.py – Pipeline Tx/Rx complet (tagStream / verifyStream)
# =============================================================

from .hmac_auth import (
    computeHmacTag,
    verifyHmacTag,
)

from .structural_ids import (
    detectStructuralAnomalies,
)

from .stream_pipeline import (
    tagStream,
    verifyStream,
)

__all__ = [
    "computeHmacTag", "verifyHmacTag",
    "detectStructuralAnomalies",
    "tagStream", "verifyStream",
]
