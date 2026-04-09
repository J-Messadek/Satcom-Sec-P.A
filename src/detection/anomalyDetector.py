# =============================================================
# anomalyDetector.py – Facade de compatibilité (DEPRECATED)
#
# Ce fichier est conservé temporairement pour la rétrocompatibilité.
# Il réexporte toutes les fonctions depuis leurs modules dédiés.
#
# ⚠️  Préférer les imports directs :
#     from src.detection.hmac_auth       import computeHmacTag, verifyHmacTag
#     from src.detection.structural_ids  import detectStructuralAnomalies
#     from src.detection.stream_pipeline import tagStream, verifyStream
# =============================================================

from .hmac_auth       import computeHmacTag, verifyHmacTag           # noqa: F401
from .structural_ids  import detectStructuralAnomalies               # noqa: F401
from .stream_pipeline import tagStream, verifyStream                 # noqa: F401
