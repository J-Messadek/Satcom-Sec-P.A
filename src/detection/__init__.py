# Detection package – Défense 2 (HMAC + IDS structurel)
from .anomaly_detector import (
    compute_hmac_tag,
    verify_hmac_tag,
    tag_stream,
    verify_stream,
    detect_structural_anomalies,
)
