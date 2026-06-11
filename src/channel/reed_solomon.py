"""Code correcteur Reed-Solomon (FEC) contre le bruit du canal."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from reedsolo import RSCodec, ReedSolomonError

from .jamming import JammingReport


class ReedSolomonProtector:
    def __init__(self, ecc_symbols: int = 10):
        self.ecc_symbols = max(int(ecc_symbols), 2)
        self._codec = RSCodec(self.ecc_symbols)

    @property
    def correction_capacity(self) -> int:
        """Octets corrigeables par bloc (= ecc_symbols // 2)."""
        return self.ecc_symbols // 2

    def encode(self, data: bytes | bytearray) -> bytes:
        return bytes(self._codec.encode(bytes(data)))

    def decode(self, jammed_data: bytes | bytearray) -> tuple[bytes, bool]:
        """Corrige les erreurs si possible. Retourne (données, succès)."""
        try:
            return bytes(self._codec.decode(bytes(jammed_data))[0]), True
        except (ReedSolomonError, ValueError, TypeError):
            return bytes(jammed_data), False

    def simulate_protection(
        self,
        original_payload: bytes,
        jammer_func: Callable[[bytes], tuple[bytes, JammingReport | Any]],
    ) -> dict[str, Any]:
        """Flux complet encodage → brouillage → décodage, avec rapport détaillé."""
        encoded = self.encode(original_payload)
        jammed_output = jammer_func(encoded)
        if not isinstance(jammed_output, tuple) or len(jammed_output) != 2:
            raise TypeError("jammer_func must return (jammed_bytes, report)")

        jammed_data, report = jammed_output
        decoded, success = self.decode(jammed_data)
        residual = self._count_byte_errors(decoded, original_payload)
        recovered = success and decoded == original_payload

        return {
            "success": success,
            "original_len": len(original_payload),
            "total_sent_len": len(encoded),
            "ecc_symbols": self.ecc_symbols,
            "correction_capacity": self.correction_capacity,
            "redundancy_ratio": self.ecc_symbols / max(len(original_payload), 1),
            "errors_detected": report.flipped_bits if isinstance(report, JammingReport) else 0,
            "effective_ber": report.estimated_ber if isinstance(report, JammingReport) else 0.0,
            "jam_report": report,
            "recovered_data": decoded,
            "recovered_matches_original": recovered,
            "residual_byte_errors": residual,
            "status": "corrected" if recovered else "uncorrectable" if not success else "partially_recovered",
        }

    @staticmethod
    def _count_byte_errors(left: bytes, right: bytes) -> int:
        return sum(a != b for a, b in zip(left, right)) + abs(len(left) - len(right))
