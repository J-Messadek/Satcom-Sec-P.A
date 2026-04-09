from __future__ import annotations

from collections.abc import Callable
from typing import Any

from reedsolo import RSCodec, ReedSolomonError

from .jamming import JammingReport


class ReedSolomonProtector:
    def __init__(self, ecc_symbols: int = 10):
        """
        :param ecc_symbols: Nombre de symboles de correction (ECC).
                            Capacité de correction = ecc_symbols // 2.
        """
        self.ecc_symbols = max(int(ecc_symbols), 2)
        self._codec = RSCodec(self.ecc_symbols)

    @property
    def correction_capacity(self) -> int:
        """Nombre maximum d'octets théoriquement corrigeables."""
        return self.ecc_symbols // 2

    def encode(self, data: bytes | bytearray) -> bytes:
        """Ajoute les octets de parité Reed-Solomon aux données."""
        return bytes(self._codec.encode(bytes(data)))

    def decode(self, jammed_data: bytes | bytearray) -> tuple[bytes, bool]:
        """
        Tente de corriger les erreurs de brouillage.
        Retourne (données_corrigées, succès).
        """
        try:
            corrected = self._codec.decode(bytes(jammed_data))[0]
            return bytes(corrected), True
        except (ReedSolomonError, ValueError, TypeError):
            return bytes(jammed_data), False

    def simulate_protection(
        self,
        original_payload: bytes,
        jammer_func: Callable[[bytes], tuple[bytes, JammingReport | Any]],
    ) -> dict[str, Any]:
        """
        Simule le flux complet : Encodage -> Brouillage -> Décodage.
        Retourne un rapport détaillé, utile pour comparer plusieurs profils de brouillage.
        """
        encoded_data = self.encode(original_payload)
        jammed_output = jammer_func(encoded_data)

        if not isinstance(jammed_output, tuple) or len(jammed_output) != 2:
            raise TypeError("jammer_func must return a tuple: (jammed_bytes, report)")

        jammed_data, report = jammed_output
        decoded_data, success = self.decode(jammed_data)
        recovered_matches_original = success and decoded_data == original_payload
        residual_byte_errors = self._count_byte_errors(decoded_data, original_payload)

        flipped_bits = report.flipped_bits if isinstance(report, JammingReport) else 0
        effective_ber = report.estimated_ber if isinstance(report, JammingReport) else 0.0

        return {
            "success": success,
            "original_len": len(original_payload),
            "total_sent_len": len(encoded_data),
            "ecc_symbols": self.ecc_symbols,
            "correction_capacity": self.correction_capacity,
            "redundancy_ratio": self.ecc_symbols / max(len(original_payload), 1),
            "errors_detected": flipped_bits,
            "effective_ber": effective_ber,
            "jam_report": report,
            "recovered_data": decoded_data,
            "recovered_matches_original": recovered_matches_original,
            "residual_byte_errors": residual_byte_errors,
            "status": "corrected" if recovered_matches_original else "uncorrectable" if not success else "partially_recovered",
        }

    def _count_byte_errors(self, left: bytes, right: bytes) -> int:
        paired_errors = sum(first != second for first, second in zip(left, right))
        return paired_errors + abs(len(left) - len(right))
