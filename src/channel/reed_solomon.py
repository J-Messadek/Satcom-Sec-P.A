from __future__ import annotations
from reedsolo import RSCodec, ReedSolomonError
from .jamming import JammingReport


class ReedSolomonProtector:
    def __init__(self, ecc_symbols: int = 10):
        """
        :param ecc_symbols: Nombre de symboles de correction (ECC).
                            Capacité de correction = ecc_symbols // 2.
        """
        self.ecc_symbols = ecc_symbols
        self._codec = RSCodec(ecc_symbols)

    def encode(self, data: bytes) -> bytes:
        """Ajoute les octets de parité Reed-Solomon aux données."""
        return bytes(self._codec.encode(data))

    def decode(self, jammed_data: bytes) -> tuple[bytes, bool]:
        """
        Tente de corriger les erreurs de brouillage.
        Retourne (données_corrigées, succès).
        """
        try:
            corrected = self._codec.decode(jammed_data)[0]
            return bytes(corrected), True
        except (ReedSolomonError, ValueError):
            return jammed_data, False

    def simulate_protection(self, original_payload: bytes, jammer_func) -> dict:
        """
        Simule le flux complet : Encodage -> Brouillage -> Décodage.
        """

        encoded_data = self.encode(original_payload)
        jammed_data, report = jammer_func(encoded_data)
        decoded_data, success = self.decode(jammed_data)

        return {
            "success": success,
            "original_len": len(original_payload),
            "total_sent_len": len(encoded_data),
            "errors_detected": report.flipped_bits,
            "effective_ber": report.estimated_ber,
            "recovered_data": decoded_data,
        }
