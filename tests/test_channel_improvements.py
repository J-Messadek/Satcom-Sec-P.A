import unittest

from src.channel.jamming import SatelliteJammer
from src.channel.reed_solomon import ReedSolomonProtector


class TestChannelImprovements(unittest.TestCase):
    def test_multi_mode_jamming_accepts_multiple_profiles(self):
        jammer = SatelliteJammer.from_mapping(
            {
                "channel_simulation": {
                    "enable_jamming": True,
                    "default_snr": 8,
                    "jamming_intensity": 0.7,
                    "jamming": {
                        "mode": "multi",
                        "modes": ["barrage", "pulse", "tone"],
                        "seed": 2026,
                        "burst_probability": 0.2,
                        "burst_length": 12,
                        "tone_frequency_ratio": 0.18,
                    },
                }
            }
        )

        payload = b"SATCOM-LINK-PAYLOAD" * 8
        jammed, report = jammer.jam_bytes(payload)

        self.assertNotEqual(jammed, payload)
        self.assertEqual(report.mode, "multi")
        self.assertGreater(report.flipped_bits, 0)
        self.assertGreater(report.average_noise_power, 0.0)

    def test_reed_solomon_simulation_returns_diagnostics(self):
        protector = ReedSolomonProtector(ecc_symbols=32)
        jammer = SatelliteJammer.from_mapping(
            {
                "channel_simulation": {
                    "enable_jamming": True,
                    "default_snr": 18,
                    "jamming_intensity": 0.12,
                    "jamming": {"mode": "barrage", "seed": 42},
                }
            }
        )

        result = protector.simulate_protection(
            b"payload-de-test" * 10,
            jammer.jam_bytes,
        )

        self.assertIn("correction_capacity", result)
        self.assertIn("redundancy_ratio", result)
        self.assertIn("recovered_matches_original", result)
        self.assertIn("jam_report", result)
        self.assertIsInstance(result["recovered_matches_original"], bool)


if __name__ == "__main__":
    unittest.main()
