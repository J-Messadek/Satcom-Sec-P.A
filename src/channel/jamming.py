from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import erfc, log10, pi, sin, sqrt
from pathlib import Path
from random import Random
from statistics import fmean
from typing import Any


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(value, maximum))


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _safe_mean_power(samples: Sequence[float]) -> float:
    if not samples:
        return 0.0
    power = fmean(sample * sample for sample in samples)
    return max(power, 1e-12)


@dataclass(slots=True)
class JammingConfig:
    enabled: bool = False
    default_snr_db: float = 15.0
    ber_threshold: float = 1e-5
    intensity: float = 0.0
    mode: str = "barrage"
    seed: int | None = None
    burst_probability: float = 0.08
    burst_length: int = 64
    tone_frequency_ratio: float = 0.12

    @classmethod
    def from_mapping(cls, config: Mapping[str, Any]) -> "JammingConfig":
        channel_simulation = config.get("channel_simulation", config)
        if not isinstance(channel_simulation, Mapping):
            raise TypeError("channel_simulation must be a mapping")

        jamming_profile = channel_simulation.get("jamming", {})
        if not isinstance(jamming_profile, Mapping):
            raise TypeError("channel_simulation.jamming must be a mapping")

        mode = str(
            jamming_profile.get(
                "mode",
                channel_simulation.get("jamming_mode", "barrage"),
            )
        ).strip().lower()

        if mode not in {"barrage", "pulse", "tone"}:
            raise ValueError(
                "Unsupported jamming mode. Expected 'barrage', 'pulse' or 'tone'."
            )

        intensity = float(
            jamming_profile.get(
                "intensity",
                channel_simulation.get("jamming_intensity", 0.0),
            )
        )

        seed = jamming_profile.get("seed", channel_simulation.get("jamming_seed"))
        if seed is not None:
            seed = int(seed)

        return cls(
            enabled=_as_bool(channel_simulation.get("enable_jamming", False)),
            default_snr_db=float(channel_simulation.get("default_snr", 15.0)),
            ber_threshold=max(float(channel_simulation.get("ber_threshold", 1e-5)), 0.0),
            intensity=_clamp(intensity, 0.0, 1.0),
            mode=mode,
            seed=seed,
            burst_probability=_clamp(
                float(jamming_profile.get("burst_probability", 0.08)),
                0.0,
                1.0,
            ),
            burst_length=max(int(jamming_profile.get("burst_length", 64)), 1),
            tone_frequency_ratio=_clamp(
                float(jamming_profile.get("tone_frequency_ratio", 0.12)),
                1e-4,
                0.5,
            ),
        )


@dataclass(slots=True)
class JammingReport:
    enabled: bool
    mode: str
    configured_snr_db: float
    effective_snr_db: float
    estimated_ber: float
    ber_threshold: float
    threshold_exceeded: bool
    average_noise_power: float
    flipped_bits: int = 0
    payload_length_bits: int = 0


class SatelliteJammer:
    def __init__(self, config: JammingConfig):
        self.config = config
        self._random = Random(config.seed)

    @classmethod
    def from_mapping(cls, config: Mapping[str, Any]) -> "SatelliteJammer":
        return cls(JammingConfig.from_mapping(config))

    @classmethod
    def from_yaml(cls, config_path: str | Path) -> "SatelliteJammer":
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - defensive path
            raise RuntimeError(
                "PyYAML is required to load a YAML configuration file."
            ) from exc

        with Path(config_path).open("r", encoding="utf-8") as stream:
            loaded = yaml.safe_load(stream) or {}

        if not isinstance(loaded, Mapping):
            raise TypeError("The YAML configuration root must be a mapping")

        return cls.from_mapping(loaded)

    def jam_signal(self, signal: Sequence[float]) -> tuple[list[float], JammingReport]:
        samples = [float(sample) for sample in signal]
        if not samples:
            return [], self._build_report(
                average_noise_power=0.0,
                effective_snr_db=float("inf"),
                estimated_ber=0.0,
            )

        if not self.config.enabled or self.config.intensity == 0.0:
            return samples.copy(), self._build_report(
                average_noise_power=0.0,
                effective_snr_db=float("inf"),
                estimated_ber=0.0,
            )

        signal_power = _safe_mean_power(samples)
        base_noise_power = self._base_noise_power(signal_power)
        jammed_signal: list[float] = []
        noise_samples: list[float] = []

        if self.config.mode == "barrage":
            jammer_power = signal_power * self.config.intensity
            noise_std = sqrt(base_noise_power + jammer_power)
            for sample in samples:
                noise = self._random.gauss(0.0, noise_std)
                jammed_signal.append(sample + noise)
                noise_samples.append(noise)
        elif self.config.mode == "pulse":
            burst_remaining = 0
            passive_noise_std = sqrt(base_noise_power)
            burst_noise_std = sqrt(base_noise_power + (signal_power * self.config.intensity * 2.0))
            for sample in samples:
                if burst_remaining <= 0 and self._random.random() < self.config.burst_probability:
                    burst_remaining = self.config.burst_length

                if burst_remaining > 0:
                    noise = self._random.gauss(0.0, burst_noise_std)
                    burst_remaining -= 1
                else:
                    noise = self._random.gauss(0.0, passive_noise_std)

                jammed_signal.append(sample + noise)
                noise_samples.append(noise)
        else:
            gaussian_std = sqrt(base_noise_power)
            tone_amplitude = sqrt(max(2.0 * signal_power * self.config.intensity, 0.0))
            for index, sample in enumerate(samples):
                gaussian_noise = self._random.gauss(0.0, gaussian_std)
                tone_noise = tone_amplitude * sin(2.0 * pi * self.config.tone_frequency_ratio * index)
                total_noise = gaussian_noise + tone_noise
                jammed_signal.append(sample + total_noise)
                noise_samples.append(total_noise)

        average_noise_power = _safe_mean_power(noise_samples)
        effective_snr_db = self._effective_snr_db(signal_power, average_noise_power)
        estimated_ber = self._estimate_ber_from_snr_db(effective_snr_db)
        return jammed_signal, self._build_report(
            average_noise_power=average_noise_power,
            effective_snr_db=effective_snr_db,
            estimated_ber=estimated_ber,
        )

    def jam_bytes(self, payload: bytes | bytearray) -> tuple[bytes, JammingReport]:
        original = bytes(payload)
        if not original:
            return b"", self._build_report(
                average_noise_power=0.0,
                effective_snr_db=float("inf"),
                estimated_ber=0.0,
                flipped_bits=0,
                payload_length_bits=0,
            )

        if not self.config.enabled or self.config.intensity == 0.0:
            return original, self._build_report(
                average_noise_power=0.0,
                effective_snr_db=float("inf"),
                estimated_ber=0.0,
                flipped_bits=0,
                payload_length_bits=len(original) * 8,
            )

        signal_power = 1.0
        base_noise_power = self._base_noise_power(signal_power)
        effective_noise_power = self._payload_noise_power(signal_power, base_noise_power)
        effective_snr_db = self._effective_snr_db(signal_power, effective_noise_power)
        baseline_ber = self._estimate_ber_from_snr_db(effective_snr_db)

        jammed = bytearray(original)
        flipped_bits = 0
        payload_length_bits = len(jammed) * 8
        burst_remaining = 0
        tone_period = max(int(round(1.0 / self.config.tone_frequency_ratio)), 2)

        for bit_index in range(payload_length_bits):
            byte_index = bit_index // 8
            bit_offset = 7 - (bit_index % 8)
            flip_probability = baseline_ber

            if self.config.mode == "pulse":
                if burst_remaining <= 0 and self._random.random() < self.config.burst_probability:
                    burst_remaining = self.config.burst_length

                if burst_remaining > 0:
                    flip_probability = min(0.5, baseline_ber * 4.0)
                    burst_remaining -= 1
                else:
                    flip_probability = baseline_ber * 0.25
            elif self.config.mode == "tone":
                in_tone_peak = (bit_index % tone_period) < max(tone_period // 4, 1)
                flip_probability = min(0.5, baseline_ber * (3.0 if in_tone_peak else 0.35))

            if self._random.random() < flip_probability:
                jammed[byte_index] ^= 1 << bit_offset
                flipped_bits += 1

        observed_ber = flipped_bits / payload_length_bits if payload_length_bits else 0.0
        return bytes(jammed), self._build_report(
            average_noise_power=effective_noise_power,
            effective_snr_db=effective_snr_db,
            estimated_ber=observed_ber,
            flipped_bits=flipped_bits,
            payload_length_bits=payload_length_bits,
        )

    def _base_noise_power(self, signal_power: float) -> float:
        snr_linear = 10.0 ** (self.config.default_snr_db / 10.0)
        if snr_linear <= 0.0:
            return signal_power
        return signal_power / snr_linear

    def _payload_noise_power(self, signal_power: float, base_noise_power: float) -> float:
        if self.config.mode == "barrage":
            jammer_power = signal_power * self.config.intensity
        elif self.config.mode == "pulse":
            jammer_power = signal_power * self.config.intensity * max(self.config.burst_probability, 0.05) * 2.0
        else:
            jammer_power = signal_power * self.config.intensity * 0.75
        return base_noise_power + jammer_power

    def _effective_snr_db(self, signal_power: float, noise_power: float) -> float:
        if noise_power <= 0.0:
            return float("inf")
        return 10.0 * log10(signal_power / noise_power)

    def _estimate_ber_from_snr_db(self, snr_db: float) -> float:
        if snr_db == float("inf"):
            return 0.0
        snr_linear = 10.0 ** (snr_db / 10.0)
        return 0.5 * erfc(sqrt(max(snr_linear, 0.0)))

    def _build_report(
        self,
        *,
        average_noise_power: float,
        effective_snr_db: float,
        estimated_ber: float,
        flipped_bits: int = 0,
        payload_length_bits: int = 0,
    ) -> JammingReport:
        threshold_exceeded = estimated_ber > self.config.ber_threshold
        return JammingReport(
            enabled=self.config.enabled,
            mode=self.config.mode,
            configured_snr_db=self.config.default_snr_db,
            effective_snr_db=effective_snr_db,
            estimated_ber=estimated_ber,
            ber_threshold=self.config.ber_threshold,
            threshold_exceeded=threshold_exceeded,
            average_noise_power=average_noise_power,
            flipped_bits=flipped_bits,
            payload_length_bits=payload_length_bits,
        )


__all__ = ["JammingConfig", "JammingReport", "SatelliteJammer"]