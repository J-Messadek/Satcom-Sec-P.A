from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import erfc, log10, pi, sin, sqrt
from pathlib import Path
from random import Random
from statistics import fmean
from typing import Any

SUPPORTED_JAMMING_MODES = ("barrage", "pulse", "tone")
_MULTI_MODE_ALIASES = {"multi", "combined", "hybrid"}


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


def _normalize_modes(mode_value: Any, extra_modes: Any) -> tuple[str, tuple[str, ...]]:
    resolved: list[str] = []
    requested_multi = False

    def _consume(value: Any) -> None:
        nonlocal requested_multi
        if value is None:
            return

        if isinstance(value, str):
            candidates = [part.strip().lower() for part in value.replace("+", ",").split(",")]
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for item in value:
                _consume(item)
            return
        else:
            raise TypeError("Jamming modes must be provided as a string or a sequence of strings.")

        for candidate in candidates:
            if not candidate:
                continue
            if candidate in _MULTI_MODE_ALIASES:
                requested_multi = True
                continue
            if candidate not in SUPPORTED_JAMMING_MODES:
                expected = ", ".join(SUPPORTED_JAMMING_MODES)
                raise ValueError(
                    f"Unsupported jamming mode '{candidate}'. Expected one of: {expected}, multi."
                )
            if candidate not in resolved:
                resolved.append(candidate)

    _consume(mode_value)
    _consume(extra_modes)

    if not resolved:
        resolved = list(SUPPORTED_JAMMING_MODES if requested_multi else ("barrage",))

    if requested_multi or len(resolved) > 1:
        return "multi", tuple(resolved)
    return resolved[0], tuple(resolved)


@dataclass(slots=True)
class JammingConfig:
    enabled: bool = False
    default_snr_db: float = 15.0
    ber_threshold: float = 1e-5
    intensity: float = 0.0
    mode: str = "barrage"
    modes: tuple[str, ...] = ("barrage",)
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

        mode, modes = _normalize_modes(
            jamming_profile.get("mode", channel_simulation.get("jamming_mode", "barrage")),
            jamming_profile.get("modes", channel_simulation.get("jamming_modes")),
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
            modes=modes,
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
    active_modes: tuple[str, ...] = ()
    severity: str = "nominal"


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
        passive_noise_std = sqrt(base_noise_power)
        adaptive_intensity = self._adaptive_intensity()
        active_modes = self._active_modes()

        barrage_std = sqrt(max(signal_power * adaptive_intensity * 0.18, 0.0))
        burst_noise_std = sqrt(max(signal_power * adaptive_intensity * 0.75, 0.0))
        tone_amplitude = sqrt(max(2.0 * signal_power * adaptive_intensity * 0.16, 0.0))

        jammed_signal: list[float] = []
        noise_samples: list[float] = []
        burst_remaining = 0

        for index, sample in enumerate(samples):
            total_noise = self._random.gauss(0.0, passive_noise_std)

            if "barrage" in active_modes:
                total_noise += self._random.gauss(0.0, barrage_std)

            if "pulse" in active_modes:
                if burst_remaining <= 0 and self._random.random() < self.config.burst_probability:
                    burst_remaining = self.config.burst_length

                if burst_remaining > 0:
                    total_noise += self._random.gauss(0.0, burst_noise_std)
                    burst_remaining -= 1

            if "tone" in active_modes:
                total_noise += tone_amplitude * sin(2.0 * pi * self.config.tone_frequency_ratio * index)

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
        adaptive_intensity = self._adaptive_intensity()
        active_modes = self._active_modes()

        jammed = bytearray(original)
        flipped_bits = 0
        payload_length_bits = len(jammed) * 8
        burst_remaining = 0
        tone_period = max(int(round(1.0 / self.config.tone_frequency_ratio)), 2)

        for byte_index in range(len(jammed)):
            bit_index = byte_index * 8
            probabilities: list[float] = []

            if "barrage" in active_modes:
                probabilities.append(min(0.12, baseline_ber * (1.0 + adaptive_intensity * 1.4)))

            if "pulse" in active_modes:
                if burst_remaining <= 0 and self._random.random() < self.config.burst_probability:
                    burst_remaining = self.config.burst_length

                if burst_remaining > 0:
                    probabilities.append(min(0.18, baseline_ber * (2.2 + adaptive_intensity * 1.8)))
                    burst_remaining = max(burst_remaining - 8, 0)
                else:
                    probabilities.append(min(0.03, baseline_ber * 0.2))

            if "tone" in active_modes:
                in_tone_peak = (bit_index % tone_period) < max(tone_period // 4, 1)
                tone_factor = (1.6 + (0.8 * adaptive_intensity)) if in_tone_peak else 0.35
                probabilities.append(min(0.1, baseline_ber * tone_factor))

            bit_flip_probability = self._combine_probabilities(probabilities)
            if len(active_modes) > 1:
                bit_flip_probability = min(0.2, bit_flip_probability * (1.0 + 0.05 * (len(active_modes) - 1)))

            byte_flip_probability = 1.0 - ((1.0 - bit_flip_probability) ** 8)
            if self._random.random() >= byte_flip_probability:
                continue

            flip_count = self._estimate_flip_count(bit_flip_probability)
            mask = 0
            for bit_position in self._random.sample(range(8), k=flip_count):
                mask |= 1 << (7 - bit_position)

            jammed[byte_index] ^= mask
            flipped_bits += mask.bit_count()

        observed_ber = flipped_bits / payload_length_bits if payload_length_bits else 0.0
        return bytes(jammed), self._build_report(
            average_noise_power=effective_noise_power,
            effective_snr_db=effective_snr_db,
            estimated_ber=observed_ber,
            flipped_bits=flipped_bits,
            payload_length_bits=payload_length_bits,
        )

    def _active_modes(self) -> tuple[str, ...]:
        return self.config.modes or (self.config.mode,)

    def _adaptive_intensity(self) -> float:
        if self.config.intensity <= 0.0:
            return 0.0

        threshold_factor = 1.0
        if self.config.ber_threshold > 0.0:
            threshold_factor += _clamp((-log10(self.config.ber_threshold) - 3.0) * 0.08, 0.0, 0.4)

        snr_factor = 1.0 + _clamp((18.0 - self.config.default_snr_db) / 30.0, -0.15, 0.35)
        multi_factor = 1.0 + (0.12 * max(len(self._active_modes()) - 1, 0))
        return _clamp(self.config.intensity * threshold_factor * snr_factor * multi_factor, 0.0, 1.5)

    def _combine_probabilities(self, probabilities: Sequence[float]) -> float:
        if not probabilities:
            return 0.0

        survival_probability = 1.0
        for probability in probabilities:
            clamped = _clamp(probability, 0.0, 0.5)
            survival_probability *= 1.0 - clamped
        return 1.0 - survival_probability

    def _estimate_flip_count(self, bit_flip_probability: float) -> int:
        expected_flips = _clamp(8.0 * bit_flip_probability, 0.0, 8.0)
        flip_count = int(expected_flips)
        if self._random.random() < (expected_flips - flip_count):
            flip_count += 1
        return max(1, min(flip_count, 8))

    def _base_noise_power(self, signal_power: float) -> float:
        snr_linear = 10.0 ** (self.config.default_snr_db / 10.0)
        if snr_linear <= 0.0:
            return signal_power
        return signal_power / snr_linear

    def _payload_noise_power(self, signal_power: float, base_noise_power: float) -> float:
        adaptive_intensity = self._adaptive_intensity()
        active_modes = self._active_modes()
        jammer_power = 0.0

        if "barrage" in active_modes:
            jammer_power += signal_power * adaptive_intensity * 0.18
        if "pulse" in active_modes:
            jammer_power += signal_power * adaptive_intensity * max(self.config.burst_probability, 0.05) * 0.9
        if "tone" in active_modes:
            jammer_power += signal_power * adaptive_intensity * 0.12

        return base_noise_power + max(jammer_power, 0.0)

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
        severity = "high" if threshold_exceeded else "moderate" if estimated_ber > (self.config.ber_threshold * 0.5) else "nominal"
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
            active_modes=self._active_modes(),
            severity=severity,
        )


__all__ = ["JammingConfig", "JammingReport", "SatelliteJammer", "SUPPORTED_JAMMING_MODES"]