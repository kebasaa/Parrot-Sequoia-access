# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 kebasaa
"""Backend-independent data models.

The camera's exact HTTP/PTP payloads are parsed in the backends; these
dataclasses are what the rest of the library and users see. Fields that a
backend cannot provide are left as ``None``. Every model keeps the raw
payload in ``raw`` so nothing the camera reports is lost.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, FrozenSet, List, Optional


class CaptureMode(str, enum.Enum):
    SINGLE = "single"
    TIMELAPSE = "timelapse"
    GPS = "gps"


class Sensor(str, enum.Enum):
    GREEN = "green"
    RED = "red"
    REDEDGE = "rededge"
    NIR = "nir"
    RGB = "rgb"

    @property
    def is_multispectral(self) -> bool:
        return self is not Sensor.RGB


#: The four multispectral bands, in the order the camera reports them.
BANDS = (Sensor.GREEN, Sensor.RED, Sensor.REDEDGE, Sensor.NIR)
ALL_SENSORS: FrozenSet[Sensor] = frozenset(Sensor)

#: File name suffixes the Sequoia uses for each sensor (IMG_..._GRE.TIF etc.).
SENSOR_SUFFIX = {
    Sensor.GREEN: "GRE",
    Sensor.RED: "RED",
    Sensor.REDEDGE: "REG",
    Sensor.NIR: "NIR",
    Sensor.RGB: "RGB",
}


def parse_sensors(value) -> FrozenSet[Sensor]:
    """Accept sensors as enum members, names, or a comma separated string."""
    if value is None:
        return ALL_SENSORS
    if isinstance(value, str):
        value = [v for v in value.replace(" ", "").split(",") if v]
    out = set()
    for v in value:
        if isinstance(v, Sensor):
            out.add(v)
        else:
            key = str(v).lower().replace("_", "").replace("-", "")
            if key in ("all", "*"):
                return ALL_SENSORS
            aliases = {"re": "rededge", "reg": "rededge", "gre": "green", "ir": "nir"}
            out.add(Sensor(aliases.get(key, key)))
    return frozenset(out)


def sensor_from_filename(name: str) -> Optional[Sensor]:
    stem = name.rsplit(".", 1)[0].upper()
    for sensor, suffix in SENSOR_SUFFIX.items():
        if stem.endswith("_" + suffix):
            return sensor
    if name.upper().endswith((".JPG", ".JPEG")):
        return Sensor.RGB
    return None


@dataclass
class CaptureConfig:
    mode: Optional[CaptureMode] = None
    timelapse_interval_s: Optional[float] = None
    gps_distance_m: Optional[float] = None
    overlap_percent: Optional[float] = None
    sensors: Optional[FrozenSet[Sensor]] = None
    rgb_resolution_mp: Optional[int] = None  # 12 or 16
    multispectral_bit_depth: Optional[int] = None  # 8 or 10
    multispectral_resolution_mp: Optional[float] = None  # 0.3 or 1.2
    storage: Optional[str] = None  # "internal" | "sd" | "auto"
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class RemoteFile:
    """A file on the camera. ``ref`` is the backend specific handle/path."""

    storage: str
    folder: str
    name: str
    size: Optional[int] = None
    ref: Any = field(default=None, compare=False, hash=False)

    @property
    def path(self) -> str:
        return "/".join(p for p in (self.storage, self.folder, self.name) if p)

    @property
    def sensor(self) -> Optional[Sensor]:
        return sensor_from_filename(self.name)


@dataclass
class CaptureResult:
    files: List[RemoteFile]
    started_utc: datetime
    finished_utc: datetime
    capture_id: str = ""

    @property
    def folder(self) -> Optional[str]:
        return self.files[0].folder if self.files else None


@dataclass
class StorageInfo:
    name: str
    total_bytes: Optional[int] = None
    free_bytes: Optional[int] = None
    selected: Optional[bool] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class GpsFix:
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    satellites: Optional[int] = None
    speed: Optional[float] = None
    fix: Optional[bool] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class BandIrradiance:
    band: Sensor
    irradiance: Optional[float] = None
    exposure_time: Optional[float] = None
    gain: Optional[float] = None
    count: Optional[float] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Irradiance:
    """One sunshine sensor reading for all bands, in raw camera units."""

    timestamp_utc: datetime
    bands: List[BandIrradiance]
    sensor_temperature: Optional[float] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    def band(self, band: Sensor) -> Optional[BandIrradiance]:
        for b in self.bands:
            if b.band == band:
                return b
        return None


@dataclass
class Temperatures:
    values: Dict[str, float] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class DeviceInfo:
    serial: Optional[str] = None
    firmware: Optional[str] = None
    model: str = "Parrot Sequoia"
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class Status:
    gps: Optional[GpsFix] = None
    irradiance: Optional[Irradiance] = None
    temperatures: Optional[Temperatures] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)
