# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 kebasaa
"""Abstract backend contract shared by the HTTP and PTP backends."""

from __future__ import annotations

import abc
from typing import Iterator, List, Optional

from ..models import (
    CaptureConfig,
    DeviceInfo,
    GpsFix,
    Irradiance,
    RemoteFile,
    StorageInfo,
    Temperatures,
)


class Backend(abc.ABC):
    """A way of talking to the camera. Implementations must be thread-safe
    enough for one capture thread plus one background poller (the client
    serialises calls with a lock anyway)."""

    name = "base"

    @abc.abstractmethod
    def device_info(self) -> DeviceInfo: ...

    @abc.abstractmethod
    def get_config(self) -> CaptureConfig: ...

    @abc.abstractmethod
    def set_config(self, cfg: CaptureConfig) -> None:
        """Apply the non-``None`` fields of ``cfg``."""

    @abc.abstractmethod
    def start_capture(self) -> None: ...

    @abc.abstractmethod
    def stop_capture(self) -> None: ...

    @abc.abstractmethod
    def is_capturing(self) -> bool: ...

    @abc.abstractmethod
    def storage(self) -> List[StorageInfo]: ...

    @abc.abstractmethod
    def gps(self) -> GpsFix: ...

    @abc.abstractmethod
    def irradiance(self) -> Irradiance: ...

    @abc.abstractmethod
    def temperatures(self) -> Temperatures: ...

    @abc.abstractmethod
    def list_files(self, storage: Optional[str] = None, folder: Optional[str] = None) -> List[RemoteFile]:
        """List image files (not folders), recursively when ``folder`` is None."""

    @abc.abstractmethod
    def open_file(self, remote: RemoteFile, chunk_size: int = 1 << 20) -> Iterator[bytes]: ...

    @abc.abstractmethod
    def delete(self, remote: RemoteFile) -> None: ...

    def ping(self) -> bool:
        """Cheap liveness check, used by keep-alive and the watchdog."""
        try:
            self.is_capturing()
            return True
        except Exception:
            return False

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
