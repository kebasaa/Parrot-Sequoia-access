# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 kebasaa
"""Exception hierarchy for sequoia-ctl."""


class SequoiaError(Exception):
    """Base class for all sequoia-ctl errors."""


class SequoiaConnectionError(SequoiaError):
    """The camera could not be reached or stopped responding."""


class CaptureTimeout(SequoiaError):
    """A capture did not produce the expected files in time."""


class StorageFull(SequoiaError):
    """The selected camera storage has no space left."""


class BackendNotAvailable(SequoiaError):
    """A backend or external tool (ptpy, exiftool, adb, ...) is not installed."""


class PowerControlUnavailable(SequoiaError):
    """No switchable USB power hardware was detected or configured."""


class DownloadError(SequoiaError):
    """A file could not be downloaded or failed verification."""


class ShellError(SequoiaError):
    """A telnet shell command failed."""
