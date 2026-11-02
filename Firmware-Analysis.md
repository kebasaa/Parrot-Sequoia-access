# Parrot Sequoia firmware analysis

Analysis of `sequoia_update_171.plf` (firmware **1.7.1**). Goals this document
supports:

- improve access to the camera;
- modify the firmware (add tools, fix bugs);
- lift the timed-capture limit for long-running, fixed-interval photography;
- drive the camera from a computer with **Python**;
- investigate stability bugs (capture stopping) and the control **webserver**.

Everything below was obtained by statically parsing and extracting the `.plf`
file — nothing was run on a device. Each claim is marked as an **observation**
(read directly from the firmware) or an **inference**. Where a question can only
be answered with the device's own logs or a decompiler, that is stated plainly.

---

## 1. Summary

| Goal | Where it lives | Difficulty |
|------|----------------|------------|
| Shell / root | `adb` port 9050 as root, no password (already documented) | Easy |
| Add tools / fix bugs | Live rootfs edit (`adb` + remount rw), or repack `.plf` | Live: easy · Repack: hard |
| **Longer capture interval** | `capture_timelapse_period.max` in `/etc/libshsettings/sicilia.cfg` = **3,600,000 ms (1 h)** | Easy (text config) |
| **Run indefinitely** | No firmware inactivity timeout — only power/heat/storage limit it | Easy |
| **Python control** | HTTP API on :80, or PTP/IP on :15740 (`sequoia-ptpy`) | Easy–Medium |
| Webserver bugs | `civetweb` (:80) + `civetitf` bridge → `siciliad` | Needs decompiler |
| Capture-stops-crash | `siciliad`; diagnose from on-device crash logs | Needs device logs |
| Firmware downgrade | `plf_updater` gate (`update_check=up`, whitelist `1.5.9`) | Medium |

Highest-value facts: the **interval cap is a plain-text config bound** (§8), and
the camera exposes an **unauthenticated HTTP control API** that Python can drive
directly (§6–7).

---

## 2. Build identity (observation)

From `/etc/build.prop`:

```
ro.parrot.build.product      = sicilia       # "sicilia" = Sequoia platform codename
ro.parrot.build.version      = 1.7.1
ro.parrot.build.uid          = sicilia-sicilia-1.7.1
ro.parrot.build.original_uid = sicilia-sicilia-1.7.1-rc7
ro.build.date                = Wed Nov  7 16:09:54 UTC 2018
```

- Userland: **BusyBox v1.25.0** (2018-11-07).
- CPU: **ARM 32-bit hard-float** (`/lib/ld-linux-armhf.so.3`, ELF machine 0x28).
  Parrot P7 / "sicilia" board. Cross-compile added tools for `arm-linux-gnueabihf`.

---

## 3. PLF container format (observation)

`.plf` = Parrot Linux Firmware: a 56-byte header, then a flat list of 20-byte
section headers each followed by a payload. Reverse-engineered directly from the
bytes; reproducible.

### 3.1 Main header (56 bytes, little-endian)

| Off | Field | 1.7.1 value |
|----:|-------|-------------|
| 0x00 | magic `PLF!` | `50 4C 46 21` |
| 0x04 | header version | 13 |
| 0x08 | header size | 56 |
| 0x0C | section header size | 20 |
| 0x10 | file type | 2 (update bundle; nested volumes use 1) |
| 0x1C | target application | 0x70 |
| 0x24/28/2C | version major/minor/patch | 1 / 7 / 1 → **1.7.1** |
| 0x34 | file size | 36,988,792 |

### 3.2 Section header (20 bytes, repeated)

```
uint32 type
uint32 size          # payload length
uint32 crc           # Parrot-custom CRC over payload (NOT standard CRC-32 — see §13)
uint32 load_addr     # flash/load address (0 for rootfs entries)
uint32 uncompressed  # if >0, payload is one gzip stream of this length
```

Payloads padded to 4 bytes. File has **1608 sections**.

### 3.3 Section inventory (observation)

| Type | Count | Meaning |
|-----:|------:|---------|
| 0x0B | 1 | Partition table (plain text) |
| 0x0C | 1 | **Nested PLF** 7.1 MB — bootloader volume |
| 0x07 | 1 | ARM boot stub (39 KB) |
| 0x03 | 1 | **Nested PLF** 4.6 MB — kernel/system volume |
| 0x09 | 1604 | Root filesystem (1 entry each) |

Partition table: `bootloader  main_boot  alt_boot  misc_boot  system  factory  cache  data`.
**`alt_boot` is a second boot bank** — the recovery angle that bounds (but does
not remove) brick risk when flashing (inference; fallback behaviour unconfirmed).

### 3.4 Rootfs entry (type 0x09)

After gunzip (if `uncompressed>0`): `path\0` + `uint32 mode` + 2×`uint32`(0) + content.
Extraction → **1110 files, 149 dirs, 345 symlinks**: a complete embedded Linux rootfs.

---

## 4. Access surface (observation)

Services in `/etc/boxinit.d/*.rc` (Android-style `boxinit` init):

| Service | State | Notes |
|---------|-------|-------|
| **adbd** (9050) | enabled, root | Primary access; root shell, no password |
| **dropbear SSH** (22) | enabled | `dropbear -F -B -a`; **`-B` = blank-password logins allowed** |
| **telnetd** (23) | disabled | Enabled only when `rw.debuggable=1` |
| **inetd FTP** (21/61) | release profile | Runs **as root** (see below) |
| **civetweb HTTP** (80) | app-started | Camera control UI + API, **no auth** (§5) |
| **siciliad** | app-started | Main camera daemon (§5) |
| **ptpip_server** (15740) | **disabled** | PTP/IP control (§7) |
| **mtp_server** | disabled | MTP file access |
| **plf_updater** | oneshot | Firmware updater (§12) |

FTP release profile (`/etc/inetd.conf.rel`), as **root**:
`port 21 → /data/medias/DCIM` (photos), `port 61 → /tmp/mounts/usb/`.
The **dev** profile (`rw.debuggable=1`) additionally exposes `port 666 → /` (whole
filesystem over FTP as root).

Credentials: `root:x:0:0:...` with an **empty `/etc/shadow`** → no root password;
that is why `adb shell` is root directly. Setting a password enables normal SSH
but (per README) breaks some services.

---

## 5. Camera control architecture (observation)

```
  Python / browser
        │  HTTP :80                         PTP/IP :15740
        ▼                                        │
   civetweb  ──►  civetitf  ──RPC──►  siciliad ◄─┘
  (web server)   (HTTP↔RPC     (libSiciliaCommand,   (ptpip_server)
                  bridge)       inet:127.0.0.1:1111)
```

- **`siciliad`** (`/usr/bin/siciliad`) — the camera daemon. Listens on
  `inet:127.0.0.1:1111` (`main_cmd_addr` in `sicilia.cfg`) using the
  `libSiciliaCommand` RPC protocol. Owns capture, sensors, GPS, storage, LEDs.
- **`civetitf`** (`/usr/bin/civetitf`) — bridges HTTP requests to `siciliad` RPC
  calls (`client_send_request_sicilia_ctrl_*`). This is where HTTP routes are
  defined (anchored regex, e.g. `/capture/start$`).
- **`civetweb`** (`/bin/civetweb`) — the HTTP server (port 80), serves the web UI
  from `/usr/share/www` (Bootstrap-based: `index.html`, `js/`, `css/`).
- **`ptpip_server`** (`/usr/bin/ptpip_server`) — standalone PTP/IP responder on
  `0.0.0.0:15740`, **disabled by default**.

RPC verbs exposed (from `civetitf`): `capture_start`, `capture_stop`,
`capture_set_mode`/`get_mode`, `timelapse_set_param`/`get_param`,
`auto_mode_set_param`/`get_param`, `gps_mode_set_param`/`get_param`,
`sensors_set_exposure_mode`/`get_*`, `get_sensors_values`, `storage_get_info`/
`get_path`/`get_autoselect`, `get_angles`, `get_xmp_tag`,
`magneto_calibration_start`/`stop`/`status`, **`poweroff`**, `status`.

---

## 6. HTTP API reference (observation)

Port **80**, **unauthenticated** (see §9). Routes confirmed from the web-UI JS
(`/usr/share/www/js`) and from `civetitf`'s handler table:

| Route | Purpose |
|-------|---------|
| `GET /status` | Full camera status (JSON) |
| `GET /config`, `/settings` | Read/update settings (incl. capture mode / timelapse period) |
| `POST /capture/start`, `POST /capture/stop`, `/capture` | Start/stop capture |
| `GET /storage`, `/sd`, `POST /eject` | Storage info / card management |
| `/download`, `/file`, `/delete`, `/gallery/` | File access on `/data/medias/DCIM` |
| `/calibration/{body,radiometric,sunshine}/{start,stop}` | Calibration routines |
| `/gpsfix`, `/carrier`, `/connection`, `/checkChange` | GPS / link status |
| `/plf` | Firmware upload (ties to `plf_updater` remote mode, §12) |

Exact JSON shapes are built by `civetitf` + the UI JS; capture the real traffic
with the browser dev-tools or `tcpdump` on the device to lock down field names.

---

## 7. Driving the camera from Python

Two practical paths; both work over USB (`10.1.1.2`) or Wi-Fi (`192.168.47.1`).

### 7.1 HTTP API (simplest)

No extra software on the camera — the HTTP API is already there and open.

```python
import requests
BASE = "http://192.168.47.1"          # or http://10.1.1.2 over USB
print(requests.get(f"{BASE}/status", timeout=5).json())
requests.post(f"{BASE}/capture/start", timeout=5)
# ... wait / run your experiment ...
requests.post(f"{BASE}/capture/stop", timeout=5)
```

Set the timelapse mode/period through `/config` (or `/settings`) — confirm the
exact JSON by watching the web UI's requests once. Values are still clamped to
the `sicilia.cfg` bounds (§8), so raise the `max` there first for long intervals.

### 7.2 PTP/IP with `sequoia-ptpy` (official library)

Parrot ships a Python PTP library: <https://github.com/Parrot-Developers/sequoia-ptpy>.
It speaks PTP/IP to `ptpip_server` on **port 15740**. That service is **disabled
by default**, so enable it first:

```bash
adb connect 10.1.1.2:9050
adb shell mount -o remount,rw /
# enable ptpip_server (edit its .rc to 'enabled', or start it directly):
adb shell /usr/bin/ptpip_server &
```

Then from the computer, use `sequoia-ptpy` to open a session, read/set camera
properties (the PTP property map is in `/etc/mtp-server.xml` — `ImageSize`,
`FNumber`, `CompressionSetting`, …) and trigger capture. PTP binds `0.0.0.0`, so
it is reachable over both Wi-Fi and USB once running.

> Recommendation for the research rig: **HTTP API for control logic** (start/stop,
> status polling, interval) because it needs nothing enabled on the camera, and
> **FTP (port 21) or MTP to pull images** from `/data/medias/DCIM`.

---

## 8. Timed capture: the interval limit (observation)

Capture parameters and their enforced ranges live in
`/etc/libshsettings/sicilia.cfg` (read by `siciliad` via `libshsettings`):

```
capture_mode = "single";
capture_timelapse_period = {     # milliseconds
    default = 1000;              # 1 s
    min     = 500;               # 0.5 s
    max     = 3600000;           # 3,600,000 ms = 1 hour  ← current ceiling
};
capture_gps_radius = { default = 25.; min = 5.0; max = 1000.0; };   # metres (distance trigger)
capture_overlap    = { default = 0.80; min = 0.0; max = 0.99; };
```

The `min`/`max` are the **enforced clamp bounds**, not compiled into `siciliad`.
To allow intervals longer than one hour, raise `capture_timelapse_period.max`
(value in **ms**; e.g. `86400000` = 24 h) and reboot:

```bash
adb connect 10.1.1.2:9050
adb shell mount -o remount,rw /
adb shell vi /etc/libshsettings/sicilia.cfg   # raise capture_timelapse_period.max
adb shell sync && adb reboot
```

Confirm on-device that the control app/HTTP API doesn't impose its own narrower
cap, and that `siciliad` re-reads the file at start-up (expected).

---

## 9. Webserver: security & bug surface

- **No authentication.** `/etc/civetweb.conf` sets `listening_ports 80` and leaves
  `authentication_domain`, `global_auth_file` and CGI **commented out**. So the
  full control API (§6), including `/capture/*`, `/delete` and `/poweroff` via the
  bridge, is open to **anyone on the Wi-Fi/USB network** (observation). Convenient
  for scripting; a real exposure if the camera's Wi-Fi is reachable by others.
- **Config vs. actual doc root.** `civetweb.conf` says `document_root /data/www`,
  but the UI ships in `/usr/share/www`; the app sets the effective root at launch
  (both `var/www` and `usr/share/www` exist). Worth confirming which is served.
- **Version / CVEs: unresolved.** The `civetweb` binary (76 KB, stripped) stores
  only the format string `"CivetWeb v%s, built on %s"` — the version is a
  compile-time macro, not a static literal, so the exact CivetWeb version (and its
  known CVEs) **cannot be determined from strings alone**. Needs the running
  `Server:` banner (`curl -I http://10.1.1.2/`) or a decompiler.
- **Bug surface is in `civetitf`** (149 KB), which parses HTTP requests and
  forwards to RPC (error paths seen: `"Cannot create new request handler struct,
  OOM"`, `"Client did not send a request"`). Finding actual input-validation bugs
  there requires decompilation (Ghidra/IDA) — not available in this environment.

---

## 10. Crash & stability ("capture stops") (observation + guidance)

The firmware cannot be shown to have a specific capture-stopping bug from static
data alone — that needs the **device's own crash logs**. What the image tells us:

- A crash handler is preloaded everywhere: `/etc/ld.so.preload` →
  `/usr/lib/libcrashdump.so`; `crashdumpd` runs as user `system` and writes to
  `/var/lib/crashdump`. Note the `.rc` comment:
  `ptrace(PTRACE_ATTACH,) error: Operation not permitted` — crashdump may fail to
  attach to root-owned processes, so some crashes won't produce a usable dump
  (inference).
- `siciliad` has fragile points visible in strings: timelapse uses `timerfd`
  (`"Failed to create a timer"`), there are per-subsystem **watchdogs**
  (`"Set %s watchdog to ..."`), and hard `abort` paths; GPIO button monitor, LED
  manager and IIO/telemetry registration can each fail at startup.
- **Most likely field cause of "stops taking pictures"** (inference, to verify):
  storage filling up in `/data/medias/DCIM`, a `siciliad` watchdog/abort, or
  thermal — the board runs sensor/IMU heaters and gets hot on long runs. None of
  these is a hard firmware gate.

### How to capture the real cause on your device

```bash
adb connect 10.1.1.2:9050
adb shell ls -la /var/lib/crashdump        # crash dumps, if any
adb shell ulogcat -C | tee sequoia-log.txt # live kernel+ulog (README)
# persistent log, if enabled: a partition dir 'ulogcatd/log' (see /etc/ulogcatd.conf)
adb shell df -h /data                      # is storage full?
adb shell cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null  # temperatures
```

Pull `/var/lib/crashdump/*` and `sequoia-log.txt` after a failure and the crash
signature (faulting process + backtrace) will point at the exact bug.

---

## 11. Modifying the firmware — two paths

### Path A — Live edit (recommended, low risk)

The rootfs is writable; `mount -o remount,rw /` sticks. No repack, no version
games:

```bash
adb connect 10.1.1.2:9050
adb shell mount -o remount,rw /
# edit configs, drop in ARM binaries, patch init scripts, then reboot
```

Edits under `/etc` survive reboot but are overwritten by a future firmware
update; edits/tools under `/data` are the most durable. Good for the interval
change (§8), enabling PTP (§7.2), adding tools, and workarounds for bugs.

### Path B — Repack the `.plf` (higher risk)

Needed only to ship a modified image or change kernel/bootloader. The container
round-trips with the parser here, **but** the per-section CRC is a Parrot-custom
algorithm not yet reproduced (§13), so a repacked image may be rejected, and a
bad `main_boot` flash risks bricking (mitigated, not removed, by `alt_boot`).
**Do not flash a repacked image until the CRC and the updater's validation are
confirmed.**

---

## 12. Firmware update & downgrade gate (observation)

Updater `/usr/bin/plf_updater` (ARM ELF) + `libpuf` (`puf_check`,
`puf_get_version`, `puf_compare_version`):

1. Watches `/update` for `sequoia_update.plf`.
2. Checks PLF platform + application names match the device.
3. Reads candidate version from the PLF header; current from property
   `ro.parrot.build.version` (fed by `/etc/build.prop`).
4. Rejects with **`no need to update: current >= new`** otherwise `PROCESS UPDATE`.

`/etc/plf_updater.conf`:
```
update_plfname         = sequoia_update.plf
update_check           = up        # "up" = upgrades only → the downgrade block
update_check_whitelist = 1.5.9     # a PLF reporting 1.5.9 is accepted regardless of installed version
default_partition      = /update
```

Two bypass levers visible in the binary (`.update_check`, `update_check_whitelist`,
`"Whitelisted version"`): setting `update_check` to a non-`up` value skips the
version comparison; a PLF whose version matches the whitelist is always accepted.
Update is triggered with `/usr/bin/pinst_trigger` (`pinst_trigger 1; reboot`).
**Observed behaviour of the stock updater — not a tested exploit.** Whether the
updater/bootloader also enforces a signature is open (§13).

---

## 13. Open questions / next steps

1. **Section CRC algorithm** — not standard CRC-32 (tested ISO-HDLC, BZIP2,
   MPEG-2, POSIX, JAMCRC, CRC-32C/D, Adler). Parrot-custom inside `libpuf`.
   Needed for Path B. Requires decompiling `puf_check` or the OSS `plftool`.
2. **Signature check?** Does the updater/bootloader verify more than version+CRC?
3. **CivetWeb version + CVEs** — get from the live `Server:` banner or a decompiler.
4. **Actual `civetitf`/`siciliad` input-validation bugs** — need Ghidra/IDA.
5. **The capture-stop crash** — collect `/var/lib/crashdump` + `ulogcat` from the
   device (§10).
6. **Verify downgrade levers on hardware** — safest first test: flip `update_check`
   live and re-install the same 1.7.1.
7. **`alt_boot` recovery flow** — confirm fallback to bound brick risk.
8. Diff the 1.4.1 / 1.6.1 / 1.7.1 PLFs (all in the repo) to see what changed.

> Tooling note: the REA reverse-engineering MCP server and a native decompiler
> (Ghidra/IDA) were **not available** in this environment (`npx` missing), so
> binary-level vulnerability analysis (items 1, 3, 4) could not be done here.
> Those are good candidates for a dedicated session with a decompiler attached.

---

## 14. Reproducibility

Two dependency-free Python scripts parse and extract the container: a
header/section walker and an extractor that rebuilds the rootfs and dumps the
nested binary volumes. The PLF layout in §3 is enough to re-implement both. No
`binwalk`/`plftool` needed. (Scripts live in the analysis scratchpad; they can be
committed to the repo on request.)
