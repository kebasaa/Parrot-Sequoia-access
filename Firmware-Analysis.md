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
| Webserver bugs | `civetitf` (:80) — **no auth; `/delete` path traversal; unvalidated firmware upload** (§9) | Decompiled |
| Capture-stops-crash | **`palermo`** capture state machine stalls with no watchdog/respawn (§10) | Decompiled |
| Firmware downgrade | `plf_updater` gate (`update_check=up`, whitelist `1.5.9`) | Medium |
| Repack / reflash | Updater checks **header + per-section CRC** (POSIX `cksum`) but **no signature** (§12.3) — recompute CRCs and it is accepted | Medium |

Highest-value facts: the **interval cap is a plain-text config bound** (§8); the
camera exposes an **unauthenticated HTTP control API** that Python can drive
directly (§6–7); the updater verifies **header + per-section CRC** (POSIX `cksum`
CRC-32) but **no signature**, so a repacked PLF is accepted once its CRCs are
recomputed (§12.3), uploadable over the network (§9); and the "stops taking
pictures" symptom matches a **`palermo` capture-state stall that neither a
watchdog nor `boxinit` respawn recovers** (§10).

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
uint32 crc           # per-section checksum = POSIX cksum CRC-32; VALIDATED at install (§12.3)
uint32 load_addr     # flash/load address (0 for rootfs entries)
uint32 uncompressed  # if >0, payload is one gzip stream of this length
```

Payloads padded to 4 bytes. File has **1608 sections**. The `crc` field is the
**POSIX `cksum` CRC-32** (poly `0x04C11DB7`, MSB-first, message length appended,
final complement — *not* zlib/Ethernet CRC-32, which is why common-variant tests
failed). It **is** verified: `libplfng` recomputes and checks the header CRC and
every section's CRC when the PLF is opened for update/install, aborting on a
mismatch (§12.3). A repacked image therefore **must** carry correct CRCs — this
corrects the earlier §12.1 note.

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
| **civetweb HTTP** (80) | app-started | Camera control UI + API, **no auth** (§5, §9) |
| **palermo** (cmd :1111) | app-started | Capture engine + command server (§5, §10) |
| **siciliad** | app-started | LED/status client of `:1111` (§5) |
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
        │  HTTP :80                          PTP/IP :15740
        ▼                                         │
   civetweb ──► civetitf ──RPC──►  palermo  ◄──── ┘   (ptpip_server)
  (web server) (HTTP↔RPC    :1111  (capture engine +
                bridge)      ▲ ▲    libSiciliaCommand server)
                             │ └──────── siciliad (LED/status client)
                 :1010 ──────┘ └────── :1020
              sensors_main          sensors_ir
              (IMU/GPS)             (irradiance/IMU)
```

Corrected from the decompiler evidence (§12.2): the process that **binds the
command server** `main_cmd_addr = inet:127.0.0.1:1111` and implements the
`sicilia_ctrl_*` capture callbacks is **`palermo`**, not `siciliad`.

- **`palermo`** (`/usr/bin/palermo`) — the **camera/capture engine and command
  server**. Binds `:1111`, implements `register_server_sicilia_ctrl_capture_*`
  (confirmed: `setting_main_cmd_addr_cb`, 4× capture server callbacks, zero client
  calls). Drives the image sensors over V4L2, runs the capture workqueues and the
  timelapse timer, and is a **client** of `sensors_main` (`:1010`, IMU/GPS) and
  `sensors_ir` (`:1020`, irradiance). Started by `70-palermo.rc`.
- **`siciliad`** (`/usr/bin/siciliad`) — a **client** of `:1111` (`client_connect_to`,
  4× `client_send_request_*`, zero capture server callbacks) that runs the **LED
  server** (`led pomp_ctx_listen`). Its command-line is LED-centric
  (`--led-body-off`, `--led-irradiance-off`). It does **not** own capture.
- **`civetitf`** (`/usr/bin/civetitf`) — bridges HTTP requests to `:1111` RPC
  calls (`client_send_request_sicilia_ctrl_*`) through a **single shared pomp
  client** with a 2 s busy timeout (§9). Defines the HTTP routes (anchored regex,
  e.g. `/capture/start$`).
- **`civetweb`** (`/bin/civetweb`) — the HTTP server (port 80, `/etc/civetweb.conf`),
  serves the web UI from `document_root /data/www` (and image tree `/var/www/img`).
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
| `/download`, `/file`, `/gallery/` | File access under the image tree `/var/www/img/{internal,sd}` |
| `/delete` | Delete a gallery folder — **path-traversal bug, §9** |
| `/calibration/{body,radiometric,sunshine}/{start,stop}` | Calibration routines |
| `/gpsfix`, `/carrier`, `/connection`, `/checkchange` | GPS / link status |
| `PUT /plf`, `/update/sequoia_update.plf` | Firmware upload — **stages the blob unvalidated, §9**; ties to `plf_updater`, §12 |

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

Confirm on-device that `palermo` re-reads the file at start-up (expected).

**Decompiler note (civetitf `set_config`, `FUN_0x19a08`).** The HTTP bridge does
**not** clamp the period itself: it reads `timelapse_param` as a double (seconds),
multiplies by `1000.0`, and forwards the result to
`sicilia_ctrl_timelapse_set_param` as a **32-bit int** of milliseconds
(`(uint)(0.0 < ms) * (int)(longlong)ms` — any value ≤ 0 becomes 0). So:

- The `[500 … 3600000]` ms clamp is enforced **server-side** (by `palermo`/the
  `sicilia.cfg` bounds), not in the web layer — raising `max` in `sicilia.cfg` is
  the one lever that actually lifts the ceiling.
- Because the field is a signed 32-bit millisecond count, the **hard upper bound
  after you lift the clamp is 2³¹−1 ms ≈ 24.8 days**; a larger interval overflows
  the int. For multi-week intervals, drive the timing from the computer instead
  (single-shot `/capture/start` on your own schedule, §7.1).

---

## 9. Webserver: security & bug surface

`civetitf` (149 KB) and the `civetweb.conf` config were decompiled/read with REA +
Ghidra 12.1.4 (§12.2). Findings below are concrete, not speculative. Severity is
amplified by the fact that **every custom handler runs as root** (civetweb has no
`run_as_user` set) and the server has **no authentication** at all.

**1. No authentication (confirmed).** `/etc/civetweb.conf` sets only
`document_root /data/www` and `listening_ports 80` (plain HTTP, no SSL); every
auth option (`authentication_domain`, `global_auth_file`, `protect_uri`,
`put_delete_auth_file`, `access_control_list`) is **commented out**. The full
control API (§6) — `/capture/*`, `/settings`, `/delete`, the firmware upload, and
`poweroff` via the bridge — is open to **anyone who can reach the camera's
Wi-Fi/USB network**. Convenient for your own scripting; a real exposure otherwise.

**2. `/delete` path traversal → arbitrary deletion as root (`FUN_0x1d6b0`).**
The delete handler splits the request path at the first `/` into a *source*
(`/internal` or `/sd`) and a *subpath*, then **validates only the source**
(`strcmp` against `"/internal"`/`"/sd"`). It builds
`/var/www/img<source>/<subpath>`, `rename()`s it to a sibling dot-folder, and
recursively deletes it (`FUN_0x1d024`). The **subpath is never checked for `..`**
and `realpath()` is never called anywhere in `civetitf`, so a request such as
`/internal/../../../../data/<anything>` resolves the *rename source* outside the
gallery and deletes it. Running as root, this is unauthenticated arbitrary
file/dir deletion. (The buffers use `__snprintf_chk` with 100-byte bounds, so it
is a logic/traversal bug, not a buffer overflow.)

**3. Firmware upload stages any blob, unvalidated (`FUN_0x1f350`).** The `/plf`
upload handler writes the raw request body to `/update/plf_temp.sequoia`,
`fsync`s, and `rename()`s it to `/update/sequoia_update.plf` — the exact path
`plf_updater` watches (§12). It **logs the first 4 bytes but checks nothing**: no
`PLF!` magic test, no size limit, no CRC, no signature, no version check. All
acceptance is deferred to `plf_updater`/`libpuf`, which (§12.1) checks only
magic + platform/app id + version policy. So an attacker on the network can stage
a firmware image unauthenticated — and, usefully for your own work, this is the
**over-the-air deploy path for a repacked PLF** (upload, then trigger as in §12).

**4. Single shared RPC client with a 2 s busy timeout (`FUN_0x19a08`, `FUN_0x179d8`).**
Every HTTP request that needs the camera goes through one process-wide pomp client
guarded by a `pompClientAvailable` flag and a 2000 ms wait
(`"Pomp Client Busy, Timeout Reached"`). If `palermo` is slow or stalled (§10), or
two control requests overlap, commands are **silently dropped** and the HTTP
caller gets a stale/empty result. For a Python control loop: serialize requests
and treat a non-answer as "retry", don't assume success.

**5. CGI/SSI compiled in but inert by config (good).** The civetweb build
includes CGI (`**.cgi$|**.pl$|**.php$`, spawned via `popen`) and SSI
(`#exec`/`#include`). Both `cgi_pattern` and `ssi_pattern` are **commented out** in
`civetweb.conf`, so those `popen`/exec paths are **not reachable by default** — do
not re-enable them on a networked camera.

**6. Version / CVEs: still open.** The `civetweb` version is a compile-time macro
(`"CivetWeb v%s, built on %s"`), not a static string, so the exact upstream version
(and its CVEs) must come from the live `Server:` banner (`curl -I http://10.1.1.2/`).

---

## 10. Crash & stability ("capture stops") (observation + guidance)

Decompiling `palermo` (the capture engine, §12.2) plus the `boxinit` service
policy gives a concrete mechanism for "the camera stops taking pictures and
doesn't come back", without needing the device's crash logs first.

**The capture path has no self-recovery, and a stall does not crash the process
— so nothing restarts it.**

- **`palermo` is a capture state machine (`FUN_0x460b0`).** It accepts a new
  capture only when its state field is in the "ready" set; otherwise it logs
  `"MultiCapture is busy ! (current state = %d)"` and drops the request. A
  sequence that never completes leaves the state stuck, and then **every**
  subsequent timelapse tick is rejected as busy — the camera goes quiet while the
  process keeps running.
- **Sequences are dropped on frame problems (`FUN_0x443fc`).** Incomplete or
  out-of-sync multi-sensor sequences are discarded
  (`"Captured sequence %d is not complete, drop it!"`,
  `"...frames are not synchronized, drop it! (max diff = %lldus)"`). Frame
  delivery itself rides on a V4L2 `select()` with a timeout
  (`"[HAL_v4l2_utils] V4L select timeout"`): if a sensor hangs (I²C glitch,
  thermal, cable), frames stop arriving and the in-flight sequence can never
  finish.
- **No capture watchdog.** `palermo`'s strings contain no watchdog/reset/recover
  for the capture state machine — nothing inside the process detects "stuck" and
  re-arms it (inference from absence; confirm on device).
- **`boxinit` won't rescue a stall.** `boxinit` (Android-init style) respawns a
  non-`oneshot` service when it **exits**, and only a service marked `critical`
  triggers a recovery reboot after repeated crashes
  (`"critical process '%s' exited %d times in %d minutes; rebooting into recovery
  mode"`). In this firmware **no service is marked `critical`**, and the capture
  chain (`palermo`, `sensors_main`, `sensors_ir`, `siciliad`) is started once via
  property triggers (e.g. `70-palermo.rc`'s comment *"palermo will auto restart if
  it crashes"* relies on the default exit-respawn). A **hang** is not an exit, so
  respawn never fires — matching the "stops and stays stopped" symptom.
- **Other plausible contributors** (inference, to verify): storage filling up in
  the image tree, a crashed `sensors_main`/`sensors_ir` leaving `palermo` without
  IMU/irradiance data, or thermal throttling on long runs (the board runs IMU
  heaters). A crash handler is preloaded (`/etc/ld.so.preload` →
  `libcrashdump.so`, `crashdumpd` → `/var/lib/crashdump`), but its `.rc` notes
  `ptrace(PTRACE_ATTACH) error: Operation not permitted`, so a root process crash
  may not leave a usable dump.

**Workarounds for the research rig** (until the exact trigger is confirmed):
drive capture from the computer (single-shot `/capture/start` per §7.1) rather
than relying on on-camera timelapse, poll `/status` and power-cycle/restart
`palermo` on a stall, and keep storage well below full. Restarting just the
daemon: `adb shell stop palermo && adb shell start palermo` (via `boxinit`).

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

Needed only to ship a modified image or change kernel/bootloader. The userspace
update/install path is now fully understood (§12.1–§12.3):

- **Version gate:** `plf_updater`/`libpuf` enforce magic + platform/app id +
  "upgrade only" version policy (bypassable via `update_check` / the `1.5.9`
  whitelist, §12).
- **Integrity gate:** `libplfng` (called by `libpuf`) verifies the **header CRC
  and every section's POSIX `cksum` CRC-32**, aborting on mismatch (§12.3). So a
  repacked PLF **must** carry correct CRCs — but the algorithm is now known and
  reproducible, so a repack tool just recomputes them.
- **No signature:** there is **no cryptographic authenticity check** in
  `libpuf`/`libplfng`/`libpinst`. A correctly-CRC'd image is accepted and can be
  delivered over the network (unauthenticated upload, §9 item 3) or dropped into
  `/update/sequoia_update.plf`.

So Path B is viable: repack, **recompute the POSIX `cksum` CRC-32 for the header
and each changed section** (a parser/packer following §3 plus `cksum` is enough —
no Parrot tooling needed), then install. The one residual risk is **boot-time
secure boot** (SoC OTP/eFuse state, §12.3), not flash-time validation: a modified
`main_boot` will flash cleanly but could still be rejected by the boot ROM if
secure boot is fused on. **Flash a modified `main_boot` to `alt_boot` and test the
recovery bank first; keep `main_boot` known-good until the board's OTP state is
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
**Observed behaviour of the stock updater — not a tested exploit.**

### 12.1 Decompiler evidence (REA + Ghidra 12.1.4, `libpuf.so`)

Decompiled from `/usr/lib/libpuf.so` (ARM, sha256 `e20206a6…22d93b`); pseudocode
is Ghidra output, not original source.

**Version gate — `puf_compare_version`** (confirms §12 step 4). The version is a
**5-field struct** `{major, minor, patch, field3, field4}` compared numerically,
field by field:

```c
int puf_compare_version(uint *cur, uint *cand) {
  // returns 0 if all 5 fields equal; -1 if cur < cand; 1 if cur > cand
  if (*cand <= *cur && *cur==*cand && cand[1]<=cur[1] && cur[1]==cand[1]
      && ... through field[4] ...) return 0;   // equal
  if (!(cur < cand)) return -1; else return 1;
}
```

So "upgrade only" rejects any candidate that is not strictly greater across that
ordered 5-tuple — matching the `no need to update: current >= new` string.

**Header read — `puf_get_version`**: validates the `PLF!` magic (`0x21464C50`)
and copies the version fields straight out of the 56-byte header. The handle
loader (`plfng_new_from_file` → helper) just `calloc`s a 0x40 handle and reads
the 56-byte header; **no integrity check on load.**

**No CRC code *inside `libpuf` itself*.** `decompile-all` over `libpuf` produced
**113 functions**; **none** contains a CRC polynomial or byte loop, and
`puf_check` / `puf_get_version` only read header fields and the version struct.

> **Correction (resolved in §12.3).** The original conclusion here — *"the
> updater does not verify the section CRC, so a repacked PLF needs no correct
> CRCs"* — was **wrong**, because it was scoped to `libpuf.so` alone. `libpuf`
> does not contain CRC code because it **delegates PLF reading to `libplfng.so`**
> (it imports `plfng_new_from_file`, `plfng_check`, `plfng_get_section_count`,
> …). `libplfng` **does** verify the header CRC and every section's CRC, and
> `puf_check` calls `plfng_check`. So the updater **does** enforce integrity;
> there is still **no signature check**. See §12.3 for the decompiled proof and
> the corrected verdict.

### 12.2 Decompiler evidence (REA + Ghidra 12.1.4, control chain)

Full-function decompilation (`decompile-all --provider ghidra`) of the control
and capture binaries. Pseudocode is Ghidra output, not original source; all
binaries are stripped, so functions are named by address.

| Binary | Size | Functions | What it establishes |
|--------|------|-----------|---------------------|
| `usr/bin/civetitf` | 149 KB | 807 | HTTP bridge; the §9 webserver bugs. No `strcpy`/`strcat`/`sprintf`; no `realpath`. |
| `usr/bin/siciliad` | 25 KB | 176 | LED/status **client** of `:1111`; not the capture owner. |
| `usr/lib/libSiciliaCommand.so` | 63 KB | 513 | Pure RPC marshalling (send/decode/callback per verb); no capture logic. |
| `usr/bin/palermo` | 418 KB | 1988 | Capture engine + `:1111` server; the §10 capture state machine. |

Key functions cited elsewhere in this document:

- **`palermo`**: `FUN_0x460b0` — capture "busy" state gate
  (`"MultiCapture is busy ! (current state = %d)"`); `FUN_0x443fc` — sequence
  completeness/sync check and drop. Server identity confirmed by
  `setting_main_cmd_addr_cb` + 4× `register_server_sicilia_ctrl_capture_*` and
  **zero** client calls.
- **`civetitf`**: `FUN_0x1d6b0` — `/delete` handler (path traversal, §9 item 2);
  `FUN_0x1f350` — `/plf` upload (unvalidated staging, §9 item 3); `FUN_0x19a08` —
  `/settings` `set_config` incl. the timelapse-period forward (§8); `FUN_0x179d8`
  — shared pomp-client busy/timeout (§9 item 4).
- **`siciliad`**: `client_connect_to inet:127.0.0.1:1111`, `led pomp_ctx_listen` —
  client + LED server only.

### 12.3 Flash-time validation of `main_boot` — CRC **yes**, signature **no**

This closes the one open repack question: *is a repacked `main_boot` CRC- or
signature-checked when it is flashed?* Decompiled `libplfng.so` (80 funcs),
`libpinst.so` (196 funcs) and re-read `libpuf` with REA + Ghidra 12.1.4.

**The install path and who checks what:**

```
plf_updater ──> libpuf (puf_check) ──> libplfng (plfng_check)   ← CRC gate
            └─> libpinst  ── writes partitions (main_boot, …)   ← no checks
```

- **`libplfng` is a *validating* PLF reader.** `plfng_check` (export `0x113c8`)
  first validates the header (magic `PLF!`, header/section-header sizes) and the
  **header CRC** (for header-version ≥ 13 — this image is version `0x0d` = 13, so
  it is enforced), then **loops over every section** calling the section
  validator `FUN_0x10eb0`, which recomputes the section's CRC over its data and
  compares it to the stored `crc` field; on the first mismatch it logs
  `"bad section checksum at offset %lu"` and returns **`-EINVAL` (`-0x16`)**,
  aborting the check. Strings: `bad header checksum: p_crc:0x%08x/crc:0x%08x`,
  `bad section checksum at offset %lu`.
- **`libpuf` calls `libplfng`.** `libpuf` imports `plfng_new_from_file`,
  `plfng_check`, `plfng_get_section_count`, `plfng_extract_unixfile`; `puf_check`
  dispatches to `plfng_check`. So the CRC gate runs as part of the updater's
  pre-flight — it is **not** optional. (This is what §12.1 missed by decompiling
  `libpuf` alone.)
- **The CRC algorithm is the POSIX `cksum` CRC-32.** The primitive
  (`FUN_0x115d0` update, `FUN_0x11600` finalize) is an MSB-first table CRC
  (`crc = tbl[(byte ^ (crc>>24)) & 0xff] ^ (crc<<8)`) that **appends the message
  length** and then complements (`~crc`) — the exact POSIX `cksum` definition
  (poly `0x04C11DB7`). The same routine is exported by `plib.so` as
  `sup_posix_crc*`. (zlib in `libplfng` is only used for `inflate`.)
- **`libpinst` does no integrity check of its own.** It imports only
  `fdisk_*`/`ioctl`/`open`/`fopen` — **no** CRC, signature, `plfng` or `puf`
  symbols. It writes the partition images (to `/dev/mtd*`, UBI volumes
  `/dev/ubi*`, or `/dev/mmcblk*`) trusting data already CRC-verified upstream.
  No RSA/ECDSA/SHA/certificate/`verify` code exists in `libpuf`, `libplfng` or
  `libpinst`.

**Partition map** (from the install descriptor, PLF section type `0x0b`):
`bootloader`, **`main_boot`**, `alt_boot`, `misc_boot` are raw boot banks
(main/alt are the A/B pair); `system`, `factory`, `cache`, `data` are UBI
volumes. `main_boot`'s image is carried in the outer PLF (one of the nested
`PLF!` boot volumes, section types `0x03`/`0x0c`), whose bytes are covered by the
section CRC that `plfng_check` verifies before `libpinst` writes them.

**Verdict.** A repacked `main_boot` **is CRC-checked at flash time** — a stale or
wrong section/header CRC is rejected with `-EINVAL` before anything is written —
but it is **not signature-checked**. So a repack is accepted **iff** you
recompute the POSIX `cksum` CRC-32 for the header and each modified section;
there is no cryptographic authenticity gate in the userspace updater/installer
to stop a correctly-CRC'd image.

> Remaining boundary (not flash-time): whether the **SoC boot ROM / u-boot
> verifies a signature at *boot* time** (secure boot) is a separate question
> governed by **OTP/eFuse** state on the specific board, which cannot be read
> from the firmware image. The presence of `flash_otp_dump` / `flash_otp_write` /
> `flash_otp_lock` in `/usr/sbin` shows the P7 SoC *supports* OTP-fused secure
> boot, but not whether it is *enabled*. If secure boot is fused on, a modified
> `main_boot` would flash cleanly (CRC ok) yet be rejected by the ROM at boot —
> test on `alt_boot` first.

1. ~~Section CRC algorithm~~ — **resolved (§12.3)**: it is the **POSIX `cksum`
   CRC-32** (poly `0x04C11DB7`, length-appended, complemented), and it **is**
   verified by `libplfng` at install — correcting the earlier §12.1 note.
2. ~~Flash-time CRC/signature on `main_boot`~~ — **resolved (§12.3)**: CRC
   **yes** (header + every section, via `libplfng`/`plfng_check`), signature
   **no**. A repacked image passes iff its CRCs are recomputed. The only
   remaining boot-chain unknown is **boot-time secure boot** (SoC OTP/eFuse
   state), which cannot be read from the image — test on `alt_boot` on hardware.
3. **CivetWeb version + CVEs** — version is a runtime macro, not a static string;
   get it from the live `Server:` banner (`curl -I http://10.1.1.2/`).
4. ~~`civetitf`/`siciliad` input-validation bugs~~ — **done (§9, §12.2)**:
   `/delete` path traversal (`FUN_0x1d6b0`), unvalidated firmware upload
   (`FUN_0x1f350`), no-auth config, single shared RPC client. Remaining: confirm
   the `/delete` traversal end-to-end on hardware, and recover the live CivetWeb
   version banner for CVE matching.
5. ~~The capture-stop crash lives in `siciliad`~~ — **corrected (§10, §12.2)**:
   capture is owned by `palermo`, whose state machine (`FUN_0x460b0`) rejects work
   as "busy" when stuck, with no watchdog and no exit (so no respawn). Remaining:
   collect `/var/lib/crashdump` + `ulogcat` on a real stall to pin the exact
   trigger (sensor hang vs. storage vs. thermal), and trace what leaves
   `palermo`'s capture state non-ready.
6. **Verify downgrade levers on hardware** — safest first test: flip `update_check`
   live and re-install the same 1.7.1.
7. **`alt_boot` recovery flow** — confirm fallback to bound brick risk.
8. Diff the 1.4.1 / 1.6.1 / 1.7.1 PLFs (all in the repo) to see what changed.

> Tooling note: REA is operational in this environment — **Ghidra 12.1.4** and
> **Hopper 6.6.1** both detected healthy. The only issue was that the MCP server
> launches bare `npx`, which was not on the login `PATH`; `npx` exists via nvm
> (`~/.nvm/versions/node/v22.23.4/bin`) and has been added to `~/.profile`, so the
> REA MCP tools connect after a desktop-app restart (confirmed: the MCP server is
> now reachable). Findings in §12.1–§12.3 and §9–§10 were produced with REA +
> Ghidra 12.1.4. The remaining decompile-reachable items are the live CivetWeb
> version (item 3) and a PLF-version diff (item 8); boot-time secure boot (item 2)
> needs the hardware's OTP state, not the image.

---

## 14. Reproducibility

Two dependency-free Python scripts parse and extract the container: a
header/section walker and an extractor that rebuilds the rootfs and dumps the
nested binary volumes. The PLF layout in §3 is enough to re-implement both. No
`binwalk`/`plftool` needed. (Scripts live in the analysis scratchpad; they can be
committed to the repo on request.)
