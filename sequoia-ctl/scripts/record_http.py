#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 kebasaa
"""Record raw responses from a Parrot Sequoia for use as test fixtures.

Only uses the Python standard library so it runs before anything is installed:

    uv run --no-project python scripts/record_http.py --host 10.1.1.2 -o tests/fixtures/http
    uv run --no-project python scripts/record_http.py --capture        # also take one photo
    uv run --no-project python scripts/record_http.py --offline-bundle  # zip everything up

What it does:
  1. probes which TCP ports are open (21 FTP, 22 SSH, 23 telnet, 80 HTTP, 9050 adb, 15740 PTP/IP)
  2. GETs every documented read-only endpoint and stores status code + body
  3. walks /file/... recursively (listing only)
  4. with --capture: starts a single capture, polls /capture, records the
     responses, diffs the file tree and downloads the new files
  5. with exiftool installed: dumps the metadata of downloaded files as JSON
"""

import argparse
import json
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 9050: "adb", 15740: "ptpip"}
READ_ENDPOINTS = [
    "/", "/capture", "/config", "/status", "/calibration", "/storage",
    "/file", "/version", "/wifi", "/manualmode",
]


def safe_name(path):
    s = path.strip("/").replace("/", "__") or "root"
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)


class Recorder:
    def __init__(self, host, out, timeout):
        self.base = "http://%s" % host
        self.host = host
        self.out = out
        self.timeout = timeout
        self.log = []

    def get(self, path, save=True, tag=""):
        url = self.base + path
        t0 = time.time()
        entry = {"path": path, "time_utc": datetime.now(timezone.utc).isoformat()}
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as r:
                body = r.read()
                entry["status"] = r.status
                entry["content_type"] = r.headers.get("Content-Type")
        except urllib.error.HTTPError as e:
            body = e.read()
            entry["status"] = e.code
            entry["content_type"] = e.headers.get("Content-Type")
        except Exception as e:  # noqa: BLE001 - we want to record anything
            entry["error"] = repr(e)
            body = b""
        entry["elapsed_s"] = round(time.time() - t0, 3)
        entry["bytes"] = len(body)
        parsed = None
        try:
            parsed = json.loads(body.decode("utf-8"))
        except Exception:
            pass
        if save:
            name = safe_name(path) + (("." + tag) if tag else "")
            if parsed is not None:
                (self.out / (name + ".json")).write_text(json.dumps(parsed, indent=2, sort_keys=True))
            elif body:
                (self.out / (name + ".body")).write_bytes(body[:200000])
        self.log.append(entry)
        status = entry.get("status", entry.get("error"))
        print("  GET %-40s -> %s (%d bytes, %.2fs)" % (path, status, len(body), entry["elapsed_s"]))
        return parsed, body

    def save_log(self):
        (self.out / "_requests.json").write_text(json.dumps(self.log, indent=2))


def probe_ports(host, timeout=1.5):
    res = {}
    for port, name in PORTS.items():
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            res[name] = True
        except OSError:
            res[name] = False
        finally:
            s.close()
        print("  port %5d %-7s %s" % (port, name, "OPEN" if res[name] else "closed"))
    return res


def walk_files(rec, path, depth=0, found=None):
    """Recursively list /file/... and collect leaf entries.

    The listing format is unknown before recording, so this is deliberately
    generous: any dict/list element with a name-like key is followed."""
    if found is None:
        found = []
    if depth > 4:
        return found
    data, _ = rec.get(path)
    if data is None:
        return found
    items = []
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                items.extend(v)
            elif isinstance(v, dict):
                items.append(v)
        if not items:
            items = [{"name": k} for k in data.keys()]
    elif isinstance(data, list):
        items = data
    for it in items:
        if isinstance(it, str):
            name, is_dir = it, "." not in it
        elif isinstance(it, dict):
            name = it.get("name") or it.get("path") or it.get("url")
            is_dir = bool(it.get("is_dir") or it.get("type") in ("dir", "folder", "directory")
                          or ("." not in str(name)))
        else:
            continue
        if not name:
            continue
        name = str(name).strip("/").split("/")[-1]
        child = path.rstrip("/") + "/" + name
        if is_dir:
            walk_files(rec, child, depth + 1, found)
        else:
            found.append(child)
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="10.1.1.2", help="10.1.1.2 (USB) or 192.168.47.1 (WiFi)")
    ap.add_argument("-o", "--output", default="tests/fixtures/http", help="output folder")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--capture", action="store_true", help="take ONE single capture and record it")
    ap.add_argument("--no-download", action="store_true", help="with --capture: do not download files")
    ap.add_argument("--offline-bundle", action="store_true",
                    help="zip the output folder at the end (for recording over WiFi offline)")
    ap.add_argument("--reconnect-wifi", metavar="SSID",
                    help="after recording, reconnect to this WiFi network (netsh/nmcli)")
    args = ap.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    print("Recording %s into %s" % (args.host, out.resolve()))

    print("[1] port scan")
    ports = probe_ports(args.host)
    (out / "_ports.json").write_text(json.dumps(ports, indent=2))
    if not ports.get("http"):
        print("HTTP port closed - is the camera connected and is the host IP right?")

    rec = Recorder(args.host, out, args.timeout)
    print("[2] read-only endpoints")
    for ep in READ_ENDPOINTS:
        rec.get(ep)

    print("[3] file tree")
    before = walk_files(rec, "/file")
    (out / "_files_before.json").write_text(json.dumps(before, indent=2))

    if args.capture:
        print("[4] single capture")
        rec.get("/capture", tag="before")
        rec.get("/capture/start", tag="start")
        # Poll for up to 15 s; stop early once the status no longer mentions
        # "running" (after a few polls, so the transition itself is recorded).
        for i in range(30):
            time.sleep(0.5)
            data, _ = rec.get("/capture", tag="poll%02d" % i)
            if i >= 4 and data is not None and "running" not in json.dumps(data).lower():
                break
        rec.get("/capture/stop", tag="stop")
        time.sleep(2)
        after_dir = out / "after_capture"
        after_dir.mkdir(exist_ok=True)
        rec_after = Recorder(args.host, after_dir, args.timeout)
        after = walk_files(rec_after, "/file")
        rec_after.save_log()
        new = sorted(set(after) - set(before))
        (out / "_files_new.json").write_text(json.dumps(new, indent=2))
        print("  new files: %d" % len(new))
        for p in new:
            print("    " + p)
        if new and not args.no_download:
            img_dir = out / "images"
            img_dir.mkdir(exist_ok=True)
            for p in new:
                dl = "/download/" + p[len("/file/"):]
                _, body = rec.get(dl, save=False)
                if body:
                    (img_dir / p.split("/")[-1]).write_bytes(body)
            exiftool = shutil.which("exiftool")
            if exiftool:
                print("[5] exiftool metadata")
                meta = subprocess.run([exiftool, "-json", "-G1", "-a", "-n", str(img_dir)],
                                      capture_output=True, text=True)
                (out / "_exiftool.json").write_text(meta.stdout)
            else:
                print("[5] exiftool not found - skipped metadata dump")

    rec.save_log()
    if args.reconnect_wifi:
        if sys.platform.startswith("win"):
            cmd = ["netsh", "wlan", "connect", "name=%s" % args.reconnect_wifi]
        else:
            cmd = ["nmcli", "connection", "up", args.reconnect_wifi]
        print("Reconnecting WiFi: %s" % " ".join(cmd))
        subprocess.run(cmd)
    if args.offline_bundle:
        zpath = out.with_suffix(".zip")
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            for f in out.rglob("*"):
                z.write(f, f.relative_to(out.parent))
        print("Bundle written to %s" % zpath)
    print("Done.")


if __name__ == "__main__":
    main()
