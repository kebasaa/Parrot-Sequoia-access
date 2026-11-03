# Sequoia reflash runbook — OTP check + `alt_boot`-first testing

A step-by-step, recovery-first procedure for testing a repacked `.plf` on real
hardware. Read it fully before touching the device.

It has two goals:

1. **Find out whether boot-time secure boot is enabled** (SoC OTP/eFuse), which
   decides whether a modified `main_boot` could ever boot.
2. **Give a safe order of operations** so a bad image can't permanently brick the
   camera — back up first, prefer changes that never touch `main_boot`, and test
   boot changes on the recovery bank.

Everything here is grounded in the static analysis in
[`Firmware-Analysis.md`](Firmware-Analysis.md) (§3, §4, §12). Points that could
not be confirmed from the image alone are marked **(verify on device)**.

> **Golden rules**
> - Keep an untouched stock `.plf` (`Old Firmware Versions/sequoia_update_171.plf`)
>   on the computer. It is your recovery image.
> - **Back up every boot partition to the computer before you flash anything.**
> - For the research goals (longer timelapse, config, extra tools) you do **not**
>   need to modify `main_boot` at all — do Part 3 and skip Part 4.
> - Change one thing at a time; run `plf.py verify` before every flash.

---

## Part 0 — Access and sanity

Access is over ADB (TCP port 9050, root, no password — see
[`Firmware-Analysis.md`](Firmware-Analysis.md) §4). Over USB the camera is
`10.1.1.2`.

```bash
adb connect 10.1.1.2:9050
adb shell id            # expect uid=0(root)
adb shell cat /etc/build.prop | grep version    # confirm ro.parrot.build.version=1.7.1
```

Work on a charged battery or external power. A power loss **during** a boot-bank
write is the one thing that genuinely bricks the device.

---

## Part 1 — Is secure boot enabled? (OTP read, read-only)

If the SoC verifies a signature on `main_boot` at boot, a modified boot image
will flash fine (CRC is ok) but the boot ROM will reject it. That gate lives in
one-time-programmable fuses, which you can only read on the device. The firmware
ships `flash_otp_info` / `flash_otp_dump` (`/usr/sbin`), which take `-f` (factory
region) or `-u` (user region) and an MTD device.

```bash
# find the raw flash device(s)
adb shell cat /proc/mtd
# OTP region sizes + lock state (try the boot/first MTD device, e.g. /dev/mtd0)
adb shell /usr/sbin/flash_otp_info -f /dev/mtd0
adb shell /usr/sbin/flash_otp_info -u /dev/mtd0
# dump the fuse contents
adb shell /usr/sbin/flash_otp_dump -f /dev/mtd0
adb shell /usr/sbin/flash_otp_dump -u /dev/mtd0
```

Repeat for each MTD device `/proc/mtd` lists until the OTP ioctls succeed
(`OTPGETREGIONCOUNT` > 0).

**How to read the result (inference — confirm against Parrot P7 docs if you can):**

- **Factory OTP is empty / all `0x00` / all `0xFF`, and unlocked** → no
  secure-boot key is fused → a modified `main_boot` will boot. Part 4 is safe to
  attempt.
- **Factory OTP contains a non-trivial value (looks like a key hash) and is
  `[locked]`** → secure boot may be enforced → **do not flash a modified
  `main_boot`**; a modified kernel/u-boot would be rejected by the ROM and you'd
  depend entirely on `alt_boot` fallback. Stick to Part 3 (rootfs/config only).
- Unsure → treat it as "enabled" and stay in Part 3.

> The exact OTP layout (which bytes are the secure-boot key, the enable fuse) is
> **not** in the firmware image; it is an SoC property. The dump tells you whether
> *something* is fused and locked, which is enough to decide conservatively.

---

## Part 2 — Map the partitions and back everything up

The install descriptor (PLF section type `0x0b`) names the partitions:
`bootloader`, `main_boot`, `alt_boot`, `misc_boot` (raw boot banks — `main`/`alt`
are the A/B pair), and `system`, `factory`, `cache`, `data` (UBI volumes). Map
them to real devices on the camera:

```bash
adb shell cat /proc/mtd          # NAND partitions + names
adb shell ls -l /dev/mtd* /dev/ubi* /dev/mmcblk* 2>/dev/null
adb shell cat /proc/cmdline      # often shows the boot device / selected bank
```

Back up **every** boot-related partition to the computer. Match each name from
`/proc/mtd` to its `mtdN`, then:

```bash
# example: if /proc/mtd shows mtd3 "main_boot", mtd4 "alt_boot", mtd2 "misc_boot",
# mtd1 "bootloader" - adjust numbers to YOUR /proc/mtd output
for p in bootloader main_boot alt_boot misc_boot; do
  n=$(adb shell cat /proc/mtd | awk -v P="\"$p\"" '$0 ~ P {gsub(":","",$1); print $1}')
  echo "backing up $p from /dev/$n"
  adb exec-out /usr/sbin/nanddump -q "/dev/$n" > "backup_${p}.bin"
done
ls -l backup_*.bin
```

(If `nanddump` isn't present, use `dd if=/dev/mtdblockN` via `adb exec-out`.)
Store these backups safely — they are how you restore a bad boot flash.

---

## Part 3 — Recommended path: rootfs/config changes, **no boot risk**

This covers the longer-timelapse goal, config tweaks, patched user binaries and
added tools. The boot volumes stay byte-identical to stock, so the bootloader is
never at risk.

### 3a. Live edit (lowest risk, no flashing at all)

The rootfs is writable; this is the safest way and needs no PLF at all:

```bash
adb connect 10.1.1.2:9050
adb shell mount -o remount,rw /
adb shell vi /etc/libshsettings/sicilia.cfg     # raise capture_timelapse_period.max (ms)
adb shell sync && adb reboot
```

Edits under `/data` are the most durable; edits under `/etc` survive reboot but
are replaced by a future firmware update.

### 3b. Repacked install (persists as a real firmware image)

Build the image on the computer and verify it first:

```bash
# e.g. the 24 h timelapse cap from tools/README.md -> custom_171.plf
python3 tools/plf.py verify custom_171.plf       # must print VERIFY OK
```

Make the updater accept it. The cleanest lever for repeated testing is the
**version whitelist** (`1.5.9` is accepted regardless of the installed version —
§12); it does not change what gets installed, only the accept decision:

```bash
python3 tools/plf.py set-version custom_171.plf 1.5.9 custom_159.plf
python3 tools/plf.py verify custom_159.plf
```

(Alternative: live-edit `/etc/plf_updater.conf` and set `update_check` to a
non-`up` value to drop the version check entirely.)

Deliver it to the update partition and trigger the updater:

```bash
adb connect 10.1.1.2:9050
adb push custom_159.plf /tmp/custom.plf
adb shell mount -o remount,rw /
adb shell cp /tmp/custom.plf /update/sequoia_update.plf
adb shell sync
adb shell /usr/bin/pinst_trigger 1      # BOOTMODE 1 = run the updater on next boot
adb reboot
```

After it reboots, reconnect and confirm your change landed:

```bash
adb connect 10.1.1.2:9050
adb shell grep -A3 capture_timelapse_period /etc/libshsettings/sicilia.cfg
```

Because the repacked image carries the **unchanged** boot sections, this install
rewrites `main_boot` with the same bytes it already had — no bootloader risk.

> **(verify on device)** Confirm the updater applies a `1.5.9`-stamped image over
> an installed `1.7.1` as expected, on a first run with an *unmodified* repack
> (same bytes, CRCs recomputed) before trusting it with real changes.

---

## Part 4 — Only if you must modify `main_boot` (kernel/bootloader)

Do this **only** if Part 1 showed secure boot is **not** fused, and you actually
need a changed kernel or u-boot. Otherwise stay in Part 3.

The camera has A/B boot banks (`main_boot` / `alt_boot`). The intended safety is
that a bad `main_boot` falls back to `alt_boot`. **However, the bank-selection /
fallback logic lives in the bootloader, which was not decompiled, and there is no
userspace `fw_setenv`/recovery script in the image to drive it** — so treat the
fallback as *unverified* and keep your Part 2 backups as the real safety net.

Conservative procedure:

1. **Prove the fallback first, before risking anything.** With your backups made,
   copy the *known-good* boot image into `alt_boot` so both banks are good, then
   deliberately test how the device chooses a bank **(verify on device)** — e.g.
   inspect `misc_boot` (the likely A/B / boot-control block) and `/proc/cmdline`
   across a normal boot to learn the selector. Do not proceed until you
   understand how to make it try `alt_boot` and how it falls back.
2. Flash the **modified** boot image to **`alt_boot`** (never `main_boot` first),
   using the same partition you identified in Part 2:
   ```bash
   adb push new_main_boot.bin /tmp/new_boot.bin
   adb shell /usr/sbin/flash_erase /dev/mtdN 0 0     # N = alt_boot
   adb shell nandwrite -p /dev/mtdN /tmp/new_boot.bin
   ```
3. Trigger a boot from `alt_boot` by the selector you confirmed in step 1, and
   reboot. If it comes up, you have a working modified boot in the recovery bank
   and `main_boot` is still stock.
4. Only after `alt_boot` boots your image reliably, consider promoting it to
   `main_boot` — keeping `alt_boot` as the known-good escape.

If a flash leaves the camera unbootable, restore from your backups (Part 5).

---

## Part 5 — Recovery

- **Still boots to ADB:** re-flash the stock partition from your Part 2 backup:
  ```bash
  adb push backup_main_boot.bin /tmp/restore.bin
  adb shell /usr/sbin/flash_erase /dev/mtdN 0 0
  adb shell nandwrite -p /dev/mtdN /tmp/restore.bin
  adb reboot
  ```
- **Won't boot but `alt_boot` is good:** boot the recovery bank, then restore
  `main_boot` from backup as above.
- **Full stock restore:** push the untouched stock `.plf` to
  `/update/sequoia_update.plf` and `pinst_trigger 1; reboot` (Part 3b) — this
  rewrites all partitions to stock.
- **No ADB at all (hard brick):** recovery then needs the SoC's low-level USB
  boot/JTAG, which is outside this runbook. This is exactly the state the
  backups-and-`alt_boot`-first order is designed to avoid.

---

## Checklist

- [ ] Stock `.plf` saved on the computer
- [ ] `plf.py selftest` passes on the stock image
- [ ] OTP read done; secure-boot state decided (Part 1)
- [ ] All boot partitions backed up (Part 2)
- [ ] `plf.py verify` prints `VERIFY OK` on the image to flash
- [ ] Change applied via Part 3 (rootfs/config) — boot untouched
- [ ] (Only if needed) boot change tested on `alt_boot` first (Part 4)
