# Sequoia PLF tooling

`plf.py` — a dependency-free (Python 3 standard library only) reader and
**repacker** for the Parrot `.plf` firmware container, built so that a modified
image passes the on-camera updater's integrity checks.

It implements the exact format and the exact CRC model the camera enforces,
reverse-engineered from `libplfng.so`/`libpinst.so` with REA + Ghidra and
**verified byte-for-byte against the stock `sequoia_update_171.plf`** (see
[`../Firmware-Analysis.md`](../Firmware-Analysis.md) §3 and §12.3).

## Why this works (and what the camera checks)

The updater (`plf_updater` → `libpuf` → `libplfng`) accepts an image iff:

1. the main header is well-formed (`PLF!` magic, sane sizes), and
2. the **header CRC** (header word[8]) matches, and
3. **every section's CRC** matches,

and then the version policy (upgrade-only, or the `1.5.9` whitelist) allows it.
There is **no signature** anywhere in the update/install path — correct CRCs are
necessary and sufficient. Both CRCs are the **POSIX `cksum` CRC-32** (polynomial
`0x04C11DB7`, MSB-first, message length appended, final one's-complement):

- **Section CRC** = `cksum(section payload bytes, as stored)`.
- **Header CRC** = `cksum( 56-byte header with word[8] zeroed ++ every 20-byte
  section header in file order )`.

`plf.py` recomputes both on every write, so you never touch a CRC by hand.

## Install / requirements

Nothing to install. Needs Python ≥ 3.6. All commands are read-only except the
ones that take an `<out.plf>` (they never modify the input in place).

## Prove it on your machine first

```bash
python3 tools/plf.py selftest "Old Firmware Versions/sequoia_update_171.plf"
```

This checks the `cksum` test vector, confirms a **byte-identical round-trip** of
the stock image, confirms our recomputed CRCs reproduce the stock image
bit-for-bit, and confirms `verify` accepts it.

## Commands

```bash
# Inspect
python3 tools/plf.py info    sequoia_update_171.plf
python3 tools/plf.py verify  sequoia_update_171.plf     # recompute every CRC like the camera
python3 tools/plf.py extract sequoia_update_171.plf  out/   # -> out/rootfs + out/blobs

# Modify (each writes a new file and re-verifies before saving)
python3 tools/plf.py replace-file IN.plf etc/libshsettings/sicilia.cfg new_sicilia.cfg OUT.plf
python3 tools/plf.py set-version  IN.plf 1.5.9 OUT.plf
python3 tools/plf.py fixcrc       IN.plf OUT.plf         # after any manual byte edits
```

`verify` is the one you run before flashing — if it prints `VERIFY OK`, the
camera's `libplfng` will accept the image.

## Worked example — raise the timelapse cap to 24 h

```bash
cd "$(git rev-parse --show-toplevel)"
SRC="Old Firmware Versions/sequoia_update_171.plf"

# 1. pull the current config out of the firmware
python3 tools/plf.py extract "$SRC" /tmp/fw
cp /tmp/fw/rootfs/etc/libshsettings/sicilia.cfg /tmp/sicilia.cfg

# 2. edit the cap (ms): max = 3600000  ->  86400000  (24 h)
#    (note: the HTTP layer forwards the period as a signed 32-bit ms value,
#     so the practical ceiling after this change is ~24.8 days - see §8)
sed -i 's/max *= *3600000/max = 86400000/' /tmp/sicilia.cfg

# 3. repack + verify
python3 tools/plf.py replace-file "$SRC" etc/libshsettings/sicilia.cfg /tmp/sicilia.cfg custom_171.plf
python3 tools/plf.py verify custom_171.plf
```

This changes only the one section that carries `sicilia.cfg` (plus the header
CRC); every other byte, including the boot volumes, is identical to stock.

## Scope, safety, limits

- **`replace-file` swaps a regular file's contents** in the rootfs (type-9
  section). It preserves the file's mode and re-gzips if the original was
  gzipped. It does not add or remove files, and it will refuse a directory or
  symlink or an ambiguous path match.
- **`set-version`** edits the version the *updater* reads; it does not change
  `build.prop`, so the running system still reports its real version.
- **The CRC covers integrity, not authenticity.** This tooling lets you build an
  image the stock updater accepts; it is for your own device. It cannot and does
  not defeat **boot-time** secure boot (SoC OTP/eFuse) if that is enabled — see
  the reflash runbook.
- Keep a **known-good stock `.plf`** for recovery before flashing anything.

Flashing to hardware: follow [`../Reflash-Runbook.md`](../Reflash-Runbook.md).
