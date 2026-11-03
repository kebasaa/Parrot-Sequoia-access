#!/usr/bin/env python3
"""
plf.py - Parrot PLF (Parrot Linux Firmware) reader / repacker for the Sequoia.

Dependency-free (standard library only). Implements the exact container format
and the exact integrity checks the on-camera updater enforces, so a repacked
image is accepted by `plf_updater` / `libpinst`.

Integrity model (reverse-engineered from libplfng.so with REA + Ghidra, and
verified byte-for-byte against sequoia_update_171.plf - see Firmware-Analysis.md
sections 3 and 12.3):

  * Each section header carries a `crc` field = POSIX cksum CRC-32 of that
    section's stored payload bytes.
  * The main header word[8] is the HEADER crc = POSIX cksum CRC-32 of
    (the 56-byte header with word[8] zeroed) concatenated with every 20-byte
    section header in file order (payloads skipped).
  * There is NO cryptographic signature anywhere in the update path. Correct
    CRCs are necessary and sufficient for the updater to accept the image.

POSIX cksum CRC-32: polynomial 0x04C11DB7, MSB-first, no reflection, the message
byte-length appended after the data, final one's-complement.

CLI:
  plf.py info     <in.plf>
  plf.py verify   <in.plf>                      # recompute every CRC like the camera does
  plf.py extract  <in.plf> <outdir>             # rootfs (type 9) + raw section blobs
  plf.py fixcrc   <in.plf> <out.plf>            # recompute all CRCs, rewrite
  plf.py replace-file <in.plf> <rootfs-path> <newfile> <out.plf>
  plf.py set-version  <in.plf> <maj.min.patch> <out.plf>
  plf.py selftest <in.plf>                      # prove the CRC + serializer on a known-good image

All writers recompute every CRC and re-verify the result before saving.
"""
import struct, sys, os, zlib, stat

MAGIC = 0x21464C50           # "PLF!"
HDR_FMT = "<14I"             # 14 x uint32 = 56-byte main header
HDR_SIZE = 56
SH_FMT = "<5I"              # type, size, crc, load_addr, uncompressed
SH_SIZE = 20
W_HEADER_CRC = 8            # index of the header-crc word in the main header
W_VER_MAJOR, W_VER_MINOR, W_VER_PATCH = 9, 10, 11
W_FILE_SIZE = 13
TYPE_FILESYSTEM = 0x09

# ---------------------------------------------------------------- CRC (cksum)
def _mk_cksum_table():
    tab = []
    for i in range(256):
        c = (i << 24) & 0xFFFFFFFF
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if (c & 0x80000000) else (c << 1) & 0xFFFFFFFF
        tab.append(c)
    return tab

_CKSUM_TAB = _mk_cksum_table()

def cksum(data):
    """POSIX cksum CRC-32 over `data` (bytes)."""
    crc = 0
    tab = _CKSUM_TAB
    for b in data:
        crc = (tab[((crc >> 24) ^ b) & 0xFF] ^ ((crc << 8) & 0xFFFFFFFF)) & 0xFFFFFFFF
    n = len(data)
    while n:
        crc = (tab[((crc >> 24) ^ (n & 0xFF)) & 0xFF] ^ ((crc << 8) & 0xFFFFFFFF)) & 0xFFFFFFFF
        n >>= 8
    return (~crc) & 0xFFFFFFFF

# ---------------------------------------------------------------- data model
def _pad4(n):
    return (4 - (n & 3)) & 3

class Section:
    __slots__ = ("type", "crc", "load_addr", "uncompressed", "payload", "pad")
    def __init__(self, stype, crc, load_addr, uncompressed, payload, pad=b""):
        self.type = stype
        self.crc = crc
        self.load_addr = load_addr
        self.uncompressed = uncompressed
        self.payload = payload
        self.pad = pad                      # trailing padding bytes as found on disk
    @property
    def size(self):
        return len(self.payload)
    def header_bytes(self, crc=None):
        return struct.pack(SH_FMT, self.type, self.size,
                           self.crc if crc is None else crc,
                           self.load_addr, self.uncompressed)
    def computed_crc(self):
        return cksum(self.payload)

class PLF:
    def __init__(self, header_words, sections, trailer=b""):
        self.h = list(header_words)         # 14 words
        self.sections = sections            # list[Section]
        self.trailer = trailer              # any bytes after the last section (normally none)

    # -- parse ------------------------------------------------------------
    @classmethod
    def parse(cls, data):
        if len(data) < HDR_SIZE:
            raise ValueError("file shorter than a PLF header")
        words = list(struct.unpack_from(HDR_FMT, data, 0))
        if words[0] != MAGIC:
            raise ValueError("bad magic 0x%08x (not a PLF)" % words[0])
        hsize, shsize = words[2], words[3]
        if hsize != HDR_SIZE or shsize != SH_SIZE:
            raise ValueError("unexpected header_size=%d section_hdr_size=%d" % (hsize, shsize))
        secs = []
        off = hsize
        while off + shsize <= len(data):
            stype, ssize, crc, load, usize = struct.unpack_from(SH_FMT, data, off)
            body_off = off + shsize
            if body_off + ssize > len(data):
                raise ValueError("section at 0x%x overruns file (size=%d)" % (off, ssize))
            payload = data[body_off:body_off + ssize]
            pad_n = _pad4(ssize)
            pad = data[body_off + ssize: body_off + ssize + pad_n]
            secs.append(Section(stype, crc, load, usize, payload, pad))
            off = body_off + ssize + pad_n
        trailer = data[off:]
        return cls(words, secs, trailer)

    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as f:
            return cls.parse(f.read())

    # -- serialize --------------------------------------------------------
    def header_crc(self):
        """Recompute the header CRC exactly as libplfng does."""
        hdr = bytearray(struct.pack(HDR_FMT, *self.h))
        struct.pack_into("<I", hdr, W_HEADER_CRC * 4, 0)     # zero the crc field
        buf = bytearray(hdr)
        for s in self.sections:
            buf += s.header_bytes()                           # uses each section's stored crc
        return cksum(bytes(buf))

    def recompute_crcs(self):
        """Set every section crc and the header crc + file_size from current data."""
        for s in self.sections:
            s.crc = s.computed_crc()
        self.h[W_FILE_SIZE] = self.serialized_size()
        self.h[W_HEADER_CRC] = self.header_crc()

    def serialized_size(self):
        n = HDR_SIZE
        for s in self.sections:
            n += SH_SIZE + s.size + _pad4(s.size)
        n += len(self.trailer)
        return n

    def to_bytes(self):
        out = bytearray(struct.pack(HDR_FMT, *self.h))
        for s in self.sections:
            out += s.header_bytes()
            out += s.payload
            pad_n = _pad4(s.size)
            # preserve original padding when it matches, else zero-pad
            out += (s.pad if len(s.pad) == pad_n else b"\x00" * pad_n)
        out += self.trailer
        return bytes(out)

    def save(self, path, recompute=True, verify_after=True):
        if recompute:
            self.recompute_crcs()
        data = self.to_bytes()
        if verify_after:
            ok, errs = PLF.parse(data).verify()
            if not ok:
                raise RuntimeError("internal: rebuilt image fails verify:\n  " + "\n  ".join(errs))
        with open(path, "wb") as f:
            f.write(data)
        return len(data)

    # -- verify (mirror of libplfng plfng_check) --------------------------
    def verify(self):
        errs = []
        if self.h[0] != MAGIC:
            errs.append("bad magic")
        hc = self.header_crc()
        if hc != self.h[W_HEADER_CRC]:
            errs.append("bad header checksum: stored 0x%08x computed 0x%08x"
                        % (self.h[W_HEADER_CRC], hc))
        for i, s in enumerate(self.sections):
            cc = s.computed_crc()
            if cc != s.crc:
                errs.append("bad section checksum: section %d type 0x%02x stored 0x%08x computed 0x%08x"
                            % (i, s.type, s.crc, cc))
        fs = self.serialized_size()
        if self.h[W_FILE_SIZE] != fs:
            errs.append("file_size field 0x%08x != actual 0x%08x" % (self.h[W_FILE_SIZE], fs))
        return (len(errs) == 0, errs)

    # -- version ----------------------------------------------------------
    def version(self):
        return (self.h[W_VER_MAJOR], self.h[W_VER_MINOR], self.h[W_VER_PATCH])
    def set_version(self, maj, minr, patch):
        self.h[W_VER_MAJOR], self.h[W_VER_MINOR], self.h[W_VER_PATCH] = maj, minr, patch

# ---------------------------------------------------------- type-9 filesystem
def _fs_decode(section):
    """Return (name, meta12, content, was_gzip) for a type-9 section, or None."""
    if section.type != TYPE_FILESYSTEM:
        return None
    body = section.payload
    was_gzip = body[:2] == b"\x1f\x8b"
    raw = zlib.decompress(body, 16 + zlib.MAX_WBITS) if was_gzip else body
    nul = raw.index(b"\x00")
    name = raw[:nul].decode("utf-8", "replace")
    meta = raw[nul + 1: nul + 1 + 12]              # mode(u32) + 2 x u32
    content = raw[nul + 1 + 12:]
    return name, meta, content, was_gzip

def _fs_encode(name, meta12, content, gzip_it):
    raw = name.encode() + b"\x00" + meta12 + content
    if gzip_it:
        co = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)   # gzip wrapper
        body = co.compress(raw) + co.flush()
        return body, len(raw)
    return raw, 0

# ------------------------------------------------------------------- extract
def _safe_join(base, rel):
    rel = rel.lstrip("/")
    p = os.path.normpath(os.path.join(base, rel))
    if not (p == base or p.startswith(base + os.sep)):
        raise ValueError("path escape: " + rel)
    return p

def cmd_extract(plf, outdir):
    rootfs = os.path.join(outdir, "rootfs")
    blobs = os.path.join(outdir, "blobs")
    os.makedirs(rootfs, exist_ok=True)
    os.makedirs(blobs, exist_ok=True)
    nf = nd = nl = nb = 0
    for i, s in enumerate(plf.sections):
        if s.type == TYPE_FILESYSTEM:
            name, meta, content, _ = _fs_decode(s)
            mode = struct.unpack_from("<I", meta, 0)[0]
            ftype = stat.S_IFMT(mode)
            dst = _safe_join(os.path.abspath(rootfs), name)
            if ftype == stat.S_IFDIR:
                os.makedirs(dst, exist_ok=True); nd += 1
            elif ftype == stat.S_IFLNK:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                tgt = content.split(b"\x00")[0].decode("utf-8", "replace")
                if os.path.lexists(dst): os.remove(dst)
                try: os.symlink(tgt, dst)
                except OSError: open(dst + ".symlink", "w").write(tgt)
                nl += 1
            else:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(dst, "wb") as f: f.write(content)
                nf += 1
        else:
            with open(os.path.join(blobs, "sec%04d_type0x%02x.bin" % (i, s.type)), "wb") as f:
                f.write(s.payload); nb += 1
    print("extracted: files=%d dirs=%d symlinks=%d blobs=%d -> %s" % (nf, nd, nl, nb, outdir))

# --------------------------------------------------------------------- verbs
def cmd_info(plf):
    print("PLF version %d.%d.%d  file_type=%d platform=%d application=%d"
          % (plf.version() + (plf.h[4], plf.h[6], plf.h[7])))
    print("header_crc=0x%08x  file_size=%d  sections=%d" % (plf.h[W_HEADER_CRC], plf.h[W_FILE_SIZE], len(plf.sections)))
    hist = {}
    for s in plf.sections:
        hist[s.type] = hist.get(s.type, 0) + 1
    print("section types: " + ", ".join("0x%02x:%d" % (t, n) for t, n in sorted(hist.items())))
    nfiles = sum(1 for s in plf.sections if s.type == TYPE_FILESYSTEM)
    print("type-9 filesystem entries: %d" % nfiles)

def cmd_verify(plf):
    ok, errs = plf.verify()
    if ok:
        print("VERIFY OK - header + %d section CRCs all valid; the updater will accept this image."
              % len(plf.sections))
        return 0
    print("VERIFY FAILED (%d problem(s)):" % len(errs))
    for e in errs[:50]:
        print("  " + e)
    if len(errs) > 50:
        print("  ... and %d more" % (len(errs) - 50))
    return 1

def _find_fs_section(plf, rootfs_path):
    want = "/" + rootfs_path.lstrip("/")
    hits = []
    for i, s in enumerate(plf.sections):
        if s.type == TYPE_FILESYSTEM:
            name, meta, content, gz = _fs_decode(s)
            nm = "/" + name.lstrip("./").lstrip("/")
            if nm == want or name == rootfs_path or name.lstrip("./") == rootfs_path.lstrip("/"):
                hits.append((i, name, meta, content, gz))
    return hits

def cmd_replace_file(plf, rootfs_path, newfile, out):
    hits = _find_fs_section(plf, rootfs_path)
    if not hits:
        print("error: no type-9 entry matching %r" % rootfs_path); return 1
    if len(hits) > 1:
        print("error: %d entries match %r: %s" % (len(hits), rootfs_path, [h[1] for h in hits])); return 1
    i, name, meta, old, gz = hits[0]
    mode = struct.unpack_from("<I", meta, 0)[0]
    if stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        print("error: %r is not a regular file (mode 0%o)" % (rootfs_path, mode)); return 1
    with open(newfile, "rb") as f:
        new = f.read()
    body, usize = _fs_encode(name, meta, new, gz)
    plf.sections[i].payload = body
    plf.sections[i].uncompressed = usize
    plf.sections[i].pad = b""        # force zero-pad recompute
    n = plf.save(out)
    print("replaced %s (%d -> %d bytes, %s) ; wrote %s (%d bytes)"
          % (name, len(old), len(new), "gzip" if gz else "stored", out, n))
    print("  section %d crc -> 0x%08x ; header crc -> 0x%08x" % (i, plf.sections[i].crc, plf.h[W_HEADER_CRC]))
    return 0

def cmd_set_version(plf, verstr, out):
    try:
        maj, minr, patch = (int(x) for x in verstr.split("."))
    except Exception:
        print("error: version must be maj.min.patch, e.g. 1.5.9"); return 1
    old = plf.version()
    plf.set_version(maj, minr, patch)
    n = plf.save(out)
    print("version %d.%d.%d -> %d.%d.%d ; wrote %s (%d bytes) ; header crc -> 0x%08x"
          % (old + (maj, minr, patch) + (out, n, plf.h[W_HEADER_CRC])))
    return 0

def cmd_fixcrc(plf, out):
    before = (plf.h[W_HEADER_CRC], plf.h[W_FILE_SIZE])
    n = plf.save(out)
    print("recomputed all CRCs ; wrote %s (%d bytes)" % (out, n))
    print("  header crc 0x%08x -> 0x%08x ; file_size %d -> %d"
          % (before[0], plf.h[W_HEADER_CRC], before[1], plf.h[W_FILE_SIZE]))
    return 0

def cmd_selftest(path):
    ok = True
    # 1. cksum known test vector (POSIX: cksum of "123456789" == 930766865)
    tv = cksum(b"123456789")
    print("[%s] cksum known vector: 0x%08x (%d)" % ("ok" if tv == 930766865 else "FAIL", tv, tv))
    ok &= tv == 930766865
    data = open(path, "rb").read()
    p = PLF.parse(data)
    # 2. byte-identical round-trip (serializer reproduces the input exactly)
    rt = p.to_bytes() == data
    print("[%s] byte-identical round-trip of %s" % ("ok" if rt else "FAIL", os.path.basename(path)))
    ok &= rt
    # 3. recompute-then-serialize also identical (our CRCs match the camera's)
    p2 = PLF.parse(data); p2.recompute_crcs()
    rc = p2.to_bytes() == data
    print("[%s] recomputed CRCs reproduce the stock image bit-for-bit" % ("ok" if rc else "FAIL"))
    ok &= rc
    # 4. verify passes
    vok, _ = p.verify()
    print("[%s] verify() accepts the stock image (%d sections)" % ("ok" if vok else "FAIL", len(p.sections)))
    ok &= vok
    print("SELFTEST", "PASSED" if ok else "FAILED")
    return 0 if ok else 1

USAGE = __doc__

def main(argv):
    if len(argv) < 2:
        print(USAGE); return 2
    cmd = argv[1]
    try:
        if cmd == "info":
            return cmd_info(PLF.from_file(argv[2])) or 0
        if cmd == "verify":
            return cmd_verify(PLF.from_file(argv[2]))
        if cmd == "extract":
            cmd_extract(PLF.from_file(argv[2]), argv[3]); return 0
        if cmd == "fixcrc":
            return cmd_fixcrc(PLF.from_file(argv[2]), argv[3])
        if cmd == "replace-file":
            return cmd_replace_file(PLF.from_file(argv[2]), argv[3], argv[4], argv[5])
        if cmd == "set-version":
            return cmd_set_version(PLF.from_file(argv[2]), argv[3], argv[4])
        if cmd == "selftest":
            return cmd_selftest(argv[2])
        print("unknown command %r\n" % cmd); print(USAGE); return 2
    except (IndexError,) :
        print("missing argument(s) for %r\n" % cmd); print(USAGE); return 2

if __name__ == "__main__":
    sys.exit(main(sys.argv))
