#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GBF Extract - Geutebrueck G-Core Backup File (.gbf) decryptor & video extractor.

Reverse-engineered format (details in README.md / AGENTS.md):

  raw file
    0x0000-0x0FFF : main header (salt, section directory at 0xA00, sizes)
    0x1000-...    : ONE continuous AES-256-CBC stream
                    key = SHA-256(password_utf8)
                    IV  = recovered via known plaintext '<?xml version="1'
                    (CBC: only the first 16 bytes depend on the IV)
    0x1000        : ExportInfo XML (length field at hdr+0x58)
    0x2000        : media region (size field at hdr+0x38)
                    [72-byte record header][record data] ...
    media_end     : index region (72-byte index records)

  record header (72 bytes)
    +0x00-0x0B : record nonce / id  (some records start '00000850' + u32 stride)
    +0x0C-0x0F : signature  d2 38 0c c4
    +0x10      : 0xff marker
    +0x11-0x13 : u24 timestamp/counter (monotonic per stream)
    +0x14      : 0x02  -> video/sample record
                 other -> event record (UTF-16 key/value text follows at +0x15)
    +0x1C-0x1F : 0xffffffff, or record stride (for '00000850' records)
    +0x20-0x23 : 80 07 38 04
    +0x30-0x33 : type word  00 04 01 02 (slice) / 00 04 00 02 (SPS/PPS)
    +0x40-0x43 : small length-ish field (mirrored at data+8 for some records)

  video record data : H.264 annex-B NAL units (00 00 00 01 prefix, zero-padded)
  event record data : UTF-16LE key/value strings

Multi-camera: streams are grouped by their SPS. Each camera encoder emits its
own SPS periodically; whenever a different SPS hash shows up a new stream is
opened and following NALs are routed to it.
"""
import argparse
import getpass
import hashlib
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET

__version__ = "1.3.3"

BLOCK = 4096
SIG = b"\xd2\x38\x0c\xc4"
KNOWN_PT = b'<?xml version="1'


def require_crypto():
    try:
        from Crypto.Cipher import AES
        return AES
    except ImportError:
        sys.exit("Missing dependency: pycryptodome  (pip install pycryptodome)")


# ---------------------------------------------------------------- GBF file
class GbfFile:
    def __init__(self, path, password):
        self.path = path
        self.raw = open(path, "rb").read()
        if len(self.raw) < 0x3000:
            raise ValueError("file too small to be a GBF export")
        self.key = self.iv = None
        self.plain = b""
        self.meta_xml = b""
        self.sections = []
        self.media_size = self.meta_len = 0
        self._unlock(password)
        self._parse_header()
        self._decrypt_all()

    def _unlock(self, password):
        AES = require_crypto()
        cands, seen = [], set()
        for pw in (password, password.strip(), password.rstrip("\r\n"),
                   password + "\n", password + "\r\n"):
            if pw and pw not in seen:
                seen.add(pw)
                cands.append(pw)
        for pw in cands:
            key = hashlib.sha256(pw.encode("utf-8")).digest()
            pt = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(
                self.raw[0x1010:0x1100])
            score = sum(1 for b in pt[16:240]
                        if 32 <= b < 127 or b in (9, 10, 13)) / 224
            if score > 0.7 and b"<" in pt and b">" in pt:
                self.key = key
                self.password = pw
                p0 = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(
                    self.raw[0x1000:0x1010])
                self.iv = bytes(a ^ b for a, b in zip(p0, KNOWN_PT))
                return
        raise ValueError(
            "password rejected - no AES-256/SHA-256 plaintext match")

    def _parse_header(self):
        h = self.raw[:BLOCK]
        self.n_sec = struct.unpack_from("<I", h, 0x34)[0]
        self.media_size = struct.unpack_from("<I", h, 0x38)[0]
        self.meta_len = struct.unpack_from("<I", h, 0x58)[0]
        for i in range(min(self.n_sec, 32)):
            e = h[0xA00 + i * 48: 0xA00 + (i + 1) * 48]
            sid, flag, size = struct.unpack_from("<III", e)
            name = e[12:].split(b"\x00")[0].decode("ascii", "replace")
            if name:
                self.sections.append((sid, flag, size, name))
        self.media_off = 0x2000
        end = self.media_off + self.media_size
        if not self.media_size or end > len(self.raw):
            end = len(self.raw) - (len(self.raw) & 0xF)
        self.media_end = end

    def _decrypt_all(self):
        AES = require_crypto()
        ct = self.raw[0x1000: (len(self.raw) // 16) * 16]
        self.plain = AES.new(self.key, AES.MODE_CBC, iv=self.iv).decrypt(ct)
        n = self.meta_len if self.meta_len else 0x1000
        self.meta_xml = self.plain[:n]

    # ------------------------------------------------------------ records
    def media(self):
        return self.plain[self.media_off - 0x1000: self.media_end - 0x1000]

    def iter_records(self):
        """Yield (kind, file_off, hdr, data).

        kind: 'video' | 'event' | 'unknown'
        """
        media = self.media()
        starts = [m.start() for m in re.finditer(re.escape(SIG), media)]
        starts.append(len(media))
        for i, s in enumerate(starts[:-1]):
            h = s - 0x0C
            if h < 0:
                continue
            nxt = starts[i + 1] - 0x0C
            if nxt <= s:
                nxt = starts[i + 1]
            hdr = media[h:h + 72]
            # two header variants exist: '80 07 38 04' at +0x20 (small recs)
            # or shifted to +0x21 (records starting '00 00 08 50')
            is_video = (hdr[0x14] == 0x02
                        and b"\x80\x07\x38" in hdr[0x20:0x24])
            if is_video:
                data = media[h + 72: nxt]
                ts = hdr[0x11] | (hdr[0x12] << 8) | (hdr[0x13] << 16)
                chan = struct.unpack_from("<I", hdr, 8)[0]
                yield "video", self.media_off + h, hdr, ts, chan, data
            else:
                data = media[s + 8: nxt]
                yield "event", self.media_off + s, hdr, 0, 0, data


# ------------------------------------------------------------- H.264 tools
START_RE = re.compile(rb"\x00\x00\x00\x01|\x00\x00\x01")


# NAL types a GBF video record can actually carry: slices, IDR, SEI, SPS,
# PPS, access-unit delimiters.  GBF record trailers / VCA metadata chunks
# use the same 00 00 01 framing but always begin with an invalid NAL header
# (type 0, forbidden-bit set, or reserved type) -> stop there.
VALID_NAL_TYPES = frozenset((1, 5, 6, 7, 8, 9))


def split_nals(chunk):
    """Split a record's data into H.264 NAL payloads.

    GBF record data = [video NALs][non-video VCA/metadata blocks] - both use
    annex-B style 00 00 00 01 / 00 00 01 delimiters.  We keep NALs while the
    NAL header is a valid video type and stop at the first invalid chunk
    (forbidden-zero-bit set, type 0, or reserved type 13-31).
    """
    nals, n = [], len(chunk)
    marks = [m.start() for m in START_RE.finditer(chunk)]
    for k, s in enumerate(marks):
        e = marks[k + 1] if k + 1 < len(marks) else n
        sc = 4 if chunk[s:s + 4] == b"\x00\x00\x00\x01" else 3
        nal = chunk[s + sc: e].rstrip(b"\x00")
        if not nal:
            continue
        h = nal[0]
        if (h & 0x80) or (h & 0x1F) not in VALID_NAL_TYPES:
            break
        nals.append(nal)
    return nals


def sps_dimensions(sps):
    """Minimal SPS parse -> (width, height) or None."""
    try:
        rbsp = bytearray()
        i = 0
        while i < len(sps):
            if i + 2 < len(sps) and sps[i:i + 3] == b"\x00\x00\x03":
                rbsp += sps[i:i + 2]
                i += 3
            else:
                rbsp.append(sps[i])
                i += 1

        class BR:
            def __init__(s, d):
                s.d, s.p = d, 0

            def u(s, n):
                v = 0
                for _ in range(n):
                    byte = s.d[s.p >> 3] if (s.p >> 3) < len(s.d) else 0
                    v = (v << 1) | ((byte >> (7 - (s.p & 7))) & 1)
                    s.p += 1
                return v

            def ue(s):
                z = 0
                while s.u(1) == 0:
                    z += 1
                    if z > 31 or (s.p >> 3) >= len(s.d):
                        raise ValueError("ue overflow")
                return (1 << z) - 1 + s.u(z)

            def se(s):
                k = s.ue()
                return (k + 1) // 2 if k & 1 else -(k // 2)

        r = BR(bytes(rbsp[2:]))
        prof = rbsp[1]
        r.u(8); r.u(8); r.ue()           # constraints+level, sps_id
        if prof in (100, 110, 122, 244, 44, 83, 86, 118, 128,
                    138, 139, 134, 135):
            chroma = r.ue()              # chroma_format_idc
            if chroma == 3:
                r.u(1)                   # separate_colour_plane_flag
            r.ue(); r.ue(); r.u(1)
            if r.u(1):                   # seq_scaling_matrix_present
                n_lists = 12 if chroma == 3 else 8
                for i in range(n_lists):
                    if r.u(1):
                        last = nxt = 8
                        for _ in range(16 if i < 6 else 64):
                            if nxt:
                                nxt = (last + r.se() + 256) % 256
                            last = nxt or last
        r.ue()                           # log2_max_frame_num_minus4
        poc = r.ue()                     # pic_order_cnt_type
        if poc == 0:
            r.ue()
        elif poc == 1:
            r.u(1); r.se(); r.se()
            for _ in range(r.ue()):
                r.se()
        r.ue()                           # max_num_ref_frames
        r.u(1)                           # gaps_in_frame_num
        w = (r.ue() + 1) * 16            # pic_width_in_mbs_minus1
        h = (r.ue() + 1) * 16            # pic_height_in_map_units_minus1
        if r.u(1) == 0:                  # frame_mbs_only_flag
            r.u(1)                       # mb_adaptive_frame_field_flag
        r.u(1)                           # direct_8x8_inference_flag
        if r.u(1):                       # frame_cropping_flag
            cl, cr, ct, cb = r.ue(), r.ue(), r.ue(), r.ue()
            w -= (cl + cr) * 2
            h -= (ct + cb) * 2
        return w, h
    except Exception:
        return None


# -------------------------------------------------------- pure-python MP4
def _box(typ, payload):
    return struct.pack(">I", 8 + len(payload)) + typ + payload


def _fbox(typ, ver, flags, payload):
    return _box(typ, bytes([ver]) + flags.to_bytes(3, "big") + payload)


def mux_mp4(samples, sps, pps, path, durations=None, fps=25.0):
    """samples: list of access units, each = concatenated length-prefixed NALs.
    durations: optional per-sample durations in 90kHz units (real timing)."""
    w, h = sps_dimensions(sps) or (1920, 1080)
    timescale = 90000
    n = len(samples)
    if durations is None:
        durations = [max(1, int(round(timescale / fps)))] * n
    durations = [max(1, d) for d in durations]

    avcc = (b"\x01" + sps[1:4] + b"\xff" + b"\xe1"
            + struct.pack(">H", len(sps)) + sps
            + b"\x01" + struct.pack(">H", len(pps)) + pps)
    if sps[1] in (100, 110, 122, 244, 44, 83, 86, 118, 128):
        # high profiles: chroma_format, bit_depth_luma-8, bit_depth_chroma-8,
        # numSpsExt (parse real values would need full SPS decode; 4:2:0/8-bit)
        avcc += b"\x01\x00\x00\x00"
    avc1 = (b"\x00" * 6 + struct.pack(">H", 1) + b"\x00" * 16
            + struct.pack(">HH", w, h)
            + struct.pack(">II", 0x00480000, 0x00480000)
            + b"\x00" * 4 + struct.pack(">H", 1) + b"\x00" * 32
            + b"\x00\x18\xff\xff" + _box(b"avcC", avcc))
    stsd = _fbox(b"stsd", 0, 0, struct.pack(">I", 1) + _box(b"avc1", avc1))
    # stts: run-length encode (sample_count, delta)
    runs = []
    for d in durations:
        if runs and runs[-1][1] == d:
            runs[-1][0] += 1
        else:
            runs.append([1, d])
    stts = _fbox(b"stts", 0, 0, struct.pack(">I", len(runs))
                 + b"".join(struct.pack(">II", c, d) for c, d in runs))
    total_dur = sum(durations)
    key_idx = [i + 1 for i, s in enumerate(samples)
               if s[4:5] and (s[4] & 0x1F) in (5, 7)]
    stss = _fbox(b"stss", 0, 0, struct.pack(">I", len(key_idx))
                 + b"".join(struct.pack(">I", i) for i in key_idx))
    stsc = _fbox(b"stsc", 0, 0, struct.pack(">I", 1)
                 + struct.pack(">III", 1, n, 1))
    stsz = _fbox(b"stsz", 0, 0, struct.pack(">II", 0, n)
                 + b"".join(struct.pack(">I", len(s)) for s in samples))
    stco0 = _fbox(b"stco", 0, 0, struct.pack(">II", 1, 0))

    def moov(stco):
        stbl = _box(b"stbl", stsd + stts + stss + stsc + stsz + stco)
        dinf = _box(b"dinf", _fbox(b"dref", 0, 0, struct.pack(">I", 1)
                                   + _fbox(b"url ", 0, 1, b"")))
        minf = _box(b"minf",
                    _fbox(b"vmhd", 0, 1, struct.pack(">HHHH", 0, 0, 0, 0))
                    + dinf + stbl)
        mdhd = _fbox(b"mdhd", 0, 0,
                     struct.pack(">IIIIHH", 0, 0, timescale, total_dur,
                                 0x55C4, 0))
        hdlr = _fbox(b"hdlr", 0, 0, b"\x00" * 4 + b"vide" + b"\x00" * 12
                     + b"GBF Video\x00")
        tkhd = _fbox(b"tkhd", 0, 7,
                     struct.pack(">IIIII", 0, 0, 1, 0, total_dur)
                     + b"\x00" * 8 + struct.pack(">HHHH", 0, 0, 0, 0)
                     + struct.pack(">IIIIIIIII", 0x10000, 0, 0, 0,
                                   0x10000, 0, 0, 0, 0x40000000)
                     + struct.pack(">II", w << 16, h << 16))
        mvhd = _fbox(b"mvhd", 0, 0,
                     struct.pack(">IIII", 0, 0, 1000,
                                 int(total_dur / 90))
                     + struct.pack(">I", 0x10000) + struct.pack(">H", 0x0100)
                     + b"\x00" * 10
                     + struct.pack(">IIIIIIIII", 0x10000, 0, 0, 0,
                                   0x10000, 0, 0, 0, 0x40000000)
                     + b"\x00" * 24 + struct.pack(">I", 2))
        return _box(b"moov", mvhd + _box(b"trak", tkhd + _box(b"mdia",
                                                             mdhd + hdlr + minf)))

    ftyp = _box(b"ftyp", b"isom" + struct.pack(">I", 0x200) + b"isomavc1mp41")
    mdat_payload = b"".join(samples)
    mdat_len = len(mdat_payload) + 8
    if mdat_len < 0xFFFFFFFF:
        mdat_head = struct.pack(">I", mdat_len) + b"mdat"
    else:
        mdat_head = struct.pack(">II", 1, mdat_len + 8) + b"mdat"
        mdat_head = struct.pack(">I", 1) + b"mdat" + struct.pack(">Q", mdat_len + 8)
    moov0 = moov(stco0)
    mdat_off = len(ftyp) + len(moov0) + len(mdat_head)
    real_moov = moov(_fbox(b"stco", 0, 0, struct.pack(">II", 1, mdat_off)))
    with open(path, "wb") as f:
        f.write(ftyp)
        f.write(real_moov)
        f.write(mdat_head)
        f.write(mdat_payload)


# ------------------------------------------------------------- event blobs
def parse_event_blob(data):
    """Return list of printable strings decoded from UTF-16LE event blob."""
    out = []
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){3,}", data):
        try:
            s = m.group(0).decode("utf-16-le").strip("\x00")
            if s:
                out.append(s)
        except Exception:
            pass
    return out


# --------------------------------------------------------------- report
def _lat(s):
    """fpdf2 core fonts are latin-1 only."""
    return str(s).encode("latin-1", "replace").decode("latin-1")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_still(annex_b, target_idx):
    """Decode the frame at `target_idx` from a raw Annex-B H.264 buffer and
    return it as PNG bytes (via PyAV + Pillow).  None on failure."""
    import io
    try:
        import av
    except ImportError:
        return None
    try:
        cont = av.open(io.BytesIO(annex_b), format="h264")
        idx = -1
        for packet in cont.demux():
            for frame in packet.decode():
                idx += 1
                if idx >= target_idx:
                    buf = io.BytesIO()
                    frame.to_image().save(buf, format="PNG")
                    cont.close()
                    return buf.getvalue()
        cont.close()
    except Exception:
        pass
    return None


def write_report(outdir, gbf, stream_info, events):
    """DIN-A4 PDF report: source-file facts (incl. SHA-256 evidence hash),
    ExportInfo metadata, one still image + stats per camera stream, event
    log excerpt and the raw XML — suitable for print/archival."""
    import datetime
    import io
    import textwrap
    from fpdf import FPDF

    base = os.path.splitext(os.path.basename(gbf.path))[0]
    rpath = os.path.join(outdir, base + "_report.pdf")

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(True, margin=15)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()

    def hline(title):
        pdf.set_font("helvetica", "B", 12)
        pdf.set_fill_color(230, 235, 245)
        pdf.cell(0, 8, _lat("  " + title), new_x="LMARGIN", new_y="NEXT",
                 fill=True)
        pdf.ln(1)

    def kv(k, v):
        pdf.set_font("helvetica", "B", 9)
        pdf.cell(45, 5, _lat(k), new_x="RIGHT", new_y="TOP")
        pdf.set_font("helvetica", "", 9)
        pdf.multi_cell(0, 5, _lat(v), new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("helvetica", "B", 17)
    pdf.cell(0, 11, "GBF-Extract - Export-Dokumentation",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 9)
    pdf.cell(0, 5, _lat(f"Erstellt: {datetime.datetime.now():%Y-%m-%d %H:%M}  |"
                      f"  GBF-Extract v{__version__}"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    hline("Quelldatei")
    kv("Dateiname", os.path.basename(gbf.path))
    kv("Groesse", f"{os.path.getsize(gbf.path):,} Bytes")
    kv("SHA-256", sha256_file(gbf.path))
    pdf.ln(2)

    meta_txt = gbf.meta_xml.decode("utf-8", "replace")
    hline("Export-Metadaten (ExportInfo.xml)")
    try:
        root = ET.fromstring(meta_txt)
        for ch in root:
            if ch.tag == "MC":
                kv("MediaChannel",
                   " | ".join(f"{g.tag}={g.text}" for g in ch if g.text))
            elif ch.text:
                kv(ch.tag, ch.text.strip())
    except Exception:
        pdf.set_font("helvetica", "", 9)
        pdf.multi_cell(0, 5, "(XML-Parsing fehlgeschlagen)",
                       new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    hline(f"Extrahierte Videostreams ({len(stream_info)})")
    for name, st in stream_info.items():
        # keep a camera block together: ~45mm of stats + ~102mm still
        # (180mm wide 16:9) must fit on the rest of the page
        if pdf.get_y() + 150 > 282:
            pdf.add_page()
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(0, 6, _lat(name), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 9)
        for k, v in st["stats"]:
            kv(k, v)
        pdf.ln(1)
        png = extract_still(st["annex"], max(0, st["n_samples"] // 2))
        if png:
            pdf.image(io.BytesIO(png), x=15, w=180)
            pdf.ln(2)
        else:
            pdf.set_font("helvetica", "I", 9)
            pdf.cell(0, 5, "(Standbild nicht dekodierbar)",
                     new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    if events:
        hline(f"Event-Daten ({len(events)} Records)")
        pdf.set_font("courier", "", 7)
        lines = []
        for off, ev in events:
            lines.append(f"=== event @0x{off:x} ===")
            lines += ev
        for ln in lines[:200]:
            pdf.multi_cell(0, 3.6, _lat(ln), new_x="LMARGIN", new_y="NEXT")
        if len(lines) > 200:
            pdf.multi_cell(0, 3.6, f"... ({len(lines) - 200} weitere Zeilen)",
                           new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    hline("ExportInfo.xml - Rohdaten")
    pdf.set_font("courier", "", 7)
    pretty = meta_txt.replace("><", ">\n<")
    for ln in pretty.splitlines():
        for chunk in textwrap.wrap(ln, 110, break_long_words=True,
                                   break_on_hyphens=False) or [""]:
            pdf.multi_cell(0, 3.6, _lat(chunk), new_x="LMARGIN",
                           new_y="NEXT")
    pdf.output(rpath)
    return rpath


# ------------------------------------------------------------- extraction
def extract(gbf, outdir, write_mp4=True, write_raw=True, fps=25.0,
            report=True):
    os.makedirs(outdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(gbf.path))[0]
    made = []

    meta_path = os.path.join(outdir, base + "_ExportInfo.xml")
    with open(meta_path, "wb") as f:
        f.write(gbf.meta_xml)
    made.append(meta_path)
    try:
        root = ET.fromstring(gbf.meta_xml.decode("utf-8", "replace"))
        for ch in root:
            if ch.text:
                print(f"    {ch.tag}: {ch.text}")
    except Exception:
        pass

    vrecs = []        # (ts, seq, chan, nals) per video record
    events = []
    n_video = 0

    for seq, (kind, off, hdr, ts, chan, data) in enumerate(gbf.iter_records()):
        if kind == "video":
            nals = split_nals(data)
            if not nals:
                continue
            n_video += 1
            vrecs.append((ts, seq, chan, nals))
        elif kind == "event":
            ev = parse_event_blob(data)
            if ev:
                events.append((off, ev))

    if events:
        ep = os.path.join(outdir, base + "_events.txt")
        with open(ep, "w", encoding="utf-8") as f:
            for off, ev in events:
                f.write(f"=== event @0x{off:x} ===\n")
                for s in ev:
                    f.write(s + "\n")
                f.write("\n")
        made.append(ep)
        print(f"    {len(events)} event records -> {ep}")

    # presentation order = timestamp order (records are stored shuffled in
    # ~2-3-record chunks by the exporter; u24 field = ms timestamp)
    vrecs.sort(key=lambda r: (r[0], r[1]))

    # multi-camera split: the u32 at header+0x08 is a per-channel monotonic
    # sequence counter.  Records of K interleaved cameras produce K monotonic
    # subsequences -> greedy best-fit split (largest last_u < u wins).
    # With a single camera this degenerates to exactly one stream.
    seqs = []   # list of dicts {last_u, recs:[(ts,nals,u)]}
    for ts, seq, u, nals in vrecs:
        best = -1
        best_u = -1
        for i, s in enumerate(seqs):
            if s["last_u"] < u and s["last_u"] > best_u:
                best, best_u = i, s["last_u"]
        if best < 0:
            best = len(seqs)
            seqs.append({"last_u": u, "recs": []})
        seqs[best]["last_u"] = u
        seqs[best]["recs"].append((ts, nals, u))

    # merge tiny orphan streams (counter blips/reordered writes) into the
    # closest big stream - a real camera produces many records
    big = [s for s in seqs if len(s["recs"]) >= 64]
    if not big:
        big = seqs[:1]
    for s in seqs:
        if s in big or len(s["recs"]) >= 64:
            continue
        for ts, nals, u in s["recs"]:
            tgt = min(big, key=lambda b: abs(b["last_u"] - u))
            tgt["last_u"] = max(tgt["last_u"], u)
            i = 0
            while i < len(tgt["recs"]) and tgt["recs"][i][0] < ts:
                i += 1
            tgt["recs"].insert(i, (ts, nals, u))
    seqs = big

    streams = {}
    for i, s in enumerate(seqs):
        st = {"sps": None, "pps": None, "nals": [], "rec": len(s["recs"]),
              "ts": []}
        for ts, nals, u in s["recs"]:
            has_au = False
            for nal in nals:
                t = nal[0] & 0x1F
                if t == 7:
                    st["sps"] = nal
                elif t == 8:
                    st["pps"] = nal
                else:
                    has_au = True
                st["nals"].append(nal)
            if has_au:
                st["ts"].append(ts)
        streams[f"cam{i}"] = st

    print(f"    {n_video} video records, {len(streams)} stream(s)")
    stream_info = {}
    for key, st in streams.items():
        annex = b"".join(b"\x00\x00\x00\x01" + n for n in st["nals"])
        info = {"annex": annex, "n_samples": len(st["ts"]), "stats": []}
        stream_info[key] = info
        dims = sps_dimensions(st["sps"]) if st["sps"] else None
        span_ms = (st["ts"][-1] - st["ts"][0]) if len(st["ts"]) > 1 else 0
        info["stats"] += [
            ("Samples", len(st["ts"])),
            ("NAL-Einheiten", len(st["nals"])),
            ("Aufloesung", f"{dims[0]} x {dims[1]}" if dims else "unbekannt"),
            ("Dauer (ca.)", f"{span_ms / 1000:.1f} s"),
        ]
        if write_raw:
            rp = os.path.join(outdir, f"{base}_{key}.264")
            with open(rp, "wb") as f:
                f.write(annex)
            made.append(rp)
            info["stats"].append(("Datei (roh)", os.path.basename(rp)))
            print(f"    raw H.264 [{key}] -> {rp} ({len(st['nals'])} NALs)")
        if write_mp4 and st["sps"] and st["pps"]:
            samples = []
            for nal in st["nals"]:
                t = nal[0] & 0x1F
                if t in (7, 8):
                    continue
                lp = struct.pack(">I", len(nal)) + nal
                if t == 5:
                    lp = (struct.pack(">I", len(st["sps"])) + st["sps"]
                          + struct.pack(">I", len(st["pps"])) + st["pps"]
                          + lp)
                samples.append(lp)
            if samples:
                # real per-sample timing: one access unit per record; ts
                # list holds one ms timestamp per AU-producing record
                ts_units = st["ts"]
                durs = []
                for i in range(len(samples)):
                    if i + 1 < len(ts_units):
                        d = (ts_units[i + 1] - ts_units[i]) * 90
                    elif durs:
                        d = durs[-1]
                    else:
                        d = 3600
                    durs.append(max(1, d))
                if len(durs) != len(samples):
                    durs = None
                mp = os.path.join(outdir, f"{base}_{key}.mp4")
                mux_mp4(samples, st["sps"], st["pps"], mp,
                        durations=durs, fps=fps)
                made.append(mp)
                dur_s = sum(durs) / 90000 if durs else len(samples) / fps
                info["stats"].append(("Datei (MP4)", os.path.basename(mp)))
                info["stats"][2] = ("Aufloesung",
                                    f"{dims[0]} x {dims[1]}"
                                    if dims else "unbekannt")
                info["stats"][3] = ("Dauer (ca.)", f"{dur_s:.1f} s")
                info["n_samples"] = len(samples)
                print(f"    MP4 [{key}] -> {mp} ({len(samples)} frames, "
                      f"{dims or '?'}, ~{dur_s:.0f}s)")
        elif write_mp4:
            print(f"    [!] {key}: no SPS/PPS -> MP4 skipped")
    if report:
        try:
            rp = write_report(outdir, gbf, stream_info, events)
            made.append(rp)
            print(f"    PDF-Report -> {rp}")
        except Exception as e:
            print(f"    [!] PDF-Report fehlgeschlagen: {e}")
    return made


# ------------------------------------------------------------------- GUI
def run_gui():
    """Tkinter GUI: .gbf per Drag&Drop oder Dateidialog waehlen, Passwort
    eingeben, extrahieren.  Laueft ohne installierte Zusatzsoftware; echter
    Explorer-Drag&Drop braucht tkinterdnd2 (im PyInstaller-Bundle enthalten).
    """
    import queue
    import threading
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD
        root = TkinterDnD.Tk()
        has_dnd = True
    except Exception:
        root = tk.Tk()
        has_dnd = False

    root.title(f"GBF-Extract v{__version__}")
    root.geometry("640x560")
    root.minsize(560, 480)

    q = queue.Queue()
    state = {"file": tk.StringVar(), "pw": tk.StringVar(),
             "out": tk.StringVar(value="."),
             "mp4": tk.BooleanVar(value=True),
             "raw": tk.BooleanVar(value=True),
             "pdf": tk.BooleanVar(value=True),
             "busy": False}

    def log(msg):
        txt.configure(state="normal")
        txt.insert("end", msg + "\n")
        txt.see("end")
        txt.configure(state="disabled")

    def poll():
        try:
            while True:
                m = q.get_nowait()
                if m == "\x00done\x00":
                    state["busy"] = False
                    btn.config(state="normal")
                else:
                    log(m)
        except queue.Empty:
            pass
        root.after(80, poll)

    def set_file(path):
        if path and path.lower().endswith(".gbf"):
            state["file"].set(path)
            drop_lbl.config(text=path.split("/")[-1].split("\\")[-1])
            # export folder is always named like the .gbf (created inside
            # the chosen target dir); default target = beside the .gbf
            state["out"].set(os.path.dirname(os.path.abspath(path)))
        elif path:
            messagebox.showerror("GBF-Extract",
                                 "Bitte eine .gbf-Datei waehlen.")

    def on_drop(ev):
        for p in root.tk.splitlist(ev.data):
            if p.lower().endswith(".gbf"):
                set_file(p)
                return
        set_file(p)  # letzter Pfad -> Fehlermeldung falls nicht .gbf

    def browse():
        p = filedialog.askopenfilename(
            title="GBF-Datei waehlen",
            filetypes=[("Geutebrueck Backup", "*.gbf"), ("Alle Dateien", "*.*")])
        if p:
            set_file(p)

    def browse_out():
        p = filedialog.askdirectory(title="Ausgabeordner waehlen")
        if p:
            state["out"].set(p)

    def worker(gbf, pw, out):
        import io
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            stem = os.path.splitext(os.path.basename(gbf))[0]
            final = os.path.join(out, stem)
            g = GbfFile(gbf, pw)
            extract(g, final, write_mp4=state["mp4"].get(),
                    write_raw=state["raw"].get(),
                    report=state["pdf"].get())
        except Exception as e:
            print("[!] " + str(e))
        finally:
            sys.stdout = old
        for line in buf.getvalue().splitlines():
            q.put(line)
        q.put("\x00done\x00")

    def start():
        gbf, pw, out = state["file"].get(), state["pw"].get(), state["out"].get()
        if not gbf:
            messagebox.showerror("GBF-Extract", "Keine .gbf-Datei gewaehlt.")
            return
        if not pw:
            messagebox.showerror("GBF-Extract", "Kein Passwort eingegeben.")
            return
        if not out:
            messagebox.showerror("GBF-Extract", "Kein Ausgabeordner.")
            return
        if state["busy"]:
            return
        state["busy"] = True
        btn.config(state="disabled")
        log(f"[>] {gbf}")
        threading.Thread(target=worker, args=(gbf, pw, out),
                         daemon=True).start()

    pad = {"padx": 10, "pady": 6}
    drop = tk.Frame(root, bd=2, relief="ridge", bg="#1e1e2e")
    drop.pack(fill="x", **pad)
    drop_lbl = tk.Label(
        drop, text=".gbf-Datei hierher ziehen" if has_dnd
        else ".gbf-Datei auswaehlen (kein Drag&Drop)",
        bg="#1e1e2e", fg="#cdd6f4", font=("Segoe UI", 11), pady=28)
    drop_lbl.pack(fill="both", expand=True)
    if has_dnd:
        for w in (drop, drop_lbl):
            w.drop_target_register(DND_FILES)
            w.dnd_bind("<<Drop>>", on_drop)
    drop_lbl.bind("<Button-1>", lambda e: browse())

    frm = tk.Frame(root)
    frm.pack(fill="x", **pad)
    tk.Button(frm, text="Datei waehlen...", command=browse).grid(
        row=0, column=0, sticky="w")
    tk.Label(frm, text="Passwort:").grid(row=1, column=0, sticky="w",
                                        pady=(10, 0))
    pw_ent = tk.Entry(frm, textvariable=state["pw"], show="*", width=36)
    pw_ent.grid(row=1, column=1, sticky="w", pady=(10, 0))
    show = tk.BooleanVar(value=False)

    def toggle_pw():
        pw_ent.config(show="" if show.get() else "*")

    tk.Checkbutton(frm, text="anzeigen", variable=show,
                   command=toggle_pw).grid(row=1, column=2, sticky="w",
                                           pady=(10, 0))
    tk.Label(frm, text="Ausgabe:").grid(row=2, column=0, sticky="w",
                                        pady=(6, 0))
    tk.Entry(frm, textvariable=state["out"], width=36).grid(
        row=2, column=1, sticky="w", pady=(6, 0))
    tk.Button(frm, text="...", command=browse_out, width=3).grid(
        row=2, column=2, sticky="w", pady=(6, 0))
    tk.Label(frm, text="Unterordner = Dateiname der .gbf",
             fg="#888888").grid(row=3, column=1, sticky="w")

    opt = tk.Frame(root)
    opt.pack(fill="x", **pad)
    tk.Checkbutton(opt, text="MP4 erzeugen", variable=state["mp4"]).pack(
        side="left")
    tk.Checkbutton(opt, text="Raw .264 erzeugen",
                   variable=state["raw"]).pack(side="left", padx=16)
    tk.Checkbutton(opt, text="PDF-Bericht (DIN A4)",
                   variable=state["pdf"]).pack(side="left")

    btn = tk.Button(root, text="Extrahieren", command=start,
                    font=("Segoe UI", 11, "bold"), bg="#89b4fa",
                    activebackground="#74c7ec", pady=4)
    btn.pack(fill="x", padx=10, pady=4)

    txt = tk.Text(root, state="disabled", bg="#11111b", fg="#a6e3a1",
                  font=("Consolas", 9), height=12)
    txt.pack(fill="both", expand=True, padx=10, pady=8)

    root.after(80, poll)
    root.mainloop()


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="gbf_extract",
        description="Decrypt + extract Geutebrueck G-Core .gbf backups "
                    "(v" + __version__ + ")")
    ap.add_argument("gbf", nargs="?", help="input .gbf file")
    ap.add_argument("-p", "--password", help="export password")
    ap.add_argument("--password-file", help="file containing the password")
    ap.add_argument("-o", "--outdir", default=None,
                    help="target dir; the export folder inside it is always "
                         "named like the .gbf file (default: dir of the .gbf)")
    ap.add_argument("--no-mp4", action="store_true")
    ap.add_argument("--no-raw", action="store_true")
    ap.add_argument("--no-report", action="store_true",
                    help="skip the DIN-A4 PDF report")
    ap.add_argument("--fps", type=float, default=25.0,
                    help="frame rate used for MP4 timing (default 25)")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)

    if not a.gbf:
        run_gui()
        return

    pw = a.password
    if not pw and a.password_file:
        pw = open(a.password_file, encoding="utf-8",
                  errors="ignore").read().strip()
    if not pw:
        pw = getpass.getpass("GBF password: ")

    try:
        g = GbfFile(a.gbf, pw)
    except (ValueError, OSError) as e:
        sys.exit(f"[!] {e}")
    print(f"[+] {a.gbf} decrypted")
    print(f"[+] sections: {', '.join(s[3] for s in g.sections)}")
    parent = a.outdir or os.path.dirname(os.path.abspath(a.gbf))
    stem = os.path.splitext(os.path.basename(a.gbf))[0]
    outdir = os.path.join(parent, stem)
    extract(g, outdir, write_mp4=not a.no_mp4,
            write_raw=not a.no_raw, fps=a.fps, report=not a.no_report)
    print("[+] done ->", os.path.abspath(outdir))


if __name__ == "__main__":
    main()
