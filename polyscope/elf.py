"""Minimal ELF header/section/dynamic reader (stdlib struct only)."""
from __future__ import annotations

import struct


def _u(data: bytes, off: int, fmt: str, endian: str):
    if off < 0 or off + struct.calcsize(fmt) > len(data):
        return None
    return struct.unpack_from(endian + fmt, data, off)[0]


def _cstr(data: bytes, off: int) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\0", off)
    return data[off:end if end >= 0 else len(data)].decode("latin-1", "replace")


def parse(data: bytes) -> dict:
    if len(data) < 52 or not data.startswith(b"\x7fELF"):
        return {"ok": False, "err": "not elf"}
    bits = data[4]
    endian = "<" if data[5] == 1 else ">"
    if bits == 2:
        shoff = _u(data, 0x28, "Q", endian)
        shentsize = _u(data, 0x3A, "H", endian)
        shnum = _u(data, 0x3C, "H", endian)
        shstrndx = _u(data, 0x3E, "H", endian)
        name_fmt = "I"
        sh_fmt_off, sh_fmt_size = 0x18, 0x20
    elif bits == 1:
        shoff = _u(data, 0x20, "I", endian)
        shentsize = _u(data, 0x2E, "H", endian)
        shnum = _u(data, 0x30, "H", endian)
        shstrndx = _u(data, 0x32, "H", endian)
        name_fmt = "I"
        sh_fmt_off, sh_fmt_size = 0x10, 0x14
    else:
        return {"ok": False, "err": "bad elf class"}

    sections: list[dict] = []
    strtab = b""
    if shoff and shentsize and shnum and shoff + shentsize * shnum <= len(data):
        if shstrndx is not None and shstrndx < shnum:
            base = shoff + shstrndx * shentsize
            s_off = _u(data, base + sh_fmt_off, "Q" if bits == 2 else "I", endian)
            s_size = _u(data, base + sh_fmt_size, "Q" if bits == 2 else "I", endian)
            if s_off is not None and s_size is not None and s_off + s_size <= len(data):
                strtab = data[s_off:s_off + s_size]
        for i in range(shnum):
            base = shoff + i * shentsize
            name_off = _u(data, base, name_fmt, endian)
            stype = _u(data, base + 4, "I", endian)
            soff = _u(data, base + sh_fmt_off, "Q" if bits == 2 else "I", endian)
            ssize = _u(data, base + sh_fmt_size, "Q" if bits == 2 else "I", endian)
            name = ""
            if strtab and name_off is not None and name_off < len(strtab):
                end = strtab.find(b"\0", name_off)
                name = strtab[name_off:end if end >= 0 else len(strtab)].decode("latin-1", "replace")
            sections.append({"name": name, "type": stype, "offset": soff, "size": ssize})

    # PT_DYNAMIC / .dynamic NEEDED entries (library provenance).
    needed: list[str] = []
    by_name = {s["name"]: s for s in sections}
    dyn = by_name.get(".dynamic")
    dynstr = by_name.get(".dynstr")
    if dyn and dynstr and dyn.get("offset") is not None and dynstr.get("offset") is not None:
        off = dyn["offset"]
        end = min(len(data), off + (dyn.get("size") or 0))
        step = 16 if bits == 2 else 8
        tag_fmt = "q" if bits == 2 else "i"
        val_fmt = "Q" if bits == 2 else "I"
        while off + step <= end:
            tag = _u(data, off, tag_fmt, endian)
            val = _u(data, off + (8 if bits == 2 else 4), val_fmt, endian)
            if tag is None:
                break
            if tag == 0:  # DT_NULL
                break
            if tag == 1 and val is not None:  # DT_NEEDED
                s = _cstr(data, (dynstr.get("offset") or 0) + val)
                if s and s not in needed:
                    needed.append(s)
            off += step

    return {
        "ok": True,
        "bits": 64 if bits == 2 else 32,
        "endian": "little" if endian == "<" else "big",
        "entry": _u(data, 0x18, "Q" if bits == 2 else "I", endian),
        "sections": sections,
        "go_buildid": any("go.buildid" in s["name"] for s in sections),
        "needed": needed,
    }


def parse_path(path, max_sections: int = 4096) -> dict:
    """Parse an ELF from disk without loading the whole file (section table can be at EOF)."""
    import os
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            hdr = f.read(64)
            if len(hdr) < 52 or not hdr.startswith(b"\x7fELF"):
                return {"ok": False, "err": "not elf"}
            bits = hdr[4]
            endian = "<" if hdr[5] == 1 else ">"
            if bits == 2:
                shoff = _u(hdr, 0x28, "Q", endian)
                shentsize = _u(hdr, 0x3A, "H", endian)
                shnum = _u(hdr, 0x3C, "H", endian)
                shstrndx = _u(hdr, 0x3E, "H", endian)
                sh_fmt_off, sh_fmt_size = 0x18, 0x20
                off_fmt, size_fmt = "Q", "Q"
            elif bits == 1:
                shoff = _u(hdr, 0x20, "I", endian)
                shentsize = _u(hdr, 0x2E, "H", endian)
                shnum = _u(hdr, 0x30, "H", endian)
                shstrndx = _u(hdr, 0x32, "H", endian)
                sh_fmt_off, sh_fmt_size = 0x10, 0x14
                off_fmt, size_fmt = "I", "I"
            else:
                return {"ok": False, "err": "bad elf class"}
            if shoff is None or shentsize is None or shnum is None:
                return {"ok": False, "err": "no section table"}
            shnum = min(shnum, max_sections)
            table_size = shentsize * shnum
            if table_size > 64 * 1024 * 1024 or shoff + table_size > size:
                return {"ok": False, "err": "section table out of range"}
            f.seek(shoff)
            shb = f.read(table_size)
            if len(shb) < table_size:
                return {"ok": False, "err": "short section table"}

            def sh_u(idx: int, rel: int, fmt: str):
                return _u(shb, idx * shentsize + rel, fmt, endian)

            strtab = b""
            if shstrndx is not None and shstrndx < shnum:
                so = sh_u(shstrndx, sh_fmt_off, off_fmt)
                ss = sh_u(shstrndx, sh_fmt_size, size_fmt)
                if so is not None and ss is not None and ss <= 64 * 1024 * 1024 and so + ss <= size:
                    f.seek(so)
                    strtab = f.read(ss)
            sections = []
            for i in range(shnum):
                name_off = sh_u(i, 0, "I")
                stype = sh_u(i, 4, "I")
                soff = sh_u(i, sh_fmt_off, off_fmt)
                ssize = sh_u(i, sh_fmt_size, size_fmt)
                name = ""
                if strtab and name_off is not None and name_off < len(strtab):
                    end = strtab.find(b"\0", name_off)
                    name = strtab[name_off:end if end >= 0 else len(strtab)].decode("latin-1", "replace")
                sections.append({"name": name, "type": stype, "offset": soff, "size": ssize})
            needed = []
            by_name = {x["name"]: x for x in sections}
            dyn, dynstr = by_name.get(".dynamic"), by_name.get(".dynstr")
            if dyn and dynstr and dyn.get("offset") is not None and dynstr.get("offset") is not None:
                dsize = min(dyn.get("size") or 0, 4 * 1024 * 1024)
                f.seek(dyn["offset"])
                db = f.read(dsize)
                dss = min(dynstr.get("size") or 0, 64 * 1024 * 1024)
                f.seek(dynstr["offset"])
                ds = f.read(dss)
                step = 16 if bits == 2 else 8
                tag_fmt = "q" if bits == 2 else "i"
                val_off = 8 if bits == 2 else 4
                off = 0
                while off + step <= len(db):
                    tag = _u(db, off, tag_fmt, endian)
                    val = _u(db, off + val_off, "Q" if bits == 2 else "I", endian)
                    if tag is None or tag == 0:
                        break
                    if tag == 1 and val is not None and val < len(ds):
                        end = ds.find(b"\0", val)
                        nm = ds[val:end if end >= 0 else len(ds)].decode("latin-1", "replace")
                        if nm and nm not in needed:
                            needed.append(nm)
                    off += step
            return {"ok": True, "bits": 64 if bits == 2 else 32,
                    "endian": "little" if endian == "<" else "big",
                    "entry": _u(hdr, 0x18, "Q" if bits == 2 else "I", endian),
                    "sections": sections,
                    "go_buildid": any("go.buildid" in x["name"] for x in sections),
                    "needed": needed}
    except OSError as exc:
        return {"ok": False, "err": str(exc)}
