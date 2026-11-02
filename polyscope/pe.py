"""Minimal PE header/section reader (stdlib struct only)."""
from __future__ import annotations

import struct


def _u(data: bytes, off: int, fmt: str):
    if off < 0 or off + struct.calcsize(fmt) > len(data):
        return None
    return struct.unpack_from("<" + fmt, data, off)[0]


def parse(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"ok": False, "err": "not pe"}
    pe = _u(data, 0x3C, "I")
    if pe is None or pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        return {"ok": False, "err": "no pe signature"}
    machine = _u(data, pe + 4, "H")
    nsect = _u(data, pe + 6, "H") or 0
    opt_size = _u(data, pe + 20, "H") or 0
    opt_magic = _u(data, pe + 24, "H")
    table = pe + 24 + opt_size
    sections = []
    for i in range(min(nsect, 96)):
        base = table + i * 40
        if base + 40 > len(data):
            break
        raw = data[base:base + 8].split(b"\0", 1)[0]
        sections.append({
            "name": raw.decode("latin-1", "replace"),
            "vsize": _u(data, base + 8, "I"),
            "vaddr": _u(data, base + 12, "I"),
            "raw_size": _u(data, base + 16, "I"),
            "raw_ptr": _u(data, base + 20, "I"),
        })
    return {
        "ok": True,
        "bits": 64 if opt_magic == 0x20B else 32,
        "machine": machine,
        "sections": sections,
    }
