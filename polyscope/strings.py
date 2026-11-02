"""Extract printable ASCII and UTF-16LE strings (bounded)."""
from __future__ import annotations

import re

_ASCII = re.compile(rb"[\x20-\x7e\t]{4,}")


def extract(data: bytes, limit: int = 20000, min_len: int = 4) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in _ASCII.finditer(data):
        s = m.group().decode("latin-1", "replace")
        if len(s) >= min_len and s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= limit:
                return out
    # UTF-16LE: printable byte + NUL pairs
    i = 0
    n = len(data)
    cur = bytearray()
    while i + 1 < n:
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 32 <= lo < 127:
            cur.append(lo)
            i += 2
        else:
            if len(cur) >= min_len:
                s = cur.decode("ascii", "replace")
                if s not in seen:
                    seen.add(s)
                    out.append(s)
                    if len(out) >= limit:
                        return out
            cur.clear()
            i += 1
    if len(cur) >= min_len:
        s = cur.decode("ascii", "replace")
        if s not in seen:
            out.append(s)
    return out
