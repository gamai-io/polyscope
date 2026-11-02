"""PolyScope report: container + sections + deterministic language votes + sha256."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from typing import Any

from . import elf as elfmod
from . import pe as pemod
from .magic import detect
from .strings import extract
from .votes import classify

MAX_BYTES = 8 * 1024 * 1024


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stable(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _section_view(sections: list[dict], cap: int) -> list[dict]:
    out = []
    for s in sections[:cap]:
        out.append({k: s.get(k) for k in ("name", "type", "offset", "size", "vsize", "vaddr", "raw_size") if k in s})
    return out


FULL_MARKERS = {
    "haskell": (b"libHS", b"ghc-", b"stg_", b"GHC RTS"),
    "rust": (b"rustc version", b"/build/rustc-", b"RUST_BACKTRACE", b"library/std/src/"),
    "cpp": (b"libstdc++", b"GLIBCXX_", b"_ZSt"),
    "python": (b"PyInstaller", b"_MEIPASS", b"libpython"),
    "java": (b"java/lang/", b"(Ljava/", b"libjvm"),
    "dotnet": (b"BSJB", b"mscorlib"),
}


def _scan_full_markers(path: pathlib.Path, already: int) -> dict:
    """For large binaries, search the whole file with mmap (markers can be at EOF)."""
    import mmap
    try:
        if path.stat().st_size <= already:
            return {}
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            return {lang: any(mm.find(m) >= 0 for m in pats) for lang, pats in FULL_MARKERS.items()}
    except OSError:
        return {}


def report_bytes(data: bytes, name: str = "<bytes>", elf_parsed: dict | None = None,
                 full_markers: dict | None = None) -> dict:
    """Analyse bytes without writing or executing anything."""
    info = detect(data)
    sections: list[dict] = []
    extra: dict = {}
    needed: list[str] = []

    if info.get("container") == "elf":
        parsed = elf_parsed or elfmod.parse(data)
        if parsed.get("ok"):
            sections = parsed.get("sections", [])
            extra["go_buildid"] = parsed.get("go_buildid", False)
            needed = parsed.get("needed", [])
            extra["needed"] = needed
    elif info.get("container") == "pe":
        parsed = pemod.parse(data)
        if parsed.get("ok"):
            sections = parsed.get("sections", [])
            extra["pe_machine"] = parsed.get("machine")

    strings = extract(data) if info.get("container") not in ("text", "empty") else []
    cls = classify(data, info.get("container", "unknown"), strings, sections, needed, full_markers)

    out = {
        "name": name,
        "size": len(data),
        "sha256": _sha256(data),
        "container": info.get("container"),
        "bits": info.get("bits"),
        "endian": info.get("endian"),
        "arch": info.get("arch"),
        "detail": info.get("detail") or {},
        "lang": cls["lang"],
        "confidence": cls["confidence"],
        "evidence": cls["evidence"],
        "votes": cls["votes"],
        "sections": _section_view(sections, 64),
        "strings_sample": strings[:10],
        **extra,
    }
    out["report_sha256"] = _sha256(_stable({k: v for k, v in out.items() if k != "report_sha256"}).encode("utf-8"))
    return out


def analyze(path: str | pathlib.Path) -> dict:
    p = pathlib.Path(path)
    elf_parsed = None
    with p.open("rb") as fh:
        data = fh.read(MAX_BYTES)
    if detect(data).get("container") == "elf":
        elf_parsed = elfmod.parse_path(p)
    full_markers = _scan_full_markers(p, len(data))
    return report_bytes(data, str(p), elf_parsed=elf_parsed, full_markers=full_markers)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="polyscope", description="Container + language identification (read-only).")
    ap.add_argument("path", help="file to analyse")
    ap.add_argument("--json", action="store_true", help="JSON output (default)")
    args = ap.parse_args(argv)
    try:
        rep = analyze(args.path)
    except OSError as exc:
        print(json.dumps({"ok": False, "err": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(rep, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
