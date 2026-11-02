"""Directory/fleet scan: aggregate PolyScope results without executing anything."""
from __future__ import annotations

import argparse
import collections
import json
import pathlib

from .magic import detect
from .report import analyze

KNOWN = {"elf", "pe", "macho", "macho-fat", "wasm", "pyc", "java", "dex", "zip", "text"}


def scan_paths(paths: list[pathlib.Path], max_files: int = 500) -> dict:
    rows: list[dict] = []
    errors: list[dict] = []
    skipped = 0
    files = []
    for p in paths:
        try:
            if p.is_dir():
                files.extend(sorted(x for x in p.rglob("*") if x.is_file()))
            elif p.is_file():
                files.append(p)
        except OSError as exc:
            errors.append({"path": str(p), "err": str(exc)})
    total_seen = len(files)
    for p in files[:max_files]:
        try:
            with p.open("rb") as fh:
                head = fh.read(1024)
            if detect(head).get("container") not in KNOWN:
                skipped += 1
                continue
            rep = analyze(p)
            rows.append({"path": str(p), "container": rep["container"], "lang": rep["lang"],
                         "arch": rep["arch"], "confidence": rep["confidence"], "size": rep["size"]})
        except Exception as exc:  # noqa: BLE001
            errors.append({"path": str(p), "err": f"{type(exc).__name__}: {exc}"})
    by_lang = collections.Counter(r["lang"] for r in rows)
    by_container = collections.Counter(r["container"] for r in rows)
    by_arch = collections.Counter(r["arch"] for r in rows if r["arch"])
    return {
        "files_seen": total_seen,
        "analyzed": len(rows),
        "skipped": skipped,
        "errors": errors,
        "by_lang": dict(by_lang.most_common()),
        "by_container": dict(by_container.most_common()),
        "by_arch": dict(by_arch.most_common()),
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="polyscope.scan",
                                 description="Scan files/directories and aggregate containers, languages, archs.")
    ap.add_argument("paths", nargs="+", help="files or directories")
    ap.add_argument("--max", type=int, default=500, help="max files to analyze (default 500)")
    ap.add_argument("--details", action="store_true", help="include per-file rows")
    ap.add_argument("--json", action="store_true", help="JSON output (default)")
    args = ap.parse_args(argv)
    res = scan_paths([pathlib.Path(p) for p in args.paths], max_files=args.max)
    if not args.details:
        res.pop("rows", None)
    print(json.dumps(res, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if not res["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
