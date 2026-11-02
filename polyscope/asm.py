"""Transpile ladder, rung 1: deterministic disassembly. No execution of targets.

Statuses:
  EXACT         bytes -> assembly/bytecode (objdump / dis / javap)
  UNSUPPORTED   no tool or no format support
C and Python decompilation is intentionally not faked.
"""
from __future__ import annotations

import argparse
import dis
import io
import json
import marshal
import pathlib
import shutil
import subprocess

from .magic import detect


def _run(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def disassemble(path: str | pathlib.Path, max_lines: int = 2000) -> dict:
    p = pathlib.Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        return {"status": "UNSUPPORTED", "reason": str(exc)}
    info = detect(data[:1024])
    container = info.get("container")

    if container == "pyc":
        try:
            code = marshal.loads(data[16:])
            buf = io.StringIO()
            dis.dis(code, file=buf)
            text = buf.getvalue()
            lines = text.splitlines()
            return {"status": "EXACT", "engine": "dis", "container": "pyc",
                    "python": info.get("detail", {}).get("python"),
                    "lines": len(lines), "truncated": len(lines) > max_lines,
                    "asm": "\n".join(lines[:max_lines])}
        except Exception as exc:  # noqa: BLE001
            return {"status": "UNSUPPORTED", "reason": f"pyc disassembly failed: {exc}"}

    if container == "java":
        if not shutil.which("javap"):
            return {"status": "UNSUPPORTED", "reason": "javap not installed"}
        try:
            r = _run(["javap", "-c", "-p", str(p)])
            if r.returncode != 0:
                return {"status": "UNSUPPORTED", "reason": (r.stderr or r.stdout)[:300]}
            lines = r.stdout.splitlines()
            return {"status": "EXACT", "engine": "javap", "container": "java",
                    "lines": len(lines), "truncated": len(lines) > max_lines,
                    "asm": "\n".join(lines[:max_lines])}
        except Exception as exc:  # noqa: BLE001
            return {"status": "UNSUPPORTED", "reason": str(exc)}

    if container in ("elf", "pe"):
        if not shutil.which("objdump"):
            return {"status": "UNSUPPORTED", "reason": "objdump not installed"}
        try:
            r = _run(["objdump", "-d", "--no-show-raw-insn", str(p)])
            if r.returncode != 0:
                return {"status": "UNSUPPORTED", "reason": (r.stderr or r.stdout)[:300]}
            lines = r.stdout.splitlines()
            return {"status": "EXACT", "engine": "objdump", "container": container,
                    "arch": info.get("arch"), "lines": len(lines),
                    "truncated": len(lines) > max_lines,
                    "asm": "\n".join(lines[:max_lines])}
        except Exception as exc:  # noqa: BLE001
            return {"status": "UNSUPPORTED", "reason": str(exc)}

    return {"status": "UNSUPPORTED", "reason": f"no disassembler for container={container}"}


def to_c(path: str | pathlib.Path) -> dict:
    for tool in ("retdec-decompiler", "r2", "ghidraRun"):
        if shutil.which(tool):
            return {"status": "UNSUPPORTED", "reason": f"{tool} present but adapter not implemented",
                    "next": "wire a sandboxed decompiler adapter"}
    return {"status": "UNSUPPORTED", "reason": "no decompiler installed (retdec/Ghidra/rizin)"}


def to_python(path: str | pathlib.Path) -> dict:
    return {"status": "UNSUPPORTED",
            "reason": "native binary -> Python needs a reference-output oracle (same IO) and is not implemented"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="polyscope.asm",
                                 description="Deterministic disassembly (no execution).")
    ap.add_argument("path")
    ap.add_argument("--max-lines", type=int, default=2000)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    res = disassemble(args.path, max_lines=args.max_lines)
    print(json.dumps(res, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if res["status"] == "EXACT" else 1


if __name__ == "__main__":
    raise SystemExit(main())
