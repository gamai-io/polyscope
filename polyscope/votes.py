"""Evidence-based programming-language votes. No single heuristic decides."""
from __future__ import annotations

import re

_MAX_SCAN = 4 * 1024 * 1024


def _off(data: bytes, needle: bytes, limit: int = _MAX_SCAN) -> int:
    return data.find(needle, 0, min(len(data), limit))


def _add(votes: dict, lang: str, score: float, why: str) -> None:
    v = votes.setdefault(lang, {"score": 0.0, "evidence": []})
    v["score"] += score
    if why and why not in v["evidence"] and len(v["evidence"]) < 8:
        v["evidence"].append(why)


def _binary_votes(data: bytes, container: str, strings: list[str], sections: list[dict],
                  needed: list[str] | None = None, full_markers: dict | None = None) -> dict:
    votes: dict = {}
    for lang, hit in (full_markers or {}).items():
        if hit:
            _add(votes, lang, 8.0, f"full-file marker for {lang}")
    names = " ".join(s.get("name", "") for s in sections)
    head = data[: min(len(data), _MAX_SCAN)]
    joined = "\n".join(strings[:20000])

    # Go
    if b"Go build ID:" in head or b"go1." in head:
        _add(votes, "go", 5.0, "Go build id / go1. version string")
    if "gopclntab" in names or "go.buildid" in names:
        _add(votes, "go", 5.0, "ELF section .gopclntab/.note.go.buildid")
    if b"runtime.gopanic" in head or b"goroutine " in head:
        _add(votes, "go", 3.0, "runtime.gopanic / goroutine")
    if "go:build" in joined:
        _add(votes, "go", 1.0, "go:build directive")

    # Rust
    if b"rustc version" in head or b"/build/rustc-" in head:
        _add(votes, "rust", 6.0, "rustc version / build path (.comment)")
    if b"RUST_BACKTRACE" in head:
        _add(votes, "rust", 4.0, "RUST_BACKTRACE runtime string")
    if b"library/std/src/" in head:
        _add(votes, "rust", 4.0, "library/std/src paths")
    if b"rust_eh_personality" in head:
        _add(votes, "rust", 5.0, "rust_eh_personality symbol")
    m = re.search(rb"_ZN[^\x00\r\n]{1,180}17h", head)
    if m:
        _add(votes, "rust", 4.0, f"Rust legacy mangling at {m.start()}")
    if b"core::panicking" in head or b"alloc::raw_vec" in head:
        _add(votes, "rust", 3.0, "core::panicking / alloc symbols")
    for s in ("src/lib.rs", ".cargo/registry", "rustc"):
        if s in joined:
            _add(votes, "rust", 2.0, f"string {s!r}")
            break

    # C / C++
    if b"GLIBC_" in head:
        _add(votes, "c", 2.0, "GLIBC_ versioned symbol")
    if b"__libc_start_main" in head:
        _add(votes, "c", 1.0, "__libc_start_main")
    needed = needed or []
    if any("libstdc++" in n or "libc++" in n for n in needed):
        _add(votes, "cpp", 8.0, "DT_NEEDED libstdc++/libc++")
    if any("libc.so" in n or "libc.musl" in n for n in needed):
        _add(votes, "c", 2.0, "DT_NEEDED libc")
    if any("libpython" in n for n in needed):
        _add(votes, "python", 6.0, "DT_NEEDED libpython")
    if any("libjvm" in n or "libjava" in n for n in needed):
        _add(votes, "java", 6.0, "DT_NEEDED libjvm")
    if b"libstdc++" in head or b"GLIBCXX_" in head:
        _add(votes, "cpp", 6.0, "libstdc++ / GLIBCXX_ (C++ runtime)")
    if b"_ZSt" in head:
        _add(votes, "cpp", 4.0, "_ZSt std:: mangling")
    if b"std::" in head:
        _add(votes, "cpp", 2.0, "std:: symbol")
    if b"GCC:" in head:
        _add(votes, "c", 1.0, "GCC comment")

    # Swift
    if b"_$s" in head:
        _add(votes, "swift", 5.0, "_$s Swift mangling")
    if b"libswiftCore" in head:
        _add(votes, "swift", 3.0, "libswiftCore")

    # .NET / JVM / Python / JS
    if b"BSJB" in head:
        _add(votes, "dotnet", 6.0, "BSJB metadata signature")
    if b"mscorlib" in head:
        _add(votes, "dotnet", 4.0, "mscorlib")
    if b"_CorExeMain" in head:
        _add(votes, "dotnet", 3.0, "_CorExeMain")
    if b"java/lang/" in head:
        _add(votes, "java", 6.0, "java/lang/ constant")
    if b"(Ljava/" in head:
        _add(votes, "java", 4.0, "(Ljava/ descriptor")
    if container == "java":
        _add(votes, "java", 6.0, "CAFEBABE class container")
    if container == "pyc":
        _add(votes, "python", 8.0, "CPython .pyc magic")
    if b"PyInstaller" in head or b"_MEIPASS" in head:
        _add(votes, "python", 4.0, "PyInstaller loader")

    # Languages outside the compiler set we ship, but recognisable by runtime markers.
    # Recognising them prevents false "C" claims; they are still marker-based, not full support.
    if b"libHS" in head or b"ghc-" in head or b"stg_" in head or b"GHC RTS" in head:
        _add(votes, "haskell", 7.0, "libHS / GHC runtime marker")
    if b"_gfortran_" in head or b"libgfortran" in head or b"gfortran" in head:
        _add(votes, "fortran", 7.0, "libgfortran / _gfortran_ marker")
    if b"libphobos" in head or b"_Dmain" in head:
        _add(votes, "d", 6.0, "libphobos / _Dmain marker")
    if b"caml_" in head or b"libasmrun" in head:
        _add(votes, "ocaml", 7.0, "caml_ / libasmrun marker")
    if b"libgnat" in head or b"__gnat_" in head or b"GNAT." in head or b"gnat_" in head or b"ada.text_io" in head:
        _add(votes, "ada", 6.0, "GNAT / Ada runtime marker")
    if b"std.debug" in head or b"zig_" in head:
        _add(votes, "zig", 5.0, "std.debug / zig_ marker")
    return votes


_TEXT_PATTERNS = {
    "python": [(r"(?m)^\s*def\s+\w+\s*\(", 3.0),
               (r"(?m)^\s*class\s+\w+(\([^)]*\))?\s*:", 3.0),
               (r"(?m)^\s*(import|from)\s+\w+", 2.0),
               (r"\bself\.", 1.0), (r"__name__\s*==", 2.0),
               (r"\bprint\s*\(", 2.0), (r"\b(range|len)\s*\(", 1.0),
               (r"\b(None|True|False)\b", 1.0), (r"\.items\(\)", 2.0),
               (r"(?m)^\s*(for|while|if|elif|else)\b[^\n]*:", 1.0)],
    "go": [(r"(?m)^\s*package\s+\w+", 4.0), (r"\bfunc\s+\w+\s*\(", 3.0),
           (r"\bfmt\.", 2.0), (r"(?m)^\s*import\s+\(", 2.0)],
    "rust": [(r"\bfn\s+\w+\s*\(", 3.0), (r"\blet\s+mut\b", 2.0),
             (r"\buse\s+std::", 3.0), (r"\bprintln!\s*\(", 2.0), (r"->\s*Result<", 2.0)],
    "javascript": [(r"\bfunction\s+\w+\s*\(", 2.0), (r"=>", 1.0), (r"\b(const|let)\s+\w+", 1.5),
                   (r"\brequire\s*\(", 2.0), (r"module\.exports", 2.0),
                   (r"\bclass\s+\w+\s*\{", 3.0), (r"constructor\s*\(", 3.0),
                   (r"async\s+function", 2.0), (r"await\s+", 1.0),
                   (r"console\.log", 2.0)],
    "typescript": [(r"\binterface\s+\w+", 3.0), (r":\s*(string|number|boolean)\b", 2.0),
                   (r"\bexport\s+(type|interface)\b", 2.0)],
    "c": [(r"#include\s*<", 3.0), (r"\bint\s+main\s*\(", 3.0), (r"\bprintf\s*\(", 2.0)],
    "cpp": [(r"#include\s*<(iostream|vector|string)>", 4.0), (r"\bstd::", 3.0),
            (r"using\s+namespace\s+std", 2.0)],
    "java": [(r"\bpublic\s+(final\s+)?class\s+\w+", 3.0),
             (r"\bclass\s+\w+\s*\{", 2.0), (r"import\s+java\.", 3.0),
             (r"System\.out\.", 3.0)],
    "csharp": [(r"\busing\s+System\b", 3.0), (r"\bnamespace\s+\w+", 2.0),
               (r"Console\.WriteLine", 3.0)],
    "bash": [(r"(?m)^#!.*\b(ba)?sh\b", 4.0), (r"\bif\s+\[", 2.0), (r"\bfi\b", 1.0)],
}


def _text_votes(data: bytes) -> dict:
    text = data[: min(len(data), 200_000)].decode("utf-8", "replace")
    votes: dict = {}
    for lang, pats in _TEXT_PATTERNS.items():
        for pat, score in pats:
            m = re.search(pat, text)
            if m:
                _add(votes, lang, score, f"{pat} at {m.start()}")
    return votes


def classify(data: bytes, container: str, strings: list[str] | None = None,
             sections: list[dict] | None = None, needed: list[str] | None = None,
             full_markers: dict | None = None) -> dict:
    strings = strings or []
    sections = sections or []
    needed = needed or []
    if container == "text":
        votes = _text_votes(data)
    else:
        votes = _binary_votes(data, container, strings, sections, needed, full_markers)

    ranked = sorted(votes.items(), key=lambda kv: (-kv[1]["score"], kv[0]))
    total = sum(v["score"] for _, v in ranked)
    if not ranked or ranked[0][1]["score"] < 2.0:
        return {"lang": "unknown", "confidence": 0.0, "votes": [], "evidence": []}
    lang, top = ranked[0]
    confidence = round(top["score"] / total, 4) if total else 0.0
    # Cap: a single weak marker must not claim near-certainty.
    confidence = min(confidence, 0.99)
    return {
        "lang": lang,
        "confidence": confidence,
        "votes": [{"lang": k, "score": round(v["score"], 2), "evidence": v["evidence"]}
                  for k, v in ranked],
        "evidence": top["evidence"],
    }
