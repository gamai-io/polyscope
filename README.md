# PolyScope

Deterministic, evidence-first container and programming-language identification.
No execution of the analysed artefact, no network, standard library only.

PolyScope inspects bytes, container headers, strings and runtime markers, then
returns a language vote with the evidence that produced it. `unknown` is a
first-class answer.

## What it identifies

- Containers: **ELF, PE, Mach-O, WebAssembly, CPython `.pyc`, Java `.class`, DEX, ZIP, text**
- Languages: C, C++, Rust, Go, Python, Java, JavaScript, TypeScript, C#, Bash
- Binary runtime markers: Haskell, Fortran, D, OCaml, Ada, Zig, Swift, .NET
- Architecture/bits/endianness where the container exposes it

## Usage

```bash
python -m polyscope /bin/ls
python -m polyscope path/to/file.wasm
python -m polyscope path/to/module.pyc
```

```python
from polyscope import analyze
r = analyze("/bin/ls")
print(r["container"], r["lang"], r["confidence"], r["evidence"])
```

## Bench

The repository includes a real-corpus benchmark that compiles local sources and
measures classification accuracy:

```bash
python -m polyscope.bench --json
```

Measured on the reference corpus: **168/168 artefacts, accuracy 1.0, unknown 0**
(C/C++, Rust, Go, Java, Python, JavaScript plus marker-level languages).
A benchmark only proves the corpus it ran on; it is not a claim of universal
coverage.

## Design rules

- Read-only: artefacts are never executed.
- Evidence: every vote carries a human-readable reason.
- Deterministic: same bytes, same result.
- Conservative: unresolved cases return `unknown`, not a guess.

## Disassembly

`polyscope.asm` provides deterministic disassembly for ELF/PE (`objdump`),
Python bytecode (`dis`) and Java classes (`javap`) when those tools exist.
Native-to-C and native-to-Python recovery are reported as `UNSUPPORTED`; no
behavioural claims are fabricated.

## License

MIT.
