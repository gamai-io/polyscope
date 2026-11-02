from __future__ import annotations

import pathlib
import py_compile
import tempfile
import unittest

from polyscope import analyze, detect, classify


class TestContainers(unittest.TestCase):
    def test_elf(self):
        p = pathlib.Path("/bin/ls")
        if not p.exists():
            self.skipTest("no /bin/ls")
        d = detect(p.read_bytes()[:64])
        self.assertEqual(d["container"], "elf")
        self.assertEqual(d["bits"], 64)

    def test_wasm_header(self):
        d = detect(b"\x00asm\x01\x00\x00\x00")
        self.assertEqual(d["container"], "wasm")

    def test_pyc(self):
        with tempfile.TemporaryDirectory() as td:
            src = pathlib.Path(td) / "x.py"
            src.write_text("x = 1\n")
            pyc = pathlib.Path(td) / "x.pyc"
            py_compile.compile(str(src), cfile=str(pyc), doraise=True)
            d = detect(pyc.read_bytes()[:16])
            self.assertEqual(d["container"], "pyc")

    def test_unknown(self):
        d = detect(bytes(range(1, 40)))
        self.assertIn(d["container"], ("unknown", "text"))


class TestLanguages(unittest.TestCase):
    def test_text_rust(self):
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as f:
            f.write('fn main(){println!("hi");}\n'); p = pathlib.Path(f.name)
        try:
            self.assertEqual(analyze(p)["lang"], "rust")
        finally:
            p.unlink()

    def test_text_go(self):
        with tempfile.NamedTemporaryFile("w", suffix=".go", delete=False) as f:
            f.write('package main\nimport "fmt"\nfunc main(){fmt.Println("hi")}\n'); p = pathlib.Path(f.name)
        try:
            self.assertEqual(analyze(p)["lang"], "go")
        finally:
            p.unlink()

    def test_text_python(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write('def f(x):\n    return x + 1\nprint(f(2))\n'); p = pathlib.Path(f.name)
        try:
            self.assertEqual(analyze(p)["lang"], "python")
        finally:
            p.unlink()

    def test_elf_c(self):
        p = pathlib.Path("/bin/ls")
        if not p.exists():
            self.skipTest("no /bin/ls")
        self.assertIn(analyze(p)["lang"], {"c", "unknown"})


class TestVotes(unittest.TestCase):
    def test_unknown_is_first_class(self):
        v = classify(b"\x01\x02\x03", "unknown")
        self.assertIsInstance(v, dict)


if __name__ == "__main__":
    unittest.main()
