"""PolyScope — deterministic container + programming-language identification.

Stdlib only. Evidence-first: every vote carries an offset/string; unknown is a
first-class answer. No execution of analysed artefacts.
"""
from .magic import detect
from .report import analyze, report_bytes
from .votes import classify

__all__ = ["detect", "analyze", "report_bytes", "classify"]
