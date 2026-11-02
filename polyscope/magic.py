"""Container magic detection (ELF/PE/Mach-O/WASM/PYC/Java/DEX/ZIP/text)."""
from __future__ import annotations

import struct

_ELF_MACHINE = {0x03: "i386", 0x28: "arm", 0x3E: "x86_64", 0xB7: "aarch64", 0xF3: "riscv"}
_PE_MACHINE = {0x014C: "i386", 0x8664: "x86_64", 0xAA64: "arm64"}
_MACHO_CPU = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64"}

# CPython magic (first two bytes, little-endian) -> version. Not exhaustive.
_PYC = {
    3413: "3.8", 3425: "3.9", 3439: "3.10", 3495: "3.11",
    3531: "3.12", 3571: "3.13", 3607: "3.14",
}


def _u16(data: bytes, off: int, endian: str = "<") -> int | None:
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from(endian + "H", data, off)[0]


def _u32(data: bytes, off: int, endian: str = "<") -> int | None:
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from(endian + "I", data, off)[0]


def _u64(data: bytes, off: int, endian: str = "<") -> int | None:
    if off < 0 or off + 8 > len(data):
        return None
    return struct.unpack_from(endian + "Q", data, off)[0]


def _elf(data: bytes) -> dict:
    ident = data[:16]
    bits = {1: 32, 2: 64}.get(ident[4])
    endian = {1: "<", 2: ">"}.get(ident[5], "<")
    machine = _u16(data, 18, endian)
    return {
        "container": "elf",
        "bits": bits,
        "endian": "little" if endian == "<" else "big",
        "arch": _ELF_MACHINE.get(machine, f"elf-m{((machine or 0)):02x}"),
        "abi": {0: "sysv", 3: "linux"}.get(ident[7]),
    }


def _pe(data: bytes) -> dict | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = _u32(data, 0x3C)
    if e_lfanew is None or e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    machine = _u16(data, e_lfanew + 4)
    opt_magic = _u16(data, e_lfanew + 24)
    return {
        "container": "pe",
        "bits": 64 if opt_magic == 0x20B else 32,
        "endian": "little",
        "arch": _PE_MACHINE.get(machine, f"pe-m{((machine or 0)):04x}"),
        "pe_offset": e_lfanew,
    }


def _macho(data: bytes) -> dict | None:
    if len(data) < 8:
        return None
    magic = data[:4]
    if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        endian = "<" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
        cpu = _u32(data, 4, endian)
        return {
            "container": "macho",
            "bits": 64 if magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") else 32,
            "endian": "little" if endian == "<" else "big",
            "arch": _MACHO_CPU.get(cpu, f"macho-cpu{((cpu or 0)):08x}"),
        }
    if magic == b"\xca\xfe\xba\xbe":
        n = _u32(data, 4, ">") or 0
        # Java class has version numbers (45..70) here, fat Mach-O has arch count (small).
        if 45 <= n <= 100:
            return {"container": "java", "bits": 64, "endian": "big", "arch": "jvm"}
        return {"container": "macho-fat", "bits": None, "endian": "big", "arch": None}
    return None


def detect(data: bytes) -> dict:
    """Return {container, bits, endian, arch, detail} for the first bytes."""
    if not data:
        return {"container": "empty", "bits": None, "endian": None, "arch": None}
    if data.startswith(b"\x7fELF"):
        return _elf(data)
    pe = _pe(data)
    if pe:
        return pe
    macho = _macho(data)
    if macho:
        return macho
    if data.startswith(b"\0asm"):
        return {"container": "wasm", "bits": 32, "endian": "little", "arch": "wasm"}
    if data.startswith(b"dex\n"):
        return {"container": "dex", "bits": None, "endian": "little", "arch": "dalvik"}
    if len(data) >= 4 and data[2:4] == b"\r\n":
        ver = _u16(data, 0)
        return {"container": "pyc", "bits": None, "endian": "little",
                "arch": "python", "detail": {"python": _PYC.get(ver, f"magic:{ver}")}}
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return {"container": "zip", "bits": None, "endian": "little", "arch": None,
                "detail": {"note": "jar/apk/wheel/zip"}}
    if data.startswith(b"#!"):
        return {"container": "text", "bits": None, "endian": None, "arch": None,
                "detail": {"shebang": data[:80].split(b"\n", 1)[0].decode("latin-1", "replace")}}
    sample = data[:4096]
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127)
    if sample and printable / len(sample) > 0.85:
        return {"container": "text", "bits": None, "endian": None, "arch": None}
    return {"container": "unknown", "bits": None, "endian": None, "arch": None}
