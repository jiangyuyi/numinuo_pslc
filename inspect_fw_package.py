#!/usr/bin/env python3
"""Offline inspector for InnoGrit IG5208 MPutility / Utility firmware packages.

Read-only tool: scans archives or extracted package folders for `.fw` images
(`GRIT` / `CMFG`), `.ini` configs, and Windows PE binaries (`middleware.dll`,
`MPutility.exe`, `igu.exe`), extracting Flash ID matches (Intel B17A), build
banners, `CFexpress` signatures, PE exports, and `GRIT`/`INNO` command stubs.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib
from pathlib import Path
from typing import Any

MAGIC_GRIT = b"GRIT"
MAGIC_CMFG = b"CMFG"
MAGIC_CONF = b"CONF"
TARGET_FLASH_ID = bytes.fromhex("89C40832A600")
ARCHIVE_EXTS = {".rar", ".zip", ".7z"}
BINARY_EXTS = {".exe", ".dll"}


@dataclasses.dataclass
class GritSection:
    """One section entry parsed from a GRIT firmware header."""

    index: int
    name: str
    word1: int
    word2: int
    word3: int
    file_offset: int
    size: int
    flags: int


@dataclasses.dataclass
class GritImageInfo:
    """Parsed metadata and section layout for a GRIT container."""

    header_flags: int
    section_count: int
    entry_count: int
    stored_crc32: int
    computed_crc32: int
    crc_valid: bool
    layout_variant: str
    sections: list[GritSection]


def _crc32_ie(buf: bytes) -> int:
    return zlib.crc32(buf) & 0xFFFFFFFF


def _valid_span(offset: int, size: int, min_off: int, total_len: int) -> bool:
    return min_off <= offset < total_len and 0 < size <= total_len and offset + size <= total_len


def parse_grit_image(data: bytes, start: int = 0) -> GritImageInfo | None:
    """Parse a `GRIT` firmware container starting at `start`."""
    view = memoryview(data)[start:]
    if len(view) < 32 or bytes(view[:4]) != MAGIC_GRIT:
        return None

    header_flags, section_count, entry_count, stored_crc = struct.unpack_from(
        "<IHHI", view, 4
    )
    entries: list[tuple[str, int, int, int]] = []
    pos = 16
    limit = len(view)

    while pos + 16 <= limit and len(entries) < 64:
        raw_name = bytes(view[pos : pos + 4])
        if raw_name == b"\x00\x00\x00\x00":
            break
        if not all(b == 0 or 32 <= b < 127 for b in raw_name):
            break
        if section_count and len(entries) >= section_count and pos > 16:
            break
        w1, w2, w3 = struct.unpack_from("<III", view, pos + 4)
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        entries.append((name, w1, w2, w3))
        pos += 16

    if not entries:
        return None

    table_end = 16 + len(entries) * 16
    computed_crc = _crc32_ie(bytes(view[16:table_end]))
    if computed_crc != stored_crc and 0 < section_count <= len(entries):
        alt_end = 16 + section_count * 16
        alt_crc = _crc32_ie(bytes(view[16:alt_end]))
        if alt_crc == stored_crc:
            entries = entries[:section_count]
            table_end = alt_end
            computed_crc = alt_crc

    # Match section field order against file size:
    # - layout A (grit.rs): (offset=w1, size=w2, flags=w3)
    # - layout B (grit_checksum.py): (flags/addr=w1, offset=w2, size=w3)
    fit_a = sum(1 for _, w1, w2, _ in entries if _valid_span(w1, w2, table_end, len(view)))
    fit_b = sum(1 for _, _, w2, w3 in entries if _valid_span(w2, w3, table_end, len(view)))
    use_b = fit_b > fit_a
    layout_variant = "type_off_size" if use_b else "off_size_flags"

    sections = [
        GritSection(
            index=i,
            name=name,
            word1=w1,
            word2=w2,
            word3=w3,
            file_offset=(w2 if use_b else w1),
            size=(w3 if use_b else w2),
            flags=(w1 if use_b else w3),
        )
        for i, (name, w1, w2, w3) in enumerate(entries)
    ]
    return GritImageInfo(
        header_flags=header_flags,
        section_count=section_count,
        entry_count=entry_count,
        stored_crc32=stored_crc,
        computed_crc32=computed_crc,
        crc_valid=(computed_crc == stored_crc),
        layout_variant=layout_variant,
        sections=sections,
    )


def parse_cmfg_image(data: bytes) -> dict[str, Any] | None:
    """Parse a `CMFG` firmware wrapper and any embedded `CONF` or `GRIT` blocks."""
    if len(data) < 0x50 or data[:4] != MAGIC_CMFG:
        return None

    total_dw = struct.unpack_from("<I", data, 8)[0]
    descriptors = [
        {"index": i, "start_page": s, "end_page": e}
        for i in range(8)
        for s, e in [struct.unpack_from("<II", data, 0x10 + 8 * i)]
        if s or e
    ]

    conf_pages = []
    for d in descriptors:
        off = d["start_page"] * 0x1000
        if off + 0x1000 <= len(data) and data[off : off + 4] == MAGIC_CONF:
            page = data[off : off + 0x1000]
            conf_pages.append(
                {
                    "page_index": d["start_page"],
                    "offset": f"0x{off:06x}",
                    "crc32": f"0x{_crc32_ie(page):08x}",
                    "sn_0x410": page[0x410:0x424].split(b"\x00", 1)[0].decode("latin1", "replace"),
                    "model_0x430": page[0x430:0x458].split(b"\x00", 1)[0].decode("latin1", "replace"),
                }
            )

    embedded_grit = []
    idx = 0
    while True:
        pos = data.find(MAGIC_GRIT, idx)
        if pos < 0:
            break
        info = parse_grit_image(data, start=pos)
        if info is not None and info.crc_valid:
            embedded_grit.append({"offset": f"0x{pos:06x}", "sections": len(info.sections)})
        idx = pos + 4

    return {
        "total_header_u32": total_dw,
        "descriptors": descriptors,
        "conf_pages": conf_pages,
        "embedded_grit": embedded_grit,
    }


def scan_fw_markers(data: bytes) -> dict[str, Any]:
    """Search a firmware image for Flash IDs, build banners, and CFexpress strings."""
    markers: dict[str, Any] = {
        "flash_id_exact": [hex(m.start()) for m in re.finditer(re.escape(TARGET_FLASH_ID), data)],
        "flash_id_4b": [hex(m.start()) for m in re.finditer(re.escape(TARGET_FLASH_ID[:4]), data)],
        "cfexpress": [hex(m.start()) for m in re.finditer(rb"CFexpress", data, re.IGNORECASE)],
        "pci_ids": [],
        "banners": [],
    }

    # Check both little-endian 0x1DBE / 0x5208 pairs and ASCII mentions
    for tag, pat in (
        ("vid_1dbe_le16", b"\xbe\x1d"),
        ("did_5208_le16", b"\x08\x52"),
        ("vid_did_ascii", rb"(?:1DBE|5208)"),
    ):
        if tag == "vid_did_ascii":
            hits = [hex(m.start()) for m in re.finditer(pat, data, re.IGNORECASE)][:10]
            if hits:
                markers["pci_ids"].append({"pattern": tag, "offsets": hits})
        else:
            adj = [
                hex(m.start())
                for m in re.finditer(re.escape(b"\xbe\x1d\x08\x52"), data)
            ]
            if adj and not any(p["pattern"] == "1dbe_5208_pair" for p in markers["pci_ids"]):
                markers["pci_ids"].append({"pattern": "1dbe_5208_pair", "offsets": adj[:10]})

    banner_re = re.compile(
        rb"(?:master_[0-9A-Za-z._]+|Shasta|MSH[0-9A-Z]+|INNOGRIT|nand_(?:slc|tlc|qlc)|dslc|ftk[A-Za-z0-9_]+|B17A|L06B|3\.[0-9A-Z]+\.[0-9A-Z]+\.[0-9A-Z]+|[A-Z][a-z]{2}\s+\d{1,2}\s+20\d\d)"
    )
    seen: set[str] = set()
    for m in banner_re.finditer(data):
        start = max(0, m.start() - 16)
        end = min(len(data), m.end() + 24)
        # Expand to printable ASCII run around match
        while start > 0 and 32 <= data[start - 1] < 127:
            start -= 1
        while end < len(data) and 32 <= data[end] < 127:
            end += 1
        txt = data[start:end].decode("ascii", errors="replace")
        if txt not in seen:
            seen.add(txt)
            markers["banners"].append({"offset": f"0x{start:06x}", "text": txt[:140]})
        if len(markers["banners"]) >= 30:
            break

    return markers


def _pe_sections(data: bytes) -> tuple[int, int, list[tuple[str, int, int, int, int]]]:
    if len(data) < 0x100 or data[:2] != b"MZ":
        return 0, 0, []
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
        return 0, 0, []
    _, nsec, _, _, _, opthdr_sz, _ = struct.unpack_from("<HHIIIHH", data, pe_off + 4)
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    sec_off = opt_off + opthdr_sz
    secs = []
    for i in range(nsec):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name, vsz, va, rsz, ra = struct.unpack_from("<8sIIII", data, off)[:5]
        secs.append((name.split(b"\x00", 1)[0].decode("ascii", "replace"), vsz, va, rsz, ra))
    return opt_off, magic, secs


def _rva_to_raw(rva: int, secs: list[tuple[str, int, int, int, int]]) -> int | None:
    for _, vsz, va, rsz, ra in secs:
        span = max(vsz, rsz)
        if va <= rva < va + span:
            raw = ra + (rva - va)
            return raw if raw < ra + rsz else None
    return None


def inspect_pe_binary(path: Path) -> dict[str, Any]:
    """Extract exports, GRIT/INNO command stubs, and NVMe opcodes from a PE file."""
    data = path.read_bytes()
    opt_off, magic, secs = _pe_sections(data)
    info: dict[str, Any] = {
        "file": path.name,
        "size": len(data),
        "pe": bool(secs),
        "exports": [],
        "grit_inno_stubs": [],
        "interesting_strings": [],
    }
    if not secs:
        return info

    # DataDirectory[0] (Export Table): offset +96 in PE32 (0x10B), +112 in PE32+ (0x20B)
    dd_off = opt_off + (112 if magic == 0x20B else 96)
    if dd_off + 8 <= len(data):
        exp_rva, exp_sz = struct.unpack_from("<II", data, dd_off)
        exp_raw = _rva_to_raw(exp_rva, secs) if exp_rva and exp_sz else None
        if exp_raw is not None and exp_raw + 40 <= len(data):
            n_names = struct.unpack_from("<I", data, exp_raw + 24)[0]
            names_rva = struct.unpack_from("<I", data, exp_raw + 32)[0]
            names_raw = _rva_to_raw(names_rva, secs)
            if names_raw is not None:
                for i in range(min(n_names, 200)):
                    nrva = struct.unpack_from("<I", data, names_raw + i * 4)[0]
                    nraw = _rva_to_raw(nrva, secs)
                    if nraw is not None:
                        end = data.find(b"\x00", nraw, min(len(data), nraw + 128))
                        if end > nraw:
                            info["exports"].append(data[nraw:end].decode("ascii", "replace"))

    # Locate mov imm32 / dword pairs containing GRIT (0x54495247) and INNO (0x4F4E4E49)
    for m in re.finditer(rb"GRIT", data):
        pos = m.start()
        win = data[max(0, pos - 48) : min(len(data), pos + 32)]
        if b"INNO" not in win:
            continue
        imm_vals = [
            f"0x{struct.unpack_from('<I', win, j + 4)[0]:08x}"
            for j in range(len(win) - 7)
            if win[j : j + 3] == b"\xc7\x44\x24"
        ]
        info["grit_inno_stubs"].append(
            {"file_offset": f"0x{pos:06x}", "stack_imm32": imm_vals, "window_hex": win.hex()}
        )
        if len(info["grit_inno_stubs"]) >= 64:
            break

    kw_re = re.compile(
        rb"(?:MID_[A-Za-z0-9_]+|ToRecovery|SetFWconfig|UpdateFW|GetMpInfo|SmartClean|SetThin|NandWorkMode|Config_New\.ini|ftkdisk[A-Za-z0-9_.+-]*|rdisk[A-Za-z0-9_.+-]*|programmer[A-Za-z0-9_.+-]*|loader[A-Za-z0-9_.+-]*|CFexpress)"
    )
    seen: set[str] = set()
    for m in kw_re.finditer(data):
        s = m.group().decode("ascii", errors="replace")
        if s not in seen:
            seen.add(s)
            info["interesting_strings"].append(s)
        if len(info["interesting_strings"]) >= 80:
            break

    return info


def inspect_ini_file(path: Path) -> dict[str, Any]:
    """Parse INI sections/key-value pairs relevant to IG5208 configuration."""
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    sections: dict[str, dict[str, str]] = {}
    cur = "DEFAULT"
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1].strip()
            sections.setdefault(cur, {})
        elif "=" in line:
            k, v = line.split("=", 1)
            sections.setdefault(cur, {})[k.strip()] = v.strip()
    return {"file": path.name, "sections": sections}


def _clean_ascii_stem(stem: str) -> str:
    """Normalize downloaded forum archive names (e.g. `[...]-29648-igu1.0.0.8`) to clean ASCII."""
    m = re.match(r"^(?:\[[^\]]+\]-?\d*-?)?(.*)$", stem)
    candidate = m.group(1) if m and m.group(1) else stem
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", candidate).strip("_")
    return cleaned or "archive"


def _prepare_clean_rar(archive: Path, dest_dir: Path) -> tuple[Path, str]:
    """Strip prepended anti-leech header before `Rar!\\x1a\\x07` and ensure ASCII filename."""
    clean_stem = _clean_ascii_stem(archive.stem)
    head = archive.read_bytes() if archive.stat().st_size <= 256 * 1024 * 1024 else None
    if head is not None:
        magic_pos = head[:1024].find(b"Rar!\x1a\x07")
        if magic_pos > 0 or not str(archive).isascii():
            offset = magic_pos if magic_pos > 0 else 0
            clean_rar = dest_dir / f"{clean_stem}.rar"
            clean_rar.parent.mkdir(parents=True, exist_ok=True)
            clean_rar.write_bytes(head[offset:])
            return clean_rar, clean_stem
    return archive, clean_stem


def extract_archive(archive: Path, dest_dir: Path) -> Path:
    """Extract `.zip`, `.rar`, or `.7z` into `dest_dir/<clean_stem>`."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    if archive.suffix.lower() == ".zip":
        out_dir = dest_dir / _clean_ascii_stem(archive.stem)
        out_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(out_dir)
        return out_dir

    src_archive = archive
    clean_stem = _clean_ascii_stem(archive.stem)
    if archive.suffix.lower() == ".rar":
        src_archive, clean_stem = _prepare_clean_rar(archive, dest_dir)

    out_dir = dest_dir / clean_stem
    out_dir.mkdir(parents=True, exist_ok=True)

    seven_z = shutil.which("7z") or shutil.which("7z.exe")
    if not seven_z:
        local_app = os.environ.get("LOCALAPPDATA", "")
        cand = Path(local_app) / "Microsoft" / "WindowsApps" / "7z.exe"
        if cand.exists():
            seven_z = str(cand)
    if seven_z and Path(seven_z).exists():
        res = subprocess.run(
            [str(seven_z), "x", str(src_archive), f"-o{out_dir}", "-y"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if res.returncode == 0:
            return out_dir

    res = subprocess.run(
        ["tar", "-xf", str(src_archive), "-C", str(out_dir)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(f"Failed to extract {archive.name}: {res.stderr.strip()}")
    return out_dir


def inspect_directory(target_dir: Path, extract_dest: Path, extract_archives: bool) -> dict[str, Any]:
    """Walk a workspace or extracted package folder and summarize all findings."""
    archives = sorted(
        p for p in target_dir.iterdir() if p.is_file() and p.suffix.lower() in ARCHIVE_EXTS
    )
    extracted_dirs: list[str] = []
    if extract_archives:
        for arc in archives:
            if "innogrit_nvme_flash_id" in arc.name:
                continue
            out = extract_archive(arc, extract_dest)
            extracted_dirs.append(str(out))

    roots = [target_dir] + [Path(d) for d in extracted_dirs if Path(d).parent != target_dir]
    seen_files: set[Path] = set()
    fw_reports: list[dict[str, Any]] = []
    ini_reports: list[dict[str, Any]] = []
    pe_reports: list[dict[str, Any]] = []

    for root in roots:
        if not root.exists():
            continue
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            # Skip our read-only hardware backups and already-inspected VLO rar wrapper
            if "backups" in p.parts or "reference" in p.parts:
                continue
            rp = p.resolve()
            if rp in seen_files:
                continue
            seen_files.add(rp)

            suf = p.suffix.lower()
            if suf in {".fw", ".bin"}:
                data = p.read_bytes()
                grit = parse_grit_image(data)
                cmfg = parse_cmfg_image(data)
                markers = scan_fw_markers(data)
                fw_reports.append(
                    {
                        "path": str(p),
                        "size": len(data),
                        "magic": data[:4].hex() if len(data) >= 4 else "",
                        "grit": dataclasses.asdict(grit) if grit else None,
                        "cmfg": cmfg,
                        "markers": markers,
                    }
                )
            elif suf == ".ini":
                ini_reports.append({"path": str(p), **inspect_ini_file(p)})
            elif suf in BINARY_EXTS:
                pe_reports.append({"path": str(p), **inspect_pe_binary(p)})

    return {
        "scanned_dir": str(target_dir),
        "archives_found": [str(a) for a in archives],
        "extracted_dirs": extracted_dirs,
        "fw_images": fw_reports,
        "ini_files": ini_reports,
        "pe_binaries": pe_reports,
    }


def _build_synthetic_grit(use_layout_b: bool = False) -> bytes:
    """Create a valid synthetic GRIT container for offline unit verification."""
    payload0 = b"master_2.0\x00Shasta\x00MSH00SN0\x00" + b"CFexpress\x01" + b"\x00" * 30
    payload1 = TARGET_FLASH_ID + b"\xbe\x1d\x08\x52" + b"\xff" * 48
    off0 = 0x30
    off1 = off0 + len(payload0)
    hdr_and_tbl = bytearray(off0)
    hdr_and_tbl[0:4] = MAGIC_GRIT
    struct.pack_into("<IHHI", hdr_and_tbl, 4, 1, 2, 2, 0)
    if use_layout_b:
        struct.pack_into("<4sIII", hdr_and_tbl, 16, b"head", 0x10, off0, len(payload0))
        struct.pack_into("<4sIII", hdr_and_tbl, 32, b"ftbl", 0x20, off1, len(payload1))
    else:
        struct.pack_into("<4sIII", hdr_and_tbl, 16, b"head", off0, len(payload0), 0x10)
        struct.pack_into("<4sIII", hdr_and_tbl, 32, b"ftbl", off1, len(payload1), 0x20)
    crc = _crc32_ie(bytes(hdr_and_tbl[16:48]))
    struct.pack_into("<I", hdr_and_tbl, 12, crc)
    return bytes(hdr_and_tbl) + payload0 + payload1


def _build_synthetic_cmfg() -> bytes:
    """Create a synthetic CMFG container with one CONF page at page 1."""
    buf = bytearray(0x2000)
    buf[0:4] = MAGIC_CMFG
    struct.pack_into("<I", buf, 8, 2)
    struct.pack_into("<II", buf, 0x10, 1, 2)
    buf[0x1000:0x1004] = MAGIC_CONF
    buf[0x1410:0x1419] = b"TEST_SN01"
    buf[0x1430:0x1441] = b"NUMINUO CFEA-PLUS"
    return bytes(buf)


def run_self_test(workspace: Path) -> None:
    """Verify GRIT/CMFG parsing, Flash ID scanning, and PE inspection without card access."""
    g_a = parse_grit_image(_build_synthetic_grit(use_layout_b=False))
    assert g_a is not None and g_a.crc_valid and g_a.layout_variant == "off_size_flags"
    assert len(g_a.sections) == 2 and g_a.sections[1].name == "ftbl"

    g_b = parse_grit_image(_build_synthetic_grit(use_layout_b=True))
    assert g_b is not None and g_b.crc_valid and g_b.layout_variant == "type_off_size"
    assert g_b.sections[0].file_offset == 0x30

    bad = bytearray(_build_synthetic_grit())
    bad[12] ^= 0xFF
    g_bad = parse_grit_image(bytes(bad))
    assert g_bad is not None and not g_bad.crc_valid

    cmfg = parse_cmfg_image(_build_synthetic_cmfg())
    assert cmfg is not None and len(cmfg["conf_pages"]) == 1
    assert cmfg["conf_pages"][0]["sn_0x410"] == "TEST_SN01"

    markers = scan_fw_markers(_build_synthetic_grit())
    assert markers["flash_id_exact"] and markers["cfexpress"]
    assert any("1dbe_5208_pair" == p["pattern"] for p in markers["pci_ids"])
    assert any("Shasta" in b["text"] for b in markers["banners"])

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zpath = tmp_path / "pkg.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("ftkdisk_mu_b17a.fw", _build_synthetic_grit())
            zf.writestr("Config_New.ini", "[FLASH]\nNAND_MAJORID=0x89\nNAND_WORK_MODE=TLC\n")
        report = inspect_directory(tmp_path, tmp_path / "out", extract_archives=True)
        assert len(report["fw_images"]) == 1 and report["fw_images"][0]["grit"]["crc_valid"]
        assert report["ini_files"][0]["sections"]["FLASH"]["NAND_WORK_MODE"] == "TLC"

    vlo_exe = workspace / "tools" / "vlo_flash_id" / "innogrit_nvme_flash_id.exe"
    if vlo_exe.exists():
        pe = inspect_pe_binary(vlo_exe)
        assert pe["pe"] and len(pe["grit_inno_stubs"]) >= 6

    print("inspect_fw_package.py --self-test: ALL PASSED")


def main() -> None:
    repo_root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Offline inspector for InnoGrit IG5208 MPutility/Utility firmware packages."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=str(repo_root),
        help="Directory to scan for .rar/.zip/.7z archives or extracted MPutility folders.",
    )
    parser.add_argument(
        "--extract-dir",
        type=Path,
        default=repo_root / "mp_package",
        help="Destination folder for auto-extracted archives.",
    )
    parser.add_argument(
        "--no-extract",
        action="store_true",
        help="Skip extracting .rar/.zip/.7z archives.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to save full JSON inspection report.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run offline self-tests against synthetic images and local PE tools.",
    )
    args = parser.parse_args()

    if args.self_test:
        run_self_test(Path(args.target))
        return

    report = inspect_directory(Path(args.target), args.extract_dir, extract_archives=not args.no_extract)
    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Scanned: {report['scanned_dir']}")
    print(f"Archives found ({len(report['archives_found'])}): {[Path(a).name for a in report['archives_found']]}")
    print(f"FW images ({len(report['fw_images'])}), INI ({len(report['ini_files'])}), PE ({len(report['pe_binaries'])})")
    for fw in report["fw_images"]:
        p = Path(fw["path"]).name
        g = fw["grit"]
        c = fw["cmfg"]
        m = fw["markers"]
        kind = f"GRIT(crc={'OK' if g['crc_valid'] else 'BAD'}, secs={len(g['sections'])})" if g else (
            f"CMFG(confs={len(c['conf_pages'])})" if c else "RAW"
        )
        print(
            f"  [FW] {p} ({fw['size']} B) -> {kind} | "
            f"B17A_FID={len(m['flash_id_exact'])} | CFe={len(m['cfexpress'])} | banners={len(m['banners'])}"
        )
    for ini in report["ini_files"]:
        print(f"  [INI] {ini['file']}: sections={list(ini['sections'].keys())}")
    for pe in report["pe_binaries"]:
        print(
            f"  [PE] {pe['file']} ({pe['size']} B): exports={len(pe['exports'])}, "
            f"grit_inno_stubs={len(pe['grit_inno_stubs'])}, strings={len(pe['interesting_strings'])}"
        )


if __name__ == "__main__":
    main()
