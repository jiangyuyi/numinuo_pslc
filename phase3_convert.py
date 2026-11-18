"""Phase 3 conversion toolkit for IG5208 CFexpress cards over JMS583 (0xA1)."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import time
import zlib
from pathlib import Path
from typing import Any

from backup_card import (
    GRIT_MAGIC,
    INNO_MAGIC,
    JMS583Device,
    JMS583Error,
    SCSI_IOCTL_DATA_IN,
    SCSI_IOCTL_DATA_OUT,
    backup_card,
    collect_c2_event_log,
    collect_c6_superblocks,
    parse_smart_summary,
)

REPO_ROOT = Path(__file__).resolve().parent
FTK_FW_DIR = (
    REPO_ROOT / "mp_package" / "igu1.0.0.8" / "igu1.0.0.8" / "firmware" / "ftk"
)
FW_MODE_MAP = {
    "dslc": FTK_FW_DIR / "ftkdisk_mu_single_lun_hmb.fw",
    "pslc": FTK_FW_DIR / "ftkdisk_mu_single_lun_hmb_pslc.fw",
    "pxlc": FTK_FW_DIR / "ftkdisk_mu_single_lun_hmb_pxlc.fw",
}
DSLC_SRC_FW = FW_MODE_MAP["dslc"]
EXPECTED_B17A_ID = bytes([0x89, 0xC4, 0x08, 0x32, 0xA6])

# Identify Controller tail pattern: ldrb.w r3,[r7,#0x21a]; orr.w r3,r3,#7; strb.w r3,[r7,#0x21a]
ID_HOOK_CONTEXT = bytes.fromhex("97f81a3243f0070387f81a32")
ID_ORIG_BYTES = bytes.fromhex("87f81a32")
# Unused ARM `test_and_change_bit` (64B) in ATCM
TACB_BYTES = bytes.fromhex(
    "03c011e20010cc150120a0e31f3000e2a002a0e1001181e01233a0e19f2f91e1"
    "030012e0032022e092cf81e100005ce3f9ffff1a000050e30100a0131eff2fe1"
)
TRAILER_MAGIC = struct.pack("<III", 0x1DBE5208, 0x20161201, 0x55484359)  # YCHU


class JMS583RWDevice(JMS583Device):
    """Extends JMS583Device with NVMe Admin Data-Out (0x83) and Vendor Non-Data (0x81)."""

    def nvme_admin_write(
        self,
        opcode: int,
        data: bytes,
        nsid: int = 0,
        cdw10: int = 0,
        cdw11: int = 0,
        cdw12: int = 0,
        cdw13: int = 0,
        cdw14: int = 0,
        cdw15: int = 0,
    ) -> tuple[int, int]:
        """Execute a Data-Out NVMe Admin command through JMS583 0xA1 (0x80 -> 0x83 -> 0x8F)."""
        size = len(data)
        if size <= 0 or size > 0xFFFFFF:
            raise ValueError(f"Invalid Data-Out size: {size}")

        # Step 1: Send 512B NVM Command Set Payload (0x80)
        cdb1 = bytes([0xA1, 0x80, 0x00, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0, 0])
        nvm_cmd = bytearray(512)
        nvm_cmd[0:4] = b"NVME"
        struct.pack_into("<II", nvm_cmd, 8, opcode, nsid)
        struct.pack_into(
            "<IIIIII", nvm_cmd, 48, cdw10, cdw11, cdw12, cdw13, cdw14, cdw15
        )
        st1, sense1, _ = self._scsi_pass_through(
            cdb1, SCSI_IOCTL_DATA_OUT, bytes(nvm_cmd)
        )
        if st1 != 0:
            raise JMS583Error(
                f"JMS583 Write Step 1 failed for OP 0x{opcode:02X}: SCSI 0x{st1:02X}, sense={sense1.hex()}"
            )

        # Step 2: DMA-Out data transfer (protocol 0x83 = Admin + DMA_OUT)
        cdb2 = bytes(
            [
                0xA1,
                0x83,
                0x00,
                (size >> 16) & 0xFF,
                (size >> 8) & 0xFF,
                size & 0xFF,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        )
        st2, sense2, _ = self._scsi_pass_through(cdb2, SCSI_IOCTL_DATA_OUT, data)
        if st2 != 0:
            raise JMS583Error(
                f"JMS583 Write Step 2 failed for OP 0x{opcode:02X}: SCSI 0x{st2:02X}, sense={sense2.hex()}"
            )

        # Step 3: Response (protocol 0x8F)
        cdb3 = bytes([0xA1, 0x8F, 0x00, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0, 0])
        st3, sense3, resp = self._scsi_pass_through(
            cdb3, SCSI_IOCTL_DATA_IN, None, 512
        )
        if st3 != 0 or resp[0:4] != b"NVME":
            raise JMS583Error(
                f"JMS583 Write Step 3 failed for OP 0x{opcode:02X}: SCSI 0x{st3:02X}, hdr={resp[0:4]!r}, sense={sense3.hex()}"
            )

        nvme_result = struct.unpack_from("<I", resp, 8)[0]
        nvme_status = struct.unpack_from("<I", resp, 20)[0] >> 17
        return nvme_status, nvme_result

    def innogrit_nondata(
        self,
        opcode: int,
        nsid: int = 0,
        cdw10: int = 0,
        cdw11: int = 0,
        cdw12: int = 0,
        cdw13: int = 0,
        cdw14: int = GRIT_MAGIC,
        cdw15: int = INNO_MAGIC,
    ) -> tuple[int, int]:
        """Execute a Non-Data NVMe Admin command (including vendor opcodes >= 0xC0)."""
        cdb1 = bytes([0xA1, 0x80, 0x00, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0, 0])
        nvm_cmd = bytearray(512)
        nvm_cmd[0:4] = b"NVME"
        struct.pack_into("<II", nvm_cmd, 8, opcode, nsid)
        struct.pack_into(
            "<IIIIII", nvm_cmd, 48, cdw10, cdw11, cdw12, cdw13, cdw14, cdw15
        )
        st1, sense1, _ = self._scsi_pass_through(
            cdb1, SCSI_IOCTL_DATA_OUT, bytes(nvm_cmd)
        )
        if st1 != 0:
            raise JMS583Error(
                f"JMS583 Non-Data Step 1 failed for OP 0x{opcode:02X}: SCSI 0x{st1:02X}, sense={sense1.hex()}"
            )

        cdb2 = bytes([0xA1, 0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        st2, sense2, _ = self._scsi_pass_through(cdb2, SCSI_IOCTL_DATA_IN, None, 0)
        if st2 != 0:
            raise JMS583Error(
                f"JMS583 Non-Data Step 2 failed for OP 0x{opcode:02X}: SCSI 0x{st2:02X}, sense={sense2.hex()}"
            )

        cdb3 = bytes([0xA1, 0x8F, 0x00, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0, 0])
        st3, sense3, resp = self._scsi_pass_through(
            cdb3, SCSI_IOCTL_DATA_IN, None, 512
        )
        if st3 != 0 or resp[0:4] != b"NVME":
            raise JMS583Error(
                f"JMS583 Non-Data Step 3 failed for OP 0x{opcode:02X}: SCSI 0x{st3:02X}, hdr={resp[0:4]!r}, sense={sense3.hex()}"
            )

        nvme_result = struct.unpack_from("<I", resp, 8)[0]
        nvme_status = struct.unpack_from("<I", resp, 20)[0] >> 17
        return nvme_status, nvme_result


def build_pfct_payload(base_pfct: bytes, capacity_gb: int) -> bytes:
    """Create a 4096B Pfct buffer from a card backup with updated target capacity."""
    if len(base_pfct) != 4096:
        raise ValueError(f"Expected 4096B Pfct buffer, got {len(base_pfct)}")
    buf = bytearray(base_pfct)
    buf[0:5] = b"Pfct\x00"
    struct.pack_into("<H", buf, 0x16, capacity_gb)  # Capacityforset
    struct.pack_into("<H", buf, 0x84, capacity_gb)  # VENDOR_Capacity
    return bytes(buf)


def snapshot_state(dev: JMS583RWDevice) -> dict[str, Any]:
    """Capture current read-only device state for before/after comparison."""
    id_ctrl = dev.identify(cns=1, nsid=0)
    id_ns = dev.identify(cns=0, nsid=1)
    nsze = struct.unpack_from("<Q", id_ns, 0)[0]
    st_f2, _, f2 = dev.innogrit_read(0xF2, cdw10=0x400, size=4096)
    st_f6, _, f6 = dev.innogrit_read(0xF6, cdw10=0x400, size=4096)
    st_fe, _, fe = dev.innogrit_read(0xFE, cdw10=0x400, size=4096)
    return {
        "sn": id_ctrl[4:24].split(b"\x00", 1)[0].decode("ascii", "replace").strip(),
        "mn": id_ctrl[24:64].split(b"\x00", 1)[0].decode("ascii", "replace").strip(),
        "fr": id_ctrl[64:72].split(b"\x00", 1)[0].decode("ascii", "replace").strip(),
        "cfe_0c00": id_ctrl[0x0C00:0x0C10].hex(),
        "cfe_0c77": id_ctrl[0x0C77:0x0C80].hex(),
        "nsze_sectors": nsze,
        "capacity_gb_decimal": round(nsze * 512 / 1e9, 3),
        "f2_status": f"0x{st_f2:02X}",
        "f2_sig": f2[0:4].decode("latin1"),
        "f2_op": f2[0x15],
        "f2_cap_for_set": struct.unpack_from("<H", f2, 0x16)[0],
        "f2_vendor_cap": struct.unpack_from("<H", f2, 0x84)[0],
        "f2_pgcnts": struct.unpack_from("<H", f2, 0x120)[0],
        "f2_slcpgcnts": struct.unpack_from("<H", f2, 0x130)[0],
        "f2_sha256": hashlib.sha256(f2).hexdigest(),
        "f6_status": f"0x{st_f6:02X}",
        "f6_cap_gb": struct.unpack_from("<I", f6, 0x20)[0],
        "fe_status": f"0x{st_fe:02X}",
        "fe_cur_width": fe[0x1C],
        "fe_native_width": fe[0x1D],
    }


def decode_c2_log_events(raw_c2: bytes) -> list[dict[str, Any]]:
    """Extract (mid, level, msg_id, p0..p4) tuples from a raw 0xC2 event log dump."""
    events: list[dict[str, Any]] = []
    if len(raw_c2) < 32 or raw_c2[:4] != b"glve":
        return events
    # glve page entries are 32 bytes each starting at offset 0x20 on page 0
    for off in range(0x20, min(len(raw_c2), 4096) - 31, 32):
        rec = raw_c2[off : off + 32]
        w = struct.unpack_from("<8I", rec, 0)
        if all(x == 0 for x in w):
            continue
        events.append(
            {
                "off": f"0x{off:03x}",
                "ts_lo": w[0],
                "ts_hi": w[1],
                "mod_lvl_mid": f"0x{w[2]:08x}",
                "params": [f"0x{x:08x}" for x in w[3:8]],
            }
        )
    return events


def encode_thumb_bl(src_va: int, dst_va: int) -> bytes:
    """Encode a 32-bit Thumb-2 BL instruction from src_va to dst_va."""
    rel = dst_va - (src_va + 4)
    if not -(1 << 24) <= rel < (1 << 24):
        raise ValueError(f"BL target out of range: rel={rel}")
    s = 1 if rel < 0 else 0
    if s:
        rel += 1 << 25
    i1 = (rel >> 23) & 1
    i2 = (rel >> 22) & 1
    j1 = (~i1 ^ s) & 1
    j2 = (~i2 ^ s) & 1
    imm10 = (rel >> 12) & 0x3FF
    imm11 = (rel >> 1) & 0x7FF
    hw0 = 0xF000 | (s << 10) | imm10
    hw1 = 0xD000 | (j1 << 13) | (j2 << 11) | imm11
    return struct.pack("<HH", hw0, hw1)


def build_cfexpress_identify_stub() -> bytes:
    """Build Thumb-2 stub replacing unused test_and_change_bit to inject CFexpress signatures."""
    stub = bytearray()
    stub.extend(struct.pack("<HH", 0xF887, 0x321A))  # strb.w r3, [r7, #0x21a]
    stub.extend(struct.pack("<HH", 0xF507, 0x6040))  # add.w  r0, r7, #0xc00
    stub.extend(struct.pack("<H", 0xA108))           # adr    r1, [pc, #0x20] (+0x2c)
    stub.extend(struct.pack("<H", 0x2200))           # movs   r2, #0
    stub.extend(struct.pack("<H", 0x5C8B))           # ldrb   r3, [r1, r2]
    stub.extend(struct.pack("<H", 0x5483))           # strb   r3, [r0, r2]
    stub.extend(struct.pack("<H", 0x3201))           # adds   r2, #1
    stub.extend(struct.pack("<H", 0x2A0A))           # cmp    r2, #10
    stub.extend(struct.pack("<H", 0xD1FA))           # bne    -8
    stub.extend(struct.pack("<H", 0x3077))           # adds   r0, #0x77 (r7 + 0xc77)
    stub.extend(struct.pack("<H", 0x2200))           # movs   r2, #0
    stub.extend(struct.pack("<H", 0x5C8B))           # ldrb   r3, [r1, r2]
    stub.extend(struct.pack("<H", 0x5483))           # strb   r3, [r0, r2]
    stub.extend(struct.pack("<H", 0x3201))           # adds   r2, #1
    stub.extend(struct.pack("<H", 0x2A09))           # cmp    r2, #9
    stub.extend(struct.pack("<H", 0xD1FA))           # bne    -8
    stub.extend(struct.pack("<H", 0x4770))           # bx     lr
    stub.extend(struct.pack("<HHH", 0xBF00, 0xBF00, 0xBF00))  # align +0x2c
    stub.extend(b"CFexpress\x01\x00\x00")
    assert len(stub) == 56
    return bytes(stub)


def patch_dslc_fw(src_fw: Path, out_fw: Path) -> dict[str, Any]:
    """Patch a 3.0.0.1S .fw (dslc/pslc/pxlc) for CFexpress Identify and recompute CRC32s."""
    raw = bytearray(src_fw.read_bytes())
    if raw[:4] != b"GRIT":
        raise ValueError(f"Unexpected FW magic {raw[:4]!r} in {src_fw}")

    # Parse ATCM section header (first section, offset 0x10)
    atcm_name = raw[0x10:0x14]
    atcm_foff, atcm_size, atcm_va = struct.unpack_from("<III", raw, 0x14)
    if atcm_name != b"ATCM" or atcm_va != 0:
        raise ValueError(f"Unexpected ATCM header {atcm_name!r}, va=0x{atcm_va:x}")

    hook_ctx_pos = raw.find(ID_HOOK_CONTEXT, atcm_foff, atcm_foff + atcm_size)
    if hook_ctx_pos < 0 or raw.count(ID_HOOK_CONTEXT, atcm_foff, atcm_foff + atcm_size) != 1:
        raise ValueError("Could not uniquely locate Identify Controller hook site")
    id_patch_off = hook_ctx_pos + 8
    id_call_va = atcm_va + (id_patch_off - atcm_foff)
    if bytes(raw[id_patch_off : id_patch_off + 4]) != ID_ORIG_BYTES:
        raise ValueError("Unexpected instruction bytes at Identify hook site")

    stub_off = raw.find(TACB_BYTES, atcm_foff, atcm_foff + atcm_size)
    if stub_off < 0:
        raise ValueError("Could not locate unused test_and_change_bit slot in ATCM")
    stub_va = atcm_va + (stub_off - atcm_foff)

    # Ensure no code/data references the unused test_and_change_bit slot we reuse
    for w in (stub_va, stub_va + 1):
        if raw.count(struct.pack("<I", w)) != 0:
            raise ValueError(f"Unexpected reference to 0x{w:08x} in source FW")

    stub = build_cfexpress_identify_stub()
    bl_bytes = encode_thumb_bl(id_call_va, stub_va)
    raw[id_patch_off : id_patch_off + 4] = bl_bytes
    raw[stub_off : stub_off + len(stub)] = stub
    raw[stub_off + len(stub) : stub_off + 64] = b"\x00" * (64 - len(stub))

    # Recompute GRIT header section-table CRC32 (0x0C, covers 0x10..0xC0)
    sec_cnt = struct.unpack_from("<H", raw, 8)[0]
    table_end = 16 + sec_cnt * 16
    hdr_crc = zlib.crc32(raw[16:table_end]) & 0xFFFFFFFF
    struct.pack_into("<I", raw, 0x0C, hdr_crc)

    # Recompute trailing YCHU whole-image CRC32 (`fw_verify_image`)
    trailer_off = raw.find(TRAILER_MAGIC)
    if trailer_off < 0:
        raise ValueError("YCHU trailer magic not found in source FW")
    full_crc = zlib.crc32(raw[:trailer_off]) & 0xFFFFFFFF
    struct.pack_into("<I", raw, trailer_off + 0x0C, full_crc)

    out_fw.parent.mkdir(parents=True, exist_ok=True)
    out_fw.write_bytes(bytes(raw))
    return {
        "src_fw": str(src_fw),
        "out_fw": str(out_fw),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "id_call_va": f"0x{id_call_va:06x}",
        "stub_va": f"0x{stub_va:06x}",
        "grit_header_crc32": f"0x{hdr_crc:08x}",
        "trailer_offset": f"0x{trailer_off:06x}",
        "trailer_full_crc32": f"0x{full_crc:08x}",
        "hook_bl_hex": bl_bytes.hex(),
        "stub_len": len(stub),
    }


def _flush_report(path: Path, report: dict[str, Any]) -> None:
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def run_phase3b(
    device_path: str,
    backup_dir: Path,
    work_dir: Path,
    target_gb: int = 480,
    mode: str = "dslc",
) -> dict[str, Any]:
    """Phase 3B: Flash patched CFexpress firmware (dslc/pslc/pxlc) + write Pfct + FTL virgin."""
    work_dir.mkdir(parents=True, exist_ok=True)
    src_fw = FW_MODE_MAP[mode]
    patched_fw_path = work_dir / f"ftkdisk_mu_single_lun_hmb_{mode}_cfe_{target_gb}g.fw"
    patch_meta = patch_dslc_fw(src_fw, patched_fw_path)
    fw_bytes = patched_fw_path.read_bytes()

    orig_f2 = (backup_dir / "f2_pfct.bin").read_bytes()
    pfct_payload = build_pfct_payload(orig_f2, target_gb)
    (work_dir / f"pfct_{target_gb}g.bin").write_bytes(pfct_payload)

    report_path = work_dir / f"phase3b_{mode}_report.json"
    report: dict[str, Any] = {
        "mode": mode,
        "target_gb": target_gb,
        "patch_meta": patch_meta,
        "steps": {},
    }

    with JMS583RWDevice(device_path) as dev:
        before = snapshot_state(dev)
        report["before"] = before
        if before["sn"] != backup_dir.name:
            raise JMS583Error(
                f"Device SN {before['sn']!r} does not match backup dir {backup_dir.name!r}"
            )
        _flush_report(report_path, report)

        # Step 1: NVMe Firmware Image Download (0x11) in 4KB chunks
        chunk_sz = 4096
        dl_errors: list[dict[str, Any]] = []
        chunks_sent = 0
        for off in range(0, len(fw_bytes), chunk_sz):
            chunk = fw_bytes[off : off + chunk_sz]
            numd = (len(chunk) // 4) - 1
            ofst_dw = off // 4
            st, res = dev.nvme_admin_write(
                0x11, chunk, nsid=0, cdw10=numd, cdw11=ofst_dw
            )
            chunks_sent += 1
            if st != 0:
                dl_errors.append(
                    {"offset": off, "status": f"0x{st:02X}", "result": f"0x{res:08X}"}
                )
                break
        report["steps"]["0x11_fw_download"] = {
            "chunks_sent": chunks_sent,
            "total_bytes": len(fw_bytes),
            "errors": dl_errors,
        }
        _flush_report(report_path, report)
        if dl_errors:
            raise JMS583Error(f"0x11 FW download failed: {dl_errors[0]}")

        # Step 2: NVMe Firmware Commit (0x10), Slot=1, CA=1 (Activate on next reset)
        st_10, res_10 = dev.innogrit_nondata(
            0x10, nsid=0, cdw10=0x09, cdw14=0, cdw15=0
        )
        report["steps"]["0x10_fw_commit"] = {
            "cdw10": "0x00000009",
            "nvme_status": f"0x{st_10:02X}",
            "nvme_result": f"0x{res_10:08X}",
        }
        _flush_report(report_path, report)
        if st_10 != 0:
            raise JMS583Error(f"0x10 FW commit failed: status=0x{st_10:02X}")

        # Step 3: Refresh 480GB Pfct (0xF1)
        st_f1, res_f1 = dev.nvme_admin_write(
            0xF1,
            pfct_payload,
            nsid=0,
            cdw10=0x400,
            cdw14=GRIT_MAGIC,
            cdw15=INNO_MAGIC,
        )
        c2_before_virgin = collect_c2_event_log(dev)
        (work_dir / "c2_phase3b_before_virgin.bin").write_bytes(c2_before_virgin)
        report["steps"]["0xF1_setfactoryinfo"] = {
            "nvme_status": f"0x{st_f1:02X}",
            "nvme_result": f"0x{res_f1:08X}",
            "c2_tail_events": decode_c2_log_events(c2_before_virgin)[-10:],
        }
        _flush_report(report_path, report)

        # Step 4: Trigger FTL Virgin boot (0xF0) so new DSLC firmware builds fresh 480GB TLC FTL on replug
        try:
            st_f0, res_f0 = dev.innogrit_nondata(
                0xF0, nsid=0, cdw14=GRIT_MAGIC, cdw15=INNO_MAGIC
            )
            report["steps"]["0xF0_ftl_virgin"] = {
                "nvme_status": f"0x{st_f0:02X}",
                "nvme_result": f"0x{res_f0:08X}",
            }
        except JMS583Error as exc:
            report["steps"]["0xF0_ftl_virgin"] = {
                "note_reset_on_virgin": str(exc),
            }
        _flush_report(report_path, report)

    return report


def run_phase3a(
    device_path: str, backup_dir: Path, work_dir: Path, target_gb: int = 480
) -> dict[str, Any]:
    """Phase 3A: Test non-destructive Pfct (0xF1) + FTL virgin (0xF0) + reboot on stock VB05."""
    work_dir.mkdir(parents=True, exist_ok=True)
    orig_f2 = (backup_dir / "f2_pfct.bin").read_bytes()
    test_pfct = build_pfct_payload(orig_f2, target_gb)
    (work_dir / f"pfct_{target_gb}g.bin").write_bytes(test_pfct)

    report_path = work_dir / "phase3a_report.json"
    report: dict[str, Any] = {"target_gb": target_gb, "steps": {}}

    with JMS583RWDevice(device_path) as dev:
        before = snapshot_state(dev)
        report["before"] = before
        if before["sn"] != backup_dir.name:
            raise JMS583Error(
                f"Device SN {before['sn']!r} does not match backup dir {backup_dir.name!r}"
            )
        _flush_report(report_path, report)

        # Step 1: 0xF1 SetFactoryInfo with Capacityforset = target_gb
        st_f1, res_f1 = dev.nvme_admin_write(
            0xF1,
            test_pfct,
            nsid=0,
            cdw10=0x400,
            cdw14=GRIT_MAGIC,
            cdw15=INNO_MAGIC,
        )
        after_f1 = snapshot_state(dev)
        c2_after_f1 = collect_c2_event_log(dev)
        (work_dir / "c2_after_f1.bin").write_bytes(c2_after_f1)
        report["steps"]["0xF1_setfactoryinfo"] = {
            "nvme_status": f"0x{st_f1:02X}",
            "nvme_result": f"0x{res_f1:08X}",
            "state": after_f1,
            "c2_tail_events": decode_c2_log_events(c2_after_f1)[-8:],
        }
        _flush_report(report_path, report)

        # Step 2: 0xF0 FTL Virgin boot flag
        try:
            st_f0, res_f0 = dev.innogrit_nondata(
                0xF0, nsid=0, cdw14=GRIT_MAGIC, cdw15=INNO_MAGIC
            )
            report["steps"]["0xF0_ftl_virgin"] = {
                "nvme_status": f"0x{st_f0:02X}",
                "nvme_result": f"0x{res_f0:08X}",
            }
        except JMS583Error as exc:
            report["steps"]["0xF0_ftl_virgin"] = {"exception": str(exc)}
        _flush_report(report_path, report)

    return report


def verify_card(device_path: str, orig_backup_dir: Path) -> dict[str, Any]:
    """Read-only post-conversion verification against original factory backup."""
    with JMS583RWDevice(device_path) as dev:
        snap = snapshot_state(dev)
        id_ctrl = dev.identify(cns=1, nsid=0)
        smart = dev.get_log_page(0x02, size=512)
        smart_sum = parse_smart_summary(smart)
        _, _, ca = dev.innogrit_read(0xCA, cdw10=0x400, size=4096)
        _, _, ce = dev.innogrit_read(0xCE, cdw10=0x400, size=4096)
        _, c6_entries = collect_c6_superblocks(dev)

    orig_id = (orig_backup_dir / "id_ctrl.bin").read_bytes()
    orig_ce = (orig_backup_dir / "ce_bad_sb.bin").read_bytes()
    ce_cnt = struct.unpack_from("<I", ce, 0)[0]
    orig_ce_cnt = struct.unpack_from("<I", orig_ce, 0)[0]
    ce_valid_len = 4 + min(ce_cnt, orig_ce_cnt) * 12

    sb_by_type: dict[str, int] = {}
    for entry in c6_entries:
        t = f"0x{entry['type']:02x}"
        sb_by_type[t] = sb_by_type.get(t, 0) + 1

    return {
        "snapshot": snap,
        "smart": smart_sum,
        "fw_banner": "".join(chr(b) if 32 <= b < 127 else " " for b in ca[:96]).strip(),
        "cfe_0c00_preserved": id_ctrl[0x0C00:0x0C10] == orig_id[0x0C00:0x0C10],
        "cfe_0c70_preserved": id_ctrl[0x0C70:0x0C80] == orig_id[0x0C70:0x0C80],
        "factory_bad_sb_count": ce_cnt,
        "factory_bad_sb_exact_match": ce_cnt == orig_ce_cnt
        and ce[:ce_valid_len] == orig_ce[:ce_valid_len],
        "superblocks_by_type": sb_by_type,
    }


def convert_new_card(
    device_path: str,
    backup_root: Path,
    work_root: Path,
    target_gb: int = 480,
    mode: str = "dslc",
) -> dict[str, Any]:
    """Full end-to-end backup + verification + conversion for an identical IG5208 card."""
    with JMS583RWDevice(device_path) as dev:
        id_ctrl = dev.identify(cns=1, nsid=0)
        vid, ssvid = struct.unpack_from("<HH", id_ctrl, 0)
        if (vid, ssvid) != (0x1DBE, 0x5208):
            raise JMS583Error(
                f"Unexpected PCI VID/SSVID 0x{vid:04X}/0x{ssvid:04X}; expected IG5208 (0x1DBE/0x5208)"
            )
        _, _, f6 = dev.innogrit_read(0xF6, cdw10=0x400, size=4096)
        flash_id = bytes(struct.unpack_from("<5I", f6, 0x24))
        if flash_id != EXPECTED_B17A_ID:
            raise JMS583Error(
                f"Unexpected NAND Flash ID {flash_id.hex(' ')}; expected B17A {EXPECTED_B17A_ID.hex(' ')}"
            )

    backup_dir = backup_card(device_path, backup_root)
    work_dir = work_root / backup_dir.name
    phase3b_res = run_phase3b(
        device_path, backup_dir, work_dir, target_gb=target_gb, mode=mode
    )
    return {
        "backup_dir": str(backup_dir),
        "work_dir": str(work_dir),
        "phase3b": phase3b_res,
    }


def _resolve_sn_dirs(
    device_path: str,
    backup_root: Path,
    work_root: Path,
    backup_dir: Path | None,
    work_dir: Path | None,
) -> tuple[Path, Path]:
    if backup_dir is not None and work_dir is not None:
        return backup_dir, work_dir
    with JMS583RWDevice(device_path) as dev:
        sn = dev.identify(cns=1, nsid=0)[4:24].split(b"\x00", 1)[0].decode("ascii", "replace").strip()
    if not sn:
        raise JMS583Error("Could not read serial number from device; pass --backup-dir/--work-dir explicitly")
    return backup_dir or (backup_root / sn), work_dir or (work_root / sn)


def main() -> None:
    parser = argparse.ArgumentParser(description="IG5208 CFexpress TLC conversion tool")
    parser.add_argument(
        "--action",
        choices=[
            "patch_dslc",
            "patch_fw",
            "phase3a",
            "phase3b",
            "convert_new_card",
            "verify",
            "snapshot",
        ],
        required=True,
    )
    parser.add_argument("--mode", choices=["dslc", "pslc", "pxlc"], default="dslc")
    parser.add_argument("--device", default=r"\\.\F:")
    parser.add_argument("--backup-dir", type=Path, default=None)
    parser.add_argument("--backup-root", type=Path, default=REPO_ROOT / "backups")
    parser.add_argument("--work-dir", type=Path, default=None)
    parser.add_argument("--work-root", type=Path, default=REPO_ROOT / "work")
    parser.add_argument("--target-gb", type=int, default=480)
    args = parser.parse_args()

    if args.action in ("patch_dslc", "patch_fw"):
        out_base = args.work_dir or (args.work_root / "patched_fw")
        out_fw = out_base / f"ftkdisk_mu_single_lun_hmb_{args.mode}_cfe_{args.target_gb}g.fw"
        print(json.dumps(patch_dslc_fw(FW_MODE_MAP[args.mode], out_fw), indent=2))
    elif args.action == "snapshot":
        with JMS583RWDevice(args.device) as dev:
            print(json.dumps(snapshot_state(dev), indent=2))
    elif args.action == "verify":
        bdir, _ = _resolve_sn_dirs(
            args.device, args.backup_root, args.work_root, args.backup_dir, args.work_dir
        )
        print(json.dumps(verify_card(args.device, bdir), indent=2))
    elif args.action == "phase3a":
        bdir, wdir = _resolve_sn_dirs(
            args.device, args.backup_root, args.work_root, args.backup_dir, args.work_dir
        )
        res = run_phase3a(args.device, bdir, wdir, args.target_gb)
        print(json.dumps(res, indent=2))
    elif args.action == "phase3b":
        bdir, wdir = _resolve_sn_dirs(
            args.device, args.backup_root, args.work_root, args.backup_dir, args.work_dir
        )
        res = run_phase3b(args.device, bdir, wdir, args.target_gb, mode=args.mode)
        print(json.dumps(res, indent=2))
    elif args.action == "convert_new_card":
        res = convert_new_card(
            args.device,
            args.backup_root,
            args.work_root,
            target_gb=args.target_gb,
            mode=args.mode,
        )
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
