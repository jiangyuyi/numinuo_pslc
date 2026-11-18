"""Read-only backup utility for Innogrit IG5208 CFA cards behind a JMicron JMS583 bridge."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GRIT_MAGIC = 0x54495247  # "GRIT"
INNO_MAGIC = 0x4F4E4E49  # "INNO"

IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3

SCSI_IOCTL_DATA_OUT = 0
SCSI_IOCTL_DATA_IN = 1
SCSI_IOCTL_DATA_UNSPECIFIED = 2


class JMS583Error(RuntimeError):
    """Raised when a SCSI pass-through or NVMe command fails."""


class JMS583Device:
    """Read-only NVMe Admin Data-In pass-through interface over JMicron JMS583 (0xA1)."""

    def __init__(self, device_path: str = r"\\.\F:") -> None:
        self.device_path = device_path
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._handle: int | None = None

    def __enter__(self) -> JMS583Device:
        handle = self._kernel32.CreateFileW(
            self.device_path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle in (-1, 0xFFFFFFFFFFFFFFFF):
            err = ctypes.get_last_error()
            raise JMS583Error(f"Failed to open {self.device_path}: Win32 error {err}")
        self._handle = handle
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._handle is not None:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None

    def _scsi_pass_through(
        self, cdb: bytes, data_dir: int, buf: bytes | None = None, buf_len: int = 0
    ) -> tuple[int, bytes, bytes]:
        if self._handle is None:
            raise JMS583Error("Device handle is not open")

        if buf is not None:
            data_buf = ctypes.create_string_buffer(buf, len(buf))
            buf_len = len(buf)
        elif buf_len > 0:
            data_buf = ctypes.create_string_buffer(buf_len)
        else:
            data_buf = None

        # 64-bit SCSI_PASS_THROUGH_DIRECT layout (56 bytes) + sense buffer at offset 64
        sptd = ctypes.create_string_buffer(128)
        cdb_padded = cdb.ljust(16, b"\x00")
        struct.pack_into(
            "<HBBBBBBB3xII4xQI16s4x",
            sptd,
            0,
            56,
            0,
            0,
            0,
            0,
            len(cdb),
            32,
            data_dir,
            buf_len,
            10,
            ctypes.addressof(data_buf) if data_buf else 0,
            64,
            cdb_padded,
        )
        bytes_ret = ctypes.c_ulong(0)
        ok = self._kernel32.DeviceIoControl(
            self._handle,
            IOCTL_SCSI_PASS_THROUGH_DIRECT,
            sptd,
            128,
            sptd,
            128,
            ctypes.byref(bytes_ret),
            None,
        )
        if not ok:
            err = ctypes.get_last_error()
            raise JMS583Error(
                f"DeviceIoControl failed for CDB {cdb.hex()}: Win32 error {err}"
            )
        scsi_status = sptd.raw[2]
        sense = sptd.raw[64:96]
        out_data = data_buf.raw if data_buf else b""
        return scsi_status, sense, out_data

    def nvme_admin_read(
        self,
        opcode: int,
        nsid: int = 0,
        cdw10: int = 0,
        cdw11: int = 0,
        cdw12: int = 0,
        cdw13: int = 0,
        cdw14: int = 0,
        cdw15: int = 0,
        size: int = 4096,
    ) -> tuple[int, int, bytes]:
        """Execute a Data-In NVMe Admin command through JMS583 0xA1 tunnel."""
        if size <= 0 or size > 0xFFFFFF:
            raise ValueError(f"Invalid Data-In size: {size}")

        # Step 1: Send 512B NVM Command Set Payload (protocol 0x80 = Admin + NVM_CMD)
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
                f"JMS583 Step 1 failed for OP 0x{opcode:02X}: SCSI status 0x{st1:02X}, sense={sense1.hex()}"
            )

        # Step 2: Data-In DMA transfer (protocol 0x82 = Admin + DMA_IN)
        cdb2 = bytes(
            [
                0xA1,
                0x82,
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
        st2, sense2, data = self._scsi_pass_through(
            cdb2, SCSI_IOCTL_DATA_IN, None, size
        )
        if st2 != 0:
            raise JMS583Error(
                f"JMS583 Step 2 failed for OP 0x{opcode:02X}: SCSI status 0x{st2:02X}, sense={sense2.hex()}"
            )

        # Step 3: Return Response Information (protocol 0x8F = Admin + RESPONSE)
        cdb3 = bytes([0xA1, 0x8F, 0x00, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0, 0])
        st3, sense3, resp = self._scsi_pass_through(
            cdb3, SCSI_IOCTL_DATA_IN, None, 512
        )
        if st3 != 0 or resp[0:4] != b"NVME":
            raise JMS583Error(
                f"JMS583 Step 3 failed for OP 0x{opcode:02X}: SCSI status 0x{st3:02X}, hdr={resp[0:4]!r}, sense={sense3.hex()}"
            )

        nvme_result = struct.unpack_from("<I", resp, 8)[0]
        nvme_status = struct.unpack_from("<I", resp, 20)[0] >> 17
        return nvme_status, nvme_result, data

    def nvme_admin_non_data(
        self,
        opcode: int,
        nsid: int = 0,
        cdw10: int = 0,
        cdw11: int = 0,
        cdw12: int = 0,
        cdw13: int = 0,
        cdw14: int = 0,
        cdw15: int = 0,
    ) -> tuple[int, int]:
        """Execute a standard Non-Data NVMe Admin command (e.g. Get Features 0x0A)."""
        if opcode >= 0xC0:
            raise JMS583Error(
                f"Refusing vendor Non-Data command 0x{opcode:02X} in read-only mode"
            )
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
                f"JMS583 Non-Data Step 1 failed: SCSI status 0x{st1:02X}, sense={sense1.hex()}"
            )

        cdb2 = bytes([0xA1, 0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        st2, sense2, _ = self._scsi_pass_through(cdb2, SCSI_IOCTL_DATA_IN, None, 0)
        if st2 != 0:
            raise JMS583Error(
                f"JMS583 Non-Data Step 2 failed: SCSI status 0x{st2:02X}, sense={sense2.hex()}"
            )

        cdb3 = bytes([0xA1, 0x8F, 0x00, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0, 0])
        st3, _, resp = self._scsi_pass_through(cdb3, SCSI_IOCTL_DATA_IN, None, 512)
        if st3 != 0 or resp[0:4] != b"NVME":
            raise JMS583Error(f"JMS583 Non-Data Step 3 failed: SCSI status 0x{st3:02X}")

        nvme_result = struct.unpack_from("<I", resp, 8)[0]
        nvme_status = struct.unpack_from("<I", resp, 20)[0] >> 17
        return nvme_status, nvme_result

    def identify(self, cns: int, nsid: int = 0) -> bytes:
        st, _, data = self.nvme_admin_read(0x06, nsid=nsid, cdw10=cns, size=4096)
        if st != 0:
            raise JMS583Error(f"Identify (CNS={cns}, NSID={nsid}) returned NVMe status 0x{st:02X}")
        return data

    def get_log_page(self, lid: int, size: int = 512, nsid: int = 0xFFFFFFFF) -> bytes:
        numdl = (size // 4) - 1
        cdw10 = (lid & 0xFF) | ((numdl & 0xFFFF) << 16)
        cdw11 = (numdl >> 16) & 0xFFFF
        st, _, data = self.nvme_admin_read(
            0x02, nsid=nsid, cdw10=cdw10, cdw11=cdw11, size=size
        )
        if st != 0:
            raise JMS583Error(f"GetLogPage (LID=0x{lid:02X}) returned NVMe status 0x{st:02X}")
        return data

    def innogrit_read(
        self,
        opcode: int,
        cdw10: int = 0x400,
        cdw11: int = 0,
        cdw12: int = 0,
        cdw13: int = 0,
        size: int = 4096,
    ) -> tuple[int, int, bytes]:
        """Execute a strictly read-only (Data-In, opcode & 3 == 2) Innogrit vendor command."""
        if opcode < 0xC0 or (opcode & 0x03) != 0x02:
            raise ValueError(
                f"Opcode 0x{opcode:02X} is not a standard NVMe Data-In vendor opcode (bit[1:0] != 2)"
            )
        return self.nvme_admin_read(
            opcode,
            nsid=0,
            cdw10=cdw10,
            cdw11=cdw11,
            cdw12=cdw12,
            cdw13=cdw13,
            cdw14=GRIT_MAGIC,
            cdw15=INNO_MAGIC,
            size=size,
        )


def parse_smart_summary(smart: bytes) -> dict[str, int]:
    """Decode key standard NVMe SMART / Health Information fields."""
    temp_k = struct.unpack_from("<H", smart, 1)[0]
    return {
        "critical_warning": smart[0],
        "temperature_k": temp_k,
        "temperature_c": temp_k - 273,
        "available_spare_pct": smart[3],
        "spare_threshold_pct": smart[4],
        "percentage_used": smart[5],
        "data_units_read": int.from_bytes(smart[32:48], "little"),
        "data_units_written": int.from_bytes(smart[48:64], "little"),
        "power_cycles": int.from_bytes(smart[112:128], "little"),
        "power_on_hours": int.from_bytes(smart[128:144], "little"),
        "unsafe_shutdowns": int.from_bytes(smart[144:160], "little"),
        "media_errors": int.from_bytes(smart[160:176], "little"),
        "error_log_entries": int.from_bytes(smart[176:192], "little"),
    }


def collect_c6_superblocks(dev: JMS583Device, max_pages: int = 10) -> tuple[bytes, list[dict[str, int]]]:
    """Synchronize the 0xC6 cursor to page 0 and collect all Superblock entries."""
    # First advance until count == 0 so the next call starts at page 0.
    for _ in range(max_pages):
        st, _, data = dev.innogrit_read(0xC6, cdw10=0x400, size=4096)
        if st != 0:
            raise JMS583Error(f"0xC6 sync failed with NVMe status 0x{st:02X}")
        cnt = struct.unpack_from("<I", data, 0)[0]
        if cnt == 0:
            break
    else:
        raise JMS583Error("0xC6 cursor did not reset within max_pages")

    entries_raw = bytearray()
    entries_parsed: list[dict[str, int]] = []
    idx = 0
    for _ in range(max_pages):
        st, _, data = dev.innogrit_read(0xC6, cdw10=0x400, size=4096)
        if st != 0:
            raise JMS583Error(f"0xC6 read failed with NVMe status 0x{st:02X}")
        cnt = struct.unpack_from("<I", data, 0)[0]
        if cnt == 0:
            break
        if cnt > 341:
            raise JMS583Error(f"Unexpected 0xC6 entry count {cnt} > 341")
        for i in range(cnt):
            off = 4 + i * 12
            chunk = data[off : off + 12]
            entries_raw.extend(chunk)
            w0, w1, w2 = struct.unpack_from("<III", chunk, 0)
            entries_parsed.append(
                {
                    "sb": idx,
                    "type": (w0 >> 24) & 0xFF,
                    "erase_count": w0 & 0x00FFFFFF,
                    "w0_hex": f"0x{w0:08x}",
                    "w1_hex": f"0x{w1:08x}",
                    "w2_hex": f"0x{w2:08x}",
                }
            )
            idx += 1

    packed = struct.pack("<I", len(entries_parsed)) + bytes(entries_raw)
    return packed, entries_parsed


def collect_c2_event_log(dev: JMS583Device, max_pages: int = 16) -> bytes:
    """Synchronize to the 'glve' header page of 0xC2 and read one full cycle."""
    pages: list[bytes] = []
    started = False
    for _ in range(max_pages):
        st, _, data = dev.innogrit_read(0xC2, cdw10=0x400, size=4096)
        if st != 0:
            raise JMS583Error(f"0xC2 read failed with NVMe status 0x{st:02X}")
        is_hdr = data[:4] == b"glve"
        if not started:
            if is_hdr:
                started = True
                pages.append(data)
        else:
            if is_hdr:
                break
            pages.append(data)
    if not pages:
        # Fallback: capture whatever was returned on a single call
        _, _, data = dev.innogrit_read(0xC2, cdw10=0x400, size=4096)
        pages.append(data)
    return b"".join(pages)


def write_with_hash(path: Path, data: bytes) -> dict[str, Any]:
    path.write_bytes(data)
    return {
        "file": path.name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def backup_card(device_path: str, backup_root: Path) -> Path:
    with JMS583Device(device_path) as dev:
        id_ctrl = dev.identify(cns=1, nsid=0)
        vid, ssvid = struct.unpack_from("<HH", id_ctrl, 0)
        sn = id_ctrl[4:24].split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()
        mn = id_ctrl[24:64].split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()
        fr = id_ctrl[64:72].split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()
        tnvmcap = int.from_bytes(id_ctrl[280:296], "little")

        if not sn:
            raise JMS583Error("Identify Controller returned empty serial number")

        out_dir = backup_root / sn
        out_dir.mkdir(parents=True, exist_ok=True)

        files_meta: list[dict[str, Any]] = []
        files_meta.append(write_with_hash(out_dir / "id_ctrl.bin", id_ctrl))

        id_ns = dev.identify(cns=0, nsid=1)
        files_meta.append(write_with_hash(out_dir / "id_ns.bin", id_ns))

        smart_before = dev.get_log_page(0x02, size=512)
        files_meta.append(write_with_hash(out_dir / "smart.bin", smart_before))

        fw_log = dev.get_log_page(0x03, size=512)
        files_meta.append(write_with_hash(out_dir / "fw_log.bin", fw_log))

        cel_log = dev.get_log_page(0x05, size=4096)
        files_meta.append(write_with_hash(out_dir / "nvme_cel.bin", cel_log))

        single_vendor_reads = [
            (0xF2, "f2_pfct.bin"),
            (0xCE, "ce_bad_sb.bin"),
            (0xCA, "ca_fw_banner.bin"),
            (0xD2, "d2_codename.bin"),
            (0xD6, "d6_fw_sram_leak.bin"),
            (0xF6, "f6_nand_geom.bin"),
            (0xFA, "fa_internal_smart.bin"),
            (0xFE, "fe_fw_summary.bin"),
        ]
        for op, fname in single_vendor_reads:
            st, nres, data = dev.innogrit_read(op, cdw10=0x400, size=4096)
            if st != 0:
                raise JMS583Error(
                    f"Vendor read 0x{op:02X} failed with NVMe status 0x{st:02X}"
                )
            entry = write_with_hash(out_dir / fname, data)
            entry["opcode"] = f"0x{op:02X}"
            entry["nvme_result"] = f"0x{nres:08X}"
            files_meta.append(entry)

        c6_packed, c6_parsed = collect_c6_superblocks(dev)
        c6_bin_meta = write_with_hash(out_dir / "c6_sb_full.bin", c6_packed)
        c6_bin_meta["superblock_count"] = len(c6_parsed)
        files_meta.append(c6_bin_meta)

        c6_json_bytes = json.dumps(c6_parsed, indent=2).encode("utf-8")
        files_meta.append(write_with_hash(out_dir / "c6_superblocks_full.json", c6_json_bytes))

        c2_log = collect_c2_event_log(dev)
        files_meta.append(write_with_hash(out_dir / "c2_event_log.bin", c2_log))

        smart_after = dev.get_log_page(0x02, size=512)
        smart_summary = parse_smart_summary(smart_after)

        manifest = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "device_path": device_path,
            "controller": {
                "vid": f"0x{vid:04X}",
                "ssvid": f"0x{ssvid:04X}",
                "model": mn,
                "serial": sn,
                "firmware": fr,
                "total_nvm_capacity_bytes": tnvmcap,
                "cfexpress_sig_0c00": id_ctrl[0x0C00:0x0C10].hex(),
                "cfexpress_sig_0c70": id_ctrl[0x0C70:0x0C80].hex(),
            },
            "smart_summary": smart_summary,
            "superblocks_collected": len(c6_parsed),
            "files": files_meta,
        }
        (out_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        return out_dir


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read-only backup of Innogrit IG5208 CFA card via JMS583."
    )
    parser.add_argument(
        "--device",
        default=r"\\.\F:",
        help=r"Windows device or volume path (default: \\.\F:)",
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "backups",
        help="Root directory for card backups",
    )
    args = parser.parse_args()

    out_dir = backup_card(args.device, args.backup_dir)
    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    print(f"Backup completed: {out_dir}")
    print(f"Controller: {manifest['controller']}")
    print(f"Superblocks collected: {manifest['superblocks_collected']}")
    print(f"SMART after backup: {manifest['smart_summary']}")
    print(f"Files ({len(manifest['files'])}):")
    for f in manifest["files"]:
        print(f"  {f['file']:28s} {f['size']:6d} B  sha256={f['sha256'][:16]}...")


if __name__ == "__main__":
    main()
