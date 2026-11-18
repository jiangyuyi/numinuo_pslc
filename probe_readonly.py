"""Safely probe read-only Data-In Innogrit vendor opcodes across CDW11/CDW12/CDW13."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from backup_card import JMS583Device

READONLY_OPCODES = (0xF2, 0xF6, 0xFA, 0xFE, 0xCA, 0xCE, 0xD2, 0xD6)


def probe_opcodes(
    device_path: str, out_dir: Path, param_range: range = range(1, 9)
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    probed_blobs_dir = out_dir / "probed"
    probed_blobs_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, Any] = {"device_path": device_path, "opcodes": {}}

    with JMS583Device(device_path) as dev:
        for op in READONLY_OPCODES:
            st0, res0, base_data = dev.innogrit_read(op, cdw10=0x400, size=4096)
            base_sha = hashlib.sha256(base_data).hexdigest()
            base_head_sha = hashlib.sha256(base_data[:512]).hexdigest()

            op_report: dict[str, Any] = {
                "baseline": {
                    "nvme_status": f"0x{st0:02X}",
                    "nvme_result": f"0x{res0:08X}",
                    "sha256": base_sha,
                    "head512_sha256": base_head_sha,
                    "head64_hex": base_data[:64].hex(),
                },
                "distinct": [],
                "identical_count": 0,
            }

            seen_heads = {base_head_sha}
            for param_name in ("cdw11", "cdw12", "cdw13"):
                for val in param_range:
                    kwargs = {"cdw11": 0, "cdw12": 0, "cdw13": 0}
                    kwargs[param_name] = val
                    st, res, data = dev.innogrit_read(
                        op, cdw10=0x400, size=4096, **kwargs
                    )
                    sha = hashlib.sha256(data).hexdigest()
                    head_sha = hashlib.sha256(data[:512]).hexdigest()

                    if st == st0 and res == res0 and sha == base_sha:
                        op_report["identical_count"] += 1
                        continue

                    # Notice some commands return dynamic SRAM tail or counters;
                    # classify whether head512 or status/result actually changed.
                    head_changed = head_sha != base_head_sha
                    entry: dict[str, Any] = {
                        "param": param_name,
                        "value": val,
                        "nvme_status": f"0x{st:02X}",
                        "nvme_result": f"0x{res:08X}",
                        "head_changed": head_changed,
                        "sha256": sha,
                        "head64_hex": data[:64].hex(),
                    }
                    if head_changed and head_sha not in seen_heads:
                        seen_heads.add(head_sha)
                        blob_name = f"op_{op:02x}_{param_name}_{val}.bin"
                        (probed_blobs_dir / blob_name).write_bytes(data)
                        entry["saved_blob"] = blob_name
                    op_report["distinct"].append(entry)

            results["opcodes"][f"0x{op:02X}"] = op_report

    (out_dir / "probe_readonly_results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Probe read-only Innogrit Data-In vendor commands across CDW11/12/13."
    )
    parser.add_argument("--device", default=r"\\.\F:")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "backups" / "default",
    )
    args = parser.parse_args()

    results = probe_opcodes(args.device, args.out_dir)
    for op_hex, info in results["opcodes"].items():
        distinct = info["distinct"]
        head_changes = [d for d in distinct if d["head_changed"]]
        print(
            f"{op_hex}: baseline st={info['baseline']['nvme_status']} res={info['baseline']['nvme_result']} | "
            f"identical={info['identical_count']}, full_diff={len(distinct)}, head512_diff={len(head_changes)}"
        )
        for d in head_changes:
            print(
                f"    -> {d['param']}={d['value']}: st={d['nvme_status']} res={d['nvme_result']} "
                f"head={d['head64_hex'][:48]}... blob={d.get('saved_blob')}"
            )


if __name__ == "__main__":
    main()
