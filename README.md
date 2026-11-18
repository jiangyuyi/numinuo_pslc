# numinuo_pslc

> 针对 **InnoGrit IG5208 (`Shasta`) + Intel B17A (64L 3D TLC)** CFexpress Type A 存储卡（如 `NUMINUO CFEA-PLUS` 160GB pSLC 版）的无拆机在线分析、只读备份、**160GB pSLC → 480GB TLC (`DSLC`/`pXLC`)** 固件转换、**`CFexpress` 相机签名补丁**及安全校验工具集。

仓库地址：[`jiangyuyi/numinuo_pslc`](https://github.com/jiangyuyi/numinuo_pslc)

---

## 功能特性

- **纯标准库穿透 JMicron JMS583 USB 读卡器**：通过 Windows `IOCTL_SCSI_PASS_THROUGH_DIRECT (0x4D014)` 与 JMS583 `0xA1` NVMe 隧道协议（`0x80 / 0x81 / 0x82 / 0x83 / 0x8F`）与 IG5208 主控通信。在磁盘存在分配盘符（如 `\\.\F:`）时，**无需管理员权限**即可读写所有 NVMe Admin 与 InnoGrit 厂商私有指令。
- **全量只读备份与安全核对 ([backup_card.py](backup_card.py))**：一键导出 `Identify Controller/Namespace`、`SMART`、`CEL`、`Pfct (0xF2)` 产测参数与坏块表、`0xCE` 出厂坏超级块、`0xC6` 全量 504 个超级块擦写与类型分布、`0xC2` 启动事件日志、`0xCA` 固件 Banner 及 `0xD6` SRAM 诊断槽，并生成 `manifest.json` SHA-256 校验清单。
- **纯 Python ARM Thumb-2 离线分析 ([analyze_firmware.py](analyze_firmware.py))**：无需外部逆向工具即可对导出的 `0xD6` SRAM 代码段进行 Thumb-16/Thumb-2 反汇编、超级块/OP 容量核算及出厂坏块交叉验证，生成结构化分析报告。
- **量产包解包与二进制校验 ([inspect_fw_package.py](inspect_fw_package.py))**：支持自动剥离量产论坛常见 131 字节（`0x83`）防盗链前缀头，提取并解析 InnoGrit `.fw` (`GRIT` / `CMFG`) 镜像分区、Flash ID 表（匹配 Intel B17A `89 C4 08 32 A6 00`）、`.sav` 产测文件与 PE 工具导出的私有指令桩。
- **`CFexpress` 签名动态补丁与一键转换 ([phase3_convert.py](phase3_convert.py))**：
  - 将官方 `igu1.0.0.8` 中的 `3.0.0.1S` TLC 固件（`DSLC` 动态 SLC 缓存版 / `pXLC` 纯 TLC 版 / `pSLC` 回滚版）通过 `ATCM` 空闲槽位注入 56 字节 Thumb-2 补丁，在 `Identify Controller` `0x0C00` 与 `0x0C77` 填入相机认证所需的 `CFexpress\x01` / `CFexpress` 签名；
  - 自动重算 `GRIT` 头部分区表 CRC32 与固件末尾 `YCHU` 全镜像 CRC32；
  - 执行安全转换（强制核对 `VID=0x1DBE / SSVID=0x5208` 与 Flash ID `89 C4 08 32 A6`）并保留原卡自身 `Pfct` 序列号与出厂坏块表；
  - 提供转换后一键只读复检（`--action verify`）与回滚 160GB pSLC 支持。

---

## 环境与硬件要求

- **操作系统**：Windows 10 / Windows 11
- **Python 版本**：Python 3.10 或更高版本（**零第三方依赖**，全部仅使用标准库）
- **解压依赖（可选）**：若需直接对量产包 `.rar` 自动解包，请安装 `7z`（7-Zip / NanaZip）并确保在 `PATH` 中
- **硬件**：
  - **主控**：InnoGrit IG5208 (`PCI VID=0x1DBE, SSVID=0x5208`)
  - **闪存**：Intel/Solidigm B17A 64L 3D TLC (`Flash ID: 89 C4 08 32 A6 00`，8 Dies = 512 GiB 裸容量)
  - **读卡器**：JMicron JMS583 USB-to-NVMe CFexpress Type A 读卡器
- **外部固件包（需用户自行准备，本仓库不包含第三方二进制）**：
  - 下载 `igu1.0.0.8.rar`（InnoGrit MP/Utility 工具包），放到仓库根目录并运行 `python inspect_fw_package.py` 解压到 `mp_package/`。

---

## 目录结构

```text
numinuo_pslc/
├── backup_card.py          # 只读全量备份脚本
├── probe_readonly.py       # 厂商 Data-In 只读指令安全探测脚本
├── analyze_firmware.py     # 离线 Thumb-2 反汇编与结构分析脚本
├── inspect_fw_package.py   # 量产包防盗链剥离、解包与 GRIT/PE 校验脚本
├── phase3_convert.py       # CFexpress 补丁构建、一键转换、校验与回滚主脚本
├── CONVERSION_GUIDE.md     # 详细技术原理、实测数据、操作 SOP 与回滚文档
├── pyproject.toml
├── .gitignore
└── LICENSE
```

---

## 快速上手（用法）

> ⚠️ **风险提示**：转换过程中 `0xF0` (`ftl_virgin`) 会重建全盘 FTL 映射表，**卡内原有数据会被彻底清空**。操作前请先拔出其他不相关的移动存储设备，并确保待转换卡上无重要数据。

### 1. 解包准备官方量产固件库

将自备的 `igu1.0.0.8.rar` 放在仓库根目录后执行：

```powershell
python inspect_fw_package.py
python inspect_fw_package.py --self-test
```

确认提取出了 `mp_package/igu1.0.0.8/igu1.0.0.8/firmware/ftk/ftkdisk_mu_single_lun_hmb*.fw`。

### 2. （可选）先仅做只读备份与分析

插上目标卡（假设 Windows 分配盘符为 `F:`）：

```powershell
python backup_card.py --device \\.\F:
python analyze_firmware.py --backup-dir backups\<卡序列号>
```

### 3. 一键备份 + 转换 480GB TLC (`DSLC` + `CFexpress` 补丁)

```powershell
python phase3_convert.py --action convert_new_card --mode dslc --target-gb 480 --device \\.\F:
```

脚本会自动完成以下安全步骤：
1. 校验目标盘确为 `IG5208` + `B17A (89 C4 08 32 A6)`；
2. 完整备份原卡数据到 `backups/<SN>/`；
3. 基于 `ftkdisk_mu_single_lun_hmb.fw` 构建带 `CFexpress` 签名的 480GB `DSLC` 固件并重算双 CRC32；
4. 执行 `0x11` 下载 -> `0x10 (Slot 1, CA=1)` 提交 -> `0xF1` 写回原卡坏块表与 `480GB` 容量配置 -> `0xF0` 设置 `ftl_virgin`。

### 4. 冷断电重插 & 格式化

1. 上述命令全部返回 `0x00` 后，**拔掉读卡器 USB 线，等待 3~5 秒重新插上**；
2. 此时卡变为约 `447.1 GiB`（`480.1 GB`）未初始化 `RAW` 状态（不自动弹盘符属正常现象）；
3. 按 **`Win + X` → 磁盘管理**：初始化磁盘（如用于相机建议选 **MBR**）并新建简单卷，格式化为 **exFAT**（分配盘符 `F:`）。

### 5. 转换后只读复检

```powershell
python phase3_convert.py --action verify --device \\.\F:
```

预期核对结果：
- `nsze_sectors`: `937703088`（`480.104 GB`）
- `cfe_0c00_preserved`: `true`、`cfe_0c70_preserved`: `true`
- `factory_bad_sb_exact_match`: `true`
- `superblocks_by_type`: 包含 `0x20`（动态 SLC 缓存）与 `0x31`（TLC 数据块）
- `smart.media_errors`: `0`

> 💡 **用于相机前**：建议再插入目标相机在机内执行一次格式化，并实测开机认卡与高码率录制。

---

## 其他常用命令

- **仅生成补丁固件镜像（不写入任何设备）**：
  ```powershell
  python phase3_convert.py --action patch_fw --mode dslc --target-gb 480
  python phase3_convert.py --action patch_fw --mode pslc --target-gb 160
  ```
- **查看当前卡只读快照**：
  ```powershell
  python phase3_convert.py --action snapshot --device \\.\F:
  ```
- **回滚回 160GB 静态 pSLC 模式**：
  ```powershell
  python phase3_convert.py --action phase3b --mode pslc --target-gb 160 --device \\.\F:
  ```
  完成后同样拔插读卡器并在磁盘管理初始化格式化即可恢复 `160.0 GB`（`312,581,808` 扇区）静态 pSLC 模式。

更多逆向细节与转换实录见 [CONVERSION_GUIDE.md](CONVERSION_GUIDE.md)。

---

## 免责声明

本项目仅供个人持有存储设备的固件原理研究与闲置硬件改造参考。任何固件刷写与 FTL 重建均存在数据丢失或进入 Recovery 模式的风险，操作前请务必核对设备盘符并做好备份，使用本项目产生的一切后果由使用者自行承担。
