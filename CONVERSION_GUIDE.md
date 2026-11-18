# IG5208 CFexpress Type A（pSLC 160GB -> DSLC TLC 480GB）固件转换完整指南与归档

本文档记录了对 **NUMINUO CFEA-PLUS** 160GB CFexpress Type A 存储卡（主控 InnoGrit IG5208，闪存 Intel B17A 512GiB 3D TLC）从全盘静态 pSLC 模式无拆机在线转换为 480GB DSLC（TLC + 动态 SLC 缓存）模式的技术原理、完整验证结果、**第二张同款卡一键复现流程**，以及**回滚 pSLC 流程**。

---

## 一、核心硬件与原厂锁定机制总结

1. **通信链路**：
   - 读卡器为 **JMicron JMS583** USB-to-NVMe 桥接芯片（`USB\VID_152D&PID_0583`, 桥接固件 `9201`）。
   - 在 Windows 下无需管理员权限，通过卷句柄（如 `\\.\F:`）发送 `IOCTL_SCSI_PASS_THROUGH_DIRECT (0x4D014)` + JMS583 私有 `0xA1` 隧道指令（`0x80` 发 512B SQE、`0x81` Non-Data、`0x82` DMA-In、`0x83` DMA-Out、`0x8F` 取状态）即可完整透传所有 NVMe Admin 与 InnoGrit 厂商私有指令。
2. **主控与颗粒配置（第 1 张卡 `SN: NM24E017IT21555` 实测）**：
   - **主控**：InnoGrit IG5208（`Shasta`，`VID=0x1DBE, SSVID=0x5208`）。
   - **闪存**：`2 Ch × 4 CE/Ch × 1 Die/CE = 8 Dies`，`4 Planes/Die`，`504 Superblocks`，`2304 TLC Pages/Block`，Page 大小 `18592 B (16384 + 2208)`。
   - **Flash ID**：`89 C4 08 32 A6 00`（Intel/Solidigm 64L 3D TLC B17A 512Gb/Die，总裸容量 **512 GiB**）。
3. **pSLC 锁容根因（阶段 3A 实测验证）**：
   - 经对 `igu1.0.0.8` 附带未剥离符号 `.elf` 反汇编与阶段 3A（原厂 `VB05` 固件下通过 `0xF1` 将 `Pfct` 目标容量设为 `480` + `0xF0` 触发 `ftl_virgin`）实测证实：
     - 原厂 `VB05`（`7.3.1.3`，标签 `nand_slc_Oct 30 2023`）在 `ftl_init` 中将用户数据池写模式锁定为 `pb_type = 1`（SLC），并在 `logical_spaces_init` 中将设定容量硬编码除以 `3`（`480 / 3 = 160 GB`，实测重插后容量由 `170.044 GB` 变为精确的 `160,041,885,696 B` = `312,581,808` 扇区）。
   - 因此，**必须更换为开放 TLC 的固件分支**。
4. **CFexpress 相机认证补丁与双 CRC32 校验**：
   - `igu1.0.0.8` 中的标准 `3.0.0.1S` DSLC 固件（`ftkdisk_mu_single_lun_hmb.fw`）原版针对通用 M.2/BGA，其 NVMe `Identify Controller` 在偏移 `0x0C00..0x0FFF` 全为 0。
   - 我们的补丁脚本（`phase3_convert.py --action patch_fw`）执行以下精确修改：
     1. 定位 `Identify Controller` 处理尾部的 `strb.w r3, [r7, #0x21a]`（`0x00784e`），替换为 32 位 Thumb-2 `BL` 指令，跳转至 `ATCM` 中零被引用的 `test_and_change_bit` 函数槽位（`0x01f6e0` / pSLC 中为 `0x01f560`）；
     2. 注入 56 字节 Thumb-2 补丁：先执行原指令 `strb.w r3, [r7, #0x21a]`，随后向 `Identify` 缓冲区 `0x0C00` 写入 `CFexpress\x01`、向 `0x0C77` 写入 `CFexpress`（与原卡 `VB05` 逐字节一致），最后 `bx lr` 返回；
     3. 同时重算 **两处 CRC32**：
        - `GRIT` 头部偏移 `0x0C` 处的分区表 CRC32；
        - 固件末尾 `YCHU`（`0x1DBE5208 0x20161201 "YCHU"`）结构体偏移 `+0x0C` 处的全包镜像 CRC32（固件 `fdisk_fw_dwnld` -> `fw_verify_image` 强校验此字段）。

---

## 二、第 1 张卡（`NM24E017IT21555`）转换后全面验证结果

用户全盘直写测速均在 **200 MB/s 以上** 后，于 2026-11-18 21:21 执行只读全检（保存于本地 `work/NM24E017IT21555/post_convert_verify/verify_summary.json`）：

| 检查项 | 转换前 (`VB05` pSLC) | 转换后 (`3.0.0.1S` DSLC) | 状态 |
|---|---|---|---|
| **逻辑扇区数 (`NSZE`)** | `332,116,848` (`170.04 GB`) -> 3A 后 `312,581,808` (`160.04 GB`) | **`937,703,088` (`480,103,981,056 B` = `480.10 GB`)** | 正常（精确 480GB IDEMA） |
| **CFexpress 签名 (`0x0C00` / `0x0C77`)** | `CFexpress\x01` / `CFexpress` | **`CFexpress\x01` / `CFexpress`（逐字节一致）** | 正常 |
| **出厂坏块表 (`0xCE`)** | `10` 个坏超级块（184 坏平面/块） | **`10` 个坏超级块（有效 124 字节 100% 逐字节一致）** | 完好保留 |
| **超级块分配 (`0xC6`, 共 504)** | `0x01`: 11, `0x10`: 10, `0x30(pSLC)`: 483 | **`0x01`: 11（坏/保留）, `0x10`: 13（系统）, `0x20`: 27（动态 SLC 缓存）, `0x31`: 453（TLC 数据）** | 正常（典型 DSLC 结构） |
| **SMART 健康度与错误** | 正常 | `critical_warning=0`, `available_spare=100%`, `percentage_used=0%`, **`media_errors=0`**, **`error_log_entries=0`** | 0 错误 |
| **测试写入量与温度** | — | 已写入 `2,050,118` 单位 / 读取 `695,144` 单位（约 1TB 级压力测速），温度 `61°C` | 健康 |

### 需注意的细微差异与相机使用提醒：
1. **分区格式（重要）**：目前在 Windows 下被格式化为 `GPT + NTFS`。**用于索尼等相机前，请务必改为 `MBR + exFAT` 或直接插回相机在机内菜单执行格式化一次**（多数相机不识别 NTFS）。
2. **`Identify Controller` 三处细微字段变化**：
   - `FR`（固件版本号）：显示为 `3.0.0.1S`（不再显示 `VB05`）；
   - `MDTS`：由 `0x09` (2MB) 变为 `0x05` (128KB)；
   - `TNVMCAP` (`0x118`)：新固件留空为 `0`（Windows/标准 NVMe 读 `NSZE` 无影响；若极少数相机实测不认卡，需进一步补丁将 `TNVMCAP` 填回或保持 `FR=VB05`）。
3. **`0xFE` 厂商命令**：`3.0.0.1S` 尚未实现后代 `7.x` 固件新增的 `0xFE` 命令（返回 `0x01` Invalid Opcode），属于版本特征，不影响读写，通过 `0xC6` 已确认 `0x20` 动态 SLC + `0x31` TLC 工作正常。

---

## 三、第二张相同存储卡的完整转换流程（SOP）

> **安全守则**：操作前先**拔出已完成转换的第 1 张卡**，仅插入第 2 张未修改过的原厂卡，确认分配了盘符（假设为 `F:`；若盘符不是 `F:`，请把下方命令中的 `\\.\F:` 替换为实际盘符）。

### 第 1 步：一条命令完成全量备份 + 安全核对 + DSLC 固件刷入与提交

在仓库根目录下执行：

```powershell
python phase3_convert.py --action convert_new_card --mode dslc --target-gb 480 --device \\.\F:
```

该命令会自动完成以下动作（**若发现不是 IG5208 主控或不是 `89 C4 08 32 A6` Intel B17A 颗粒会直接中止，绝不误刷其他盘**）：
1. 完整只读备份第 2 张卡的 `Identify`、SMART、CEL、`0xF2`（`Pfct` 产测表与出厂坏块）、`0xCE`、`0xC6`、`0xCA`、`0xD6` 到 `backups/<第2张卡SN>/`；
2. 生成带 `CFexpress` 签名的 `DSLC` 补丁固件并重算双 CRC32；
3. 按顺序执行 `0x11`（下载固件）-> `0x10`（`CDW10=0x09` Slot 1 提交）-> `0xF1`（写入保留该卡自身 SN 与坏块表的 480GB `Pfct`）-> `0xF0`（标记 `ftl_virgin`），并将过程保存至 `work/<第2张卡SN>/phase3b_dslc_report.json`。

### 第 2 步：冷断电重插 & 格式化

1. 上述命令全部返回 `0x00` 结束后，**拔掉读卡器 USB 线，等待 3~5 秒再重新插入**；
2. 此时新卡已变为 `480.1 GB` 的未初始化 `RAW` 磁盘（不会自动弹盘符属于正常现象）；
3. 按 **`Win + X` -> 磁盘管理**：
   - 找到该磁盘（约 `447.1 GB` 未初始化），右键 **初始化磁盘**（若后续插相机建议选 **MBR**）；
   - 右键未分配空间 **新建简单卷**，文件系统选择 **exFAT**，分配盘符（例如 `F:`）并快速格式化。

### 第 3 步：转换后底层校验

运行只读校验（自动识别当前盘序列号，也可显式指定 `--backup-dir backups/<第2张卡SN>`）：

```powershell
python phase3_convert.py --action verify --device \\.\F:
```

核对输出中以下各项均为预期值即可收工：
- `nsze_sectors == 937703088`（`capacity_gb_decimal == 480.104`）
- `cfe_0c00_preserved == true`、`cfe_0c70_preserved == true`
- `factory_bad_sb_exact_match == true`
- `superblocks_by_type` 中存在 `0x20` 与 `0x31`
- `smart.media_errors == 0`

*(可选) 建议装回目标相机测试开机认卡、机内格式化及高码率连拍/视频录制稳定性。*

---

## 四、如何回滚回 160GB pSLC 模式

> **注**：因卡内未公开读取原厂 `VB05`（`7.3.1.3`）完整二进制镜像的指令，回滚使用同源量产包 `igu1.0.0.8` 提供的官方静态 pSLC 固件 `ftkdisk_mu_single_lun_hmb_pslc.fw`（同样已通过 `--action patch_fw --mode pslc` 注入相同的 `CFexpress` 签名，且 100% 恢复该卡备份的出厂 `f2_pfct.bin` 坏块表）。

若需将第 1 张卡或第 2 张卡恢复为 `160GB` 全盘静态 pSLC 模式，插上目标卡（假设盘符 `F:`）：

```powershell
python phase3_convert.py --action phase3b --mode pslc --target-gb 160 --device \\.\F:
```

刷完返回 `0x00` 后，拔插读卡器一次并在磁盘管理初始化格式化，容量即恢复为 `160.0 GB`（`312,581,808` 扇区），所有超级块恢复为静态 pSLC 模式。

---

## 五、工作区核心文件索引

| 文件路径 | 作用 |
|---|---|
| [backup_card.py](backup_card.py) | 只读备份工具（导出 `0xF2/0xF6/0xCE/0xC6/0xC2/0xCA/0xD2/0xD6/0xFA/0xFE` 与标准 NVMe 信息） |
| [analyze_firmware.py](analyze_firmware.py) | `VB05` 固件结构与 Thumb-2 片段离线分析脚本 |
| [inspect_fw_package.py](inspect_fw_package.py) | 剥离量产部落 131B 防盗链头、解包 `igu1.0.0.8` 并解析 `GRIT`/`CMFG` 镜像脚本 |
| [phase3_convert.py](phase3_convert.py) | 固件 CFexpress 补丁生成、刷写转换、第 2 张卡全自动转换与转换后校验主脚本 |
| [CONVERSION_GUIDE.md](CONVERSION_GUIDE.md) | 本文档（原理、校验归档、第 2 张卡 SOP 与回滚流程） |
| `backups/<SN>/` | 各卡原始备份目录（只读保存，切勿覆盖） |
| `work/<SN>/` | 转换产物、各阶段日志与 `post_convert_verify/` 复检归档 |
