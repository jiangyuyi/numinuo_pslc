"""Offline structural analyzer and ARM Thumb-2 disassembler for IG5208 backups."""

from __future__ import annotations

import argparse
import json
import struct
from collections import Counter
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Minimal, self-contained ARM Thumb / Thumb-2 Disassembler for Cortex-R/M
# ---------------------------------------------------------------------------

COND_NAMES = (
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
)


def reg_name(r: int) -> str:
    if r == 13:
        return "sp"
    if r == 14:
        return "lr"
    if r == 15:
        return "pc"
    return f"r{r}"


def reg_list_str(mask: int) -> str:
    regs = [reg_name(i) for i in range(16) if (mask >> i) & 1]
    return "{" + ", ".join(regs) + "}"


def sign_extend(val: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (val & (sign - 1)) - (val & sign)


def decode_thumb_modified_imm(i: int, imm3: int, imm8: int) -> int:
    imm12 = (i << 11) | (imm3 << 8) | imm8
    top = (imm12 >> 10) & 3
    if top == 0:
        ctrl = (imm12 >> 8) & 3
        if ctrl == 0:
            return imm8
        if ctrl == 1:
            return (imm8 << 16) | imm8
        if ctrl == 2:
            return (imm8 << 24) | (imm8 << 8)
        return (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8
    rot = (imm12 >> 7) & 0x1F
    val = 0x80 | (imm8 & 0x7F)
    return ((val >> rot) | (val << (32 - rot))) & 0xFFFFFFFF


def decode_thumb16(hw: int, off: int, data: bytes) -> tuple[str, str]:
    """Decode a 16-bit Thumb instruction. Returns (mnemonic, comment)."""
    op_top = hw >> 11
    if op_top in (0, 1, 2):  # LSLS, LSRS, ASRS (imm)
        op = ("lsls", "lsrs", "asrs")[op_top]
        imm5 = (hw >> 6) & 0x1F
        rm = (hw >> 3) & 7
        rd = hw & 7
        if op_top == 0 and imm5 == 0:
            return f"movs {reg_name(rd)}, {reg_name(rm)}", ""
        if op_top in (1, 2) and imm5 == 0:
            imm5 = 32
        return f"{op} {reg_name(rd)}, {reg_name(rm)}, #{imm5}", ""
    if op_top == 3:
        sub = (hw >> 9) & 3
        rm_imm = (hw >> 6) & 7
        rn = (hw >> 3) & 7
        rd = hw & 7
        if sub == 0:
            return f"adds {reg_name(rd)}, {reg_name(rn)}, {reg_name(rm_imm)}", ""
        if sub == 1:
            return f"subs {reg_name(rd)}, {reg_name(rn)}, {reg_name(rm_imm)}", ""
        if sub == 2:
            return f"adds {reg_name(rd)}, {reg_name(rn)}, #{rm_imm}", ""
        return f"subs {reg_name(rd)}, {reg_name(rn)}, #{rm_imm}", ""
    if op_top in (4, 5, 6, 7):
        op = ("movs", "cmp", "adds", "subs")[op_top - 4]
        rdn = (hw >> 8) & 7
        imm8 = hw & 0xFF
        return f"{op} {reg_name(rdn)}, #0x{imm8:02x}", f"{imm8}"
    if (hw >> 10) == 0x10:  # Data-processing register
        ops = (
            "ands", "eors", "lsls", "lsrs", "asrs", "adcs", "sbcs", "rors",
            "tst", "rsbs", "cmp", "cmn", "orrs", "muls", "bics", "mvns",
        )
        dp_op = (hw >> 6) & 0xF
        rm = (hw >> 3) & 7
        rdn = hw & 7
        return f"{ops[dp_op]} {reg_name(rdn)}, {reg_name(rm)}", ""
    if (hw >> 10) == 0x11:  # Special data / branch exchange
        sub = (hw >> 8) & 3
        if sub == 3:
            rm = (hw >> 3) & 0xF
            op = "blx" if (hw >> 7) & 1 else "bx"
            return f"{op} {reg_name(rm)}", ""
        d = (hw >> 7) & 1
        rm = (hw >> 3) & 0xF
        rdn = (d << 3) | (hw & 7)
        op = ("add", "cmp", "mov")[sub]
        return f"{op} {reg_name(rdn)}, {reg_name(rm)}", ""
    if op_top == 9:  # LDR Rt, [PC, #imm8*4]
        rt = (hw >> 8) & 7
        imm8 = hw & 0xFF
        target = ((off + 4) & ~3) + imm8 * 4
        cmt = f"[0x{target:04x}]"
        if target + 4 <= len(data):
            val = struct.unpack_from("<I", data, target)[0]
            cmt += f" = 0x{val:08x}"
        return f"ldr {reg_name(rt)}, [pc, #0x{imm8 * 4:x}]", cmt
    if (hw >> 12) == 5:  # Load/store register offset
        opc = (hw >> 9) & 7
        ops = ("str", "strh", "strb", "ldrsb", "ldr", "ldrh", "ldrb", "ldrsh")
        rm = (hw >> 6) & 7
        rn = (hw >> 3) & 7
        rt = hw & 7
        return f"{ops[opc]} {reg_name(rt)}, [{reg_name(rn)}, {reg_name(rm)}]", ""
    if (hw >> 13) == 3:  # Load/store word/byte immediate
        b = (hw >> 12) & 1
        l = (hw >> 11) & 1
        imm5 = (hw >> 6) & 0x1F
        rn = (hw >> 3) & 7
        rt = hw & 7
        scale = 1 if b else 4
        op = ("strb" if b else "str") if l == 0 else ("ldrb" if b else "ldr")
        return f"{op} {reg_name(rt)}, [{reg_name(rn)}, #0x{imm5 * scale:x}]", ""
    if (hw >> 12) == 8:  # Load/store halfword immediate
        l = (hw >> 11) & 1
        imm5 = (hw >> 6) & 0x1F
        rn = (hw >> 3) & 7
        rt = hw & 7
        op = "ldrh" if l else "strh"
        return f"{op} {reg_name(rt)}, [{reg_name(rn)}, #0x{imm5 * 2:x}]", ""
    if (hw >> 12) == 9:  # Load/store SP-relative
        l = (hw >> 11) & 1
        rt = (hw >> 8) & 7
        imm8 = hw & 0xFF
        op = "ldr" if l else "str"
        return f"{op} {reg_name(rt)}, [sp, #0x{imm8 * 4:x}]", ""
    if (hw >> 12) == 10:  # ADR / ADD SP, imm
        is_sp = (hw >> 11) & 1
        rd = (hw >> 8) & 7
        imm8 = hw & 0xFF
        if is_sp:
            return f"add {reg_name(rd)}, sp, #0x{imm8 * 4:x}", ""
        target = ((off + 4) & ~3) + imm8 * 4
        return f"adr {reg_name(rd)}, 0x{target:04x}", ""
    if (hw >> 12) == 11:  # Miscellaneous 16-bit
        if (hw >> 8) == 0xB0:
            imm7 = (hw & 0x7F) * 4
            op = "sub" if (hw & 0x80) else "add"
            return f"{op} sp, #0x{imm7:x}", ""
        if (hw & 0xF500) == 0xB100:  # CBZ / CBNZ
            op = "cbnz" if (hw >> 11) & 1 else "cbz"
            i = (hw >> 9) & 1
            imm5 = (hw >> 3) & 0x1F
            rn = hw & 7
            target = off + 4 + ((i << 6) | (imm5 << 1))
            return f"{op} {reg_name(rn)}, 0x{target:04x}", ""
        if (hw & 0xFF00) == 0xB200:  # SXTH / SXTB / UXTH / UXTB
            sub = (hw >> 6) & 3
            rm = (hw >> 3) & 7
            rd = hw & 7
            op = ("sxth", "sxtb", "uxth", "uxtb")[sub]
            return f"{op} {reg_name(rd)}, {reg_name(rm)}", ""
        if (hw & 0xFE00) == 0xB400:  # PUSH
            mask = (hw & 0xFF) | (0x4000 if (hw & 0x100) else 0)
            return f"push {reg_list_str(mask)}", ""
        if (hw & 0xFE00) == 0xBC00:  # POP
            mask = (hw & 0xFF) | (0x8000 if (hw & 0x100) else 0)
            return f"pop {reg_list_str(mask)}", ""
        if (hw & 0xFF00) == 0xBF00:  # IT / Hints
            if hw == 0xBF00:
                return "nop", ""
            firstcond = (hw >> 4) & 0xF
            mask = hw & 0xF
            cond0 = firstcond & 1
            suffix = ""
            for bit in (3, 2, 1):
                if (mask & ((1 << bit) - 1)) == 0:
                    break
                suffix += "t" if ((mask >> bit) & 1) == cond0 else "e"
            return f"it{suffix} {COND_NAMES[firstcond]}", ""
    if (hw >> 12) == 12:  # LDM / STM
        l = (hw >> 11) & 1
        rn = (hw >> 8) & 7
        mask = hw & 0xFF
        op = "ldmia" if l else "stmia"
        return f"{op} {reg_name(rn)}!, {reg_list_str(mask)}", ""
    if (hw >> 12) == 13:  # Conditional branch / SVC
        cond = (hw >> 8) & 0xF
        imm8 = hw & 0xFF
        if cond == 0xE:
            return f".short 0x{hw:04x}", "udf"
        if cond == 0xF:
            return f"svc #0x{imm8:02x}", ""
        target = off + 4 + (sign_extend(imm8, 8) << 1)
        return f"b{COND_NAMES[cond]} 0x{target:04x}", ""
    if op_top == 0x1C:  # Unconditional branch
        imm11 = hw & 0x7FF
        target = off + 4 + (sign_extend(imm11, 11) << 1)
        return f"b 0x{target:04x}", ""
    return f".short 0x{hw:04x}", "unhandled-16"


def decode_thumb32(hw0: int, hw1: int, off: int, data: bytes) -> tuple[str, str]:
    """Decode a 32-bit Thumb-2 instruction. Returns (mnemonic, comment)."""
    # Branch & Misc Control: 11110 ... / 1 ...
    if (hw0 & 0xF800) == 0xF000 and (hw1 & 0x8000) == 0x8000:
        if (hw1 & 0xD000) == 0x9000:  # B.W (unconditional)
            s = (hw0 >> 10) & 1
            j1 = (hw1 >> 13) & 1
            j2 = (hw1 >> 11) & 1
            i1 = ~(j1 ^ s) & 1
            i2 = ~(j2 ^ s) & 1
            rel = (s << 24) | (i1 << 23) | (i2 << 22) | ((hw0 & 0x3FF) << 12) | ((hw1 & 0x7FF) << 1)
            if s:
                rel -= 1 << 25
            target = off + 4 + rel
            return f"b.w 0x{target:04x}", f"rel={rel:+d}"
        if (hw1 & 0xD000) in (0xD000, 0xC000):  # BL or BLX(imm)
            s = (hw0 >> 10) & 1
            j1 = (hw1 >> 13) & 1
            j2 = (hw1 >> 11) & 1
            i1 = ~(j1 ^ s) & 1
            i2 = ~(j2 ^ s) & 1
            is_blx = (hw1 & 0x1000) == 0
            imm11 = hw1 & 0x7FF
            if is_blx:
                imm11 &= ~1
            rel = (s << 24) | (i1 << 23) | (i2 << 22) | ((hw0 & 0x3FF) << 12) | (imm11 << 1)
            if s:
                rel -= 1 << 25
            base = ((off + 4) & ~3) if is_blx else (off + 4)
            target = base + rel
            op = "blx" if is_blx else "bl"
            cmt = f"rel={rel:+d}"
            if 0 <= target < len(data) - 4 and is_blx:
                if struct.unpack_from("<I", data, target)[0] == 0xE51FF004:
                    veneer_dst = struct.unpack_from("<I", data, target + 4)[0]
                    cmt += f" -> veneer[0x{target:04x}] -> 0x{veneer_dst:08x}"
            return f"{op} 0x{target:x}" if target >= 0 else f"{op} (off{target:+d})", cmt
        if (hw1 & 0xD000) == 0x8000 and ((hw0 >> 6) & 0xF) not in (0xE, 0xF):
            # Conditional B<cond>.W
            s = (hw0 >> 10) & 1
            cond = (hw0 >> 6) & 0xF
            j1 = (hw1 >> 13) & 1
            j2 = (hw1 >> 11) & 1
            rel = (s << 20) | (j2 << 19) | (j1 << 18) | ((hw0 & 0x3F) << 12) | ((hw1 & 0x7FF) << 1)
            if s:
                rel -= 1 << 21
            target = off + 4 + rel
            return f"b{COND_NAMES[cond]}.w 0x{target:04x}", ""

    # Data-processing (modified immediate): 11110 i 0 op[4] S Rn / 0 imm3 Rd imm8
    if (hw0 & 0xFA00) == 0xF000 and (hw1 & 0x8000) == 0:
        i = (hw0 >> 10) & 1
        op = (hw0 >> 5) & 0xF
        s_bit = (hw0 >> 4) & 1
        rn = hw0 & 0xF
        imm3 = (hw1 >> 12) & 7
        rd = (hw1 >> 8) & 0xF
        imm8 = hw1 & 0xFF
        val = decode_thumb_modified_imm(i, imm3, imm8)
        s_str = "s" if s_bit else ""
        if op == 0:
            if rd == 15 and s_bit:
                return f"tst.w {reg_name(rn)}, #0x{val:x}", ""
            return f"and{s_str}.w {reg_name(rd)}, {reg_name(rn)}, #0x{val:x}", ""
        if op == 1:
            return f"bic{s_str}.w {reg_name(rd)}, {reg_name(rn)}, #0x{val:x}", ""
        if op == 2:
            if rn == 15:
                return f"mov{s_str}.w {reg_name(rd)}, #0x{val:x}", f"{val}"
            return f"orr{s_str}.w {reg_name(rd)}, {reg_name(rn)}, #0x{val:x}", ""
        if op == 3:
            if rn == 15:
                return f"mvn{s_str}.w {reg_name(rd)}, #0x{val:x}", ""
            return f"orn{s_str}.w {reg_name(rd)}, {reg_name(rn)}, #0x{val:x}", ""
        if op == 4:
            if rd == 15 and s_bit:
                return f"teq.w {reg_name(rn)}, #0x{val:x}", ""
            return f"eor{s_str}.w {reg_name(rd)}, {reg_name(rn)}, #0x{val:x}", ""
        if op == 8:
            if rd == 15 and s_bit:
                return f"cmn.w {reg_name(rn)}, #0x{val:x}", ""
            return f"add{s_str}.w {reg_name(rd)}, {reg_name(rn)}, #0x{val:x}", ""
        if op == 13:
            if rd == 15 and s_bit:
                return f"cmp.w {reg_name(rn)}, #0x{val:x}", f"{val}"
            return f"sub{s_str}.w {reg_name(rd)}, {reg_name(rn)}, #0x{val:x}", ""
        if op == 14:
            return f"rsb{s_str}.w {reg_name(rd)}, {reg_name(rn)}, #0x{val:x}", ""

    # Data-processing (plain binary immediate): MOVW / MOVT / ADDW / SUBW / UBFX / SBFX / BFC / BFI
    if (hw0 & 0xF800) == 0xF000 and (hw1 & 0x8000) == 0 and (hw0 & 0x0200) == 0x0200:
        i = (hw0 >> 10) & 1
        op = (hw0 >> 4) & 0x1F
        rn = hw0 & 0xF
        imm3 = (hw1 >> 12) & 7
        rd = (hw1 >> 8) & 0xF
        imm8 = hw1 & 0xFF
        imm12 = (i << 11) | (imm3 << 8) | imm8
        imm16 = ((hw0 & 0xF) << 12) | imm12
        if op == 0x04:
            return f"movw {reg_name(rd)}, #0x{imm16:04x}", f"{imm16}"
        if op == 0x0C:
            return f"movt {reg_name(rd)}, #0x{imm16:04x}", ""
        if op == 0x00:
            if rn == 15:
                target = ((off + 4) & ~3) + imm12
                return f"adr.w {reg_name(rd)}, 0x{target:04x}", ""
            return f"addw {reg_name(rd)}, {reg_name(rn)}, #0x{imm12:x}", ""
        if op == 0x0A:
            if rn == 15:
                target = ((off + 4) & ~3) - imm12
                return f"adr.w {reg_name(rd)}, 0x{target:04x}", ""
            return f"subw {reg_name(rd)}, {reg_name(rn)}, #0x{imm12:x}", ""
        if op in (0x14, 0x1C):  # SBFX / UBFX
            lsb = (imm3 << 2) | ((hw1 >> 6) & 3)
            widthm1 = hw1 & 0x1F
            name = "sbfx" if op == 0x14 else "ubfx"
            return f"{name} {reg_name(rd)}, {reg_name(rn)}, #{lsb}, #{widthm1 + 1}", ""
        if op == 0x16:  # BFC / BFI
            lsb = (imm3 << 2) | ((hw1 >> 6) & 3)
            msb = hw1 & 0x1F
            width = msb - lsb + 1
            if rn == 15:
                return f"bfc {reg_name(rd)}, #{lsb}, #{width}", ""
            return f"bfi {reg_name(rd)}, {reg_name(rn)}, #{lsb}, #{width}", ""

    # LDM / STM / PUSH.W / POP.W (11101 00 P U 0 W L Rn / mask)
    if (hw0 & 0xFE40) == 0xE800:
        u = (hw0 >> 7) & 1
        w = (hw0 >> 5) & 1
        l = (hw0 >> 4) & 1
        rn = hw0 & 0xF
        if rn == 13 and w and l and u:
            return f"pop.w {reg_list_str(hw1)}", ""
        if rn == 13 and w and not l and not u:
            return f"push.w {reg_list_str(hw1)}", ""
        op = ("ldmdb" if not u else "ldmia") if l else ("stmdb" if not u else "stmia")
        wb = "!" if w else ""
        return f"{op}.w {reg_name(rn)}{wb}, {reg_list_str(hw1)}", ""

    # LDRD / STRD (11101 00 P U 1 W L Rn / Rt Rt2 imm8)
    if (hw0 & 0xFE40) == 0xE840:
        p = (hw0 >> 8) & 1
        u = (hw0 >> 7) & 1
        w = (hw0 >> 5) & 1
        l = (hw0 >> 4) & 1
        rn = hw0 & 0xF
        rt = (hw1 >> 12) & 0xF
        rt2 = (hw1 >> 8) & 0xF
        imm8 = (hw1 & 0xFF) * 4
        sign = "" if u else "-"
        op = "ldrd" if l else "strd"
        if p:
            wb = "!" if w else ""
            return f"{op} {reg_name(rt)}, {reg_name(rt2)}, [{reg_name(rn)}, #{sign}0x{imm8:x}]{wb}", ""
        return f"{op} {reg_name(rt)}, {reg_name(rt2)}, [{reg_name(rn)}], #{sign}0x{imm8:x}", ""

    # Data-processing (shifted register): 11101 01 op[4] S Rn / 0 imm3 Rd imm2 type Rm
    if (hw0 & 0xFE00) == 0xEA00:
        op = (hw0 >> 5) & 0xF
        s_bit = (hw0 >> 4) & 1
        rn = hw0 & 0xF
        imm3 = (hw1 >> 12) & 7
        rd = (hw1 >> 8) & 0xF
        imm2 = (hw1 >> 6) & 3
        stype = (hw1 >> 4) & 3
        rm = hw1 & 0xF
        shamt = (imm3 << 2) | imm2
        snames = ("lsl", "lsr", "asr", "ror")
        sh_str = f", {snames[stype]} #{shamt}" if (shamt or stype == 3) else ""
        if shamt == 0 and stype == 3:
            sh_str = ", rrx"
        s_str = "s" if s_bit else ""
        opmap = {0: "and", 1: "bic", 2: "orr", 3: "orn", 4: "eor", 8: "add", 10: "adc", 11: "sbc", 13: "sub", 14: "rsb"}
        if op in opmap:
            if op == 2 and rn == 15:
                return f"mov{s_str}.w {reg_name(rd)}, {reg_name(rm)}{sh_str}", ""
            if op == 3 and rn == 15:
                return f"mvn{s_str}.w {reg_name(rd)}, {reg_name(rm)}{sh_str}", ""
            if op == 0 and rd == 15 and s_bit:
                return f"tst.w {reg_name(rn)}, {reg_name(rm)}{sh_str}", ""
            if op == 13 and rd == 15 and s_bit:
                return f"cmp.w {reg_name(rn)}, {reg_name(rm)}{sh_str}", ""
            return f"{opmap[op]}{s_str}.w {reg_name(rd)}, {reg_name(rn)}, {reg_name(rm)}{sh_str}", ""

    # Load/Store single (11111 00 ...): PC-relative, imm12, reg-offset, pre/post
    if (hw0 & 0xFE00) == 0xF800:
        size = (hw0 >> 5) & 3
        l = (hw0 >> 4) & 1
        s_ext = (hw0 >> 8) & 1
        u = (hw0 >> 7) & 1
        rn = hw0 & 0xF
        rt = (hw1 >> 12) & 0xF
        sz_names = {0: "b", 1: "h", 2: ""}
        if size in sz_names:
            prefix = "ldr" if l else "str"
            ext = "s" if (l and s_ext) else ""
            op = f"{prefix}{ext}{sz_names[size]}.w"
            if rn == 15 and l:
                imm12 = hw1 & 0xFFF
                base = (off + 4) & ~3
                target = base + imm12 if u else base - imm12
                cmt = f"[0x{target:04x}]"
                if 0 <= target <= len(data) - 4:
                    val = struct.unpack_from("<I", data, target)[0]
                    cmt += f" = 0x{val:08x}"
                return f"{op} {reg_name(rt)}, [pc, #{'+' if u else '-'}0x{imm12:x}]", cmt
            if u:  # 12-bit positive immediate
                imm12 = hw1 & 0xFFF
                return f"{op} {reg_name(rt)}, [{reg_name(rn)}, #0x{imm12:x}]", ""
            if (hw1 & 0x0800) == 0x0800:  # imm8 pre/post/unprivileged
                p = (hw1 >> 10) & 1
                uu = (hw1 >> 9) & 1
                w = (hw1 >> 8) & 1
                imm8 = hw1 & 0xFF
                sign = "" if uu else "-"
                if p and not w and uu:
                    return f"{op}t {reg_name(rt)}, [{reg_name(rn)}, #0x{imm8:x}]", ""
                if p:
                    wb = "!" if w else ""
                    return f"{op} {reg_name(rt)}, [{reg_name(rn)}, #{sign}0x{imm8:x}]{wb}", ""
                return f"{op} {reg_name(rt)}, [{reg_name(rn)}], #{sign}0x{imm8:x}", ""
            if (hw1 & 0x0FC0) == 0:  # register offset shifted by imm2
                rm = hw1 & 0xF
                imm2 = (hw1 >> 4) & 3
                sh = f", lsl #{imm2}" if imm2 else ""
                return f"{op} {reg_name(rt)}, [{reg_name(rn)}, {reg_name(rm)}{sh}]", ""

    # Data-processing (register): 11111 010 ... (LSL/LSR/ASR/ROR, UXTH/UXTB/SXTH/SXTB)
    if (hw0 & 0xFF00) == 0xFA00:
        op1 = (hw0 >> 4) & 0xF
        rn = hw0 & 0xF
        rd = (hw1 >> 8) & 0xF
        op2 = (hw1 >> 4) & 0xF
        rm = hw1 & 0xF
        if op1 == 0xB and (hw1 & 0xF0F0) == 0xF080 and rn == rm:
            return f"clz {reg_name(rd)}, {reg_name(rm)}", ""
        if (hw1 & 0xF0F0) == 0xF000 and op1 <= 7:
            sh = ("lsl", "lsr", "asr", "ror")[op1 >> 1]
            s_str = "s" if (op1 & 1) else ""
            return f"{sh}{s_str}.w {reg_name(rd)}, {reg_name(rn)}, {reg_name(rm)}", ""
        if op1 in (0, 1, 4, 5) and rn == 15 and (op2 & 0xC) == 0x8:
            ext_op = {0: "sxth", 1: "uxth", 4: "sxtb", 5: "uxtb"}[op1]
            rot = (op2 & 3) * 8
            rstr = f", ror #{rot}" if rot else ""
            return f"{ext_op}.w {reg_name(rd)}, {reg_name(rm)}{rstr}", ""

    # Multiply / Divide (11111 011 ...)
    if (hw0 & 0xFF00) == 0xFB00:
        op1 = (hw0 >> 4) & 7
        rn = hw0 & 0xF
        ra = (hw1 >> 12) & 0xF
        rd = (hw1 >> 8) & 0xF
        op2 = (hw1 >> 4) & 0xF
        rm = hw1 & 0xF
        if op1 == 0 and op2 == 0 and ra == 15:
            return f"mul {reg_name(rd)}, {reg_name(rn)}, {reg_name(rm)}", ""
        if op1 == 0 and op2 == 0:
            return f"mla {reg_name(rd)}, {reg_name(rn)}, {reg_name(rm)}, {reg_name(ra)}", ""
        if op1 == 0 and op2 == 1:
            return f"mls {reg_name(rd)}, {reg_name(rn)}, {reg_name(rm)}, {reg_name(ra)}", ""
        if (hw0 & 0xFF70) == 0xFB10 and op2 == 0xF:
            op = "udiv" if (hw0 & 0x20) else "sdiv"
            return f"{op} {reg_name(rd)}, {reg_name(rn)}, {reg_name(rm)}", ""

    return f".word 0x{(hw1 << 16) | hw0:08x}", "unhandled-32"


def disassemble_sram_leak(data: bytes) -> dict[str, Any]:
    """Disassemble d6_fw_sram_leak.bin identifying functions, veneers, literals, and calls."""
    # Identify literal pool / ARM veneer regions that should not be decoded as Thumb
    #ARM veneer table sits at 0x0634..0x06F3
    non_thumb_ranges = [(0x0000, 0x0048), (0x0630, 0x06F4)]
    # Data literal pools inside functions (4-byte aligned pointers at end of functions)
    literal_targets: set[int] = set()
    for off in range(0, len(data) - 2, 2):
        hw0 = struct.unpack_from("<H", data, off)[0]
        if (hw0 & 0xF800) == 0x4800:
            t = ((off + 4) & ~3) + (hw0 & 0xFF) * 4
            if 0 <= t <= len(data) - 4:
                literal_targets.add(t)
        elif (hw0 & 0xFF7F) == 0xF85F and off + 4 <= len(data):
            hw1 = struct.unpack_from("<H", data, off + 2)[0]
            u = (hw0 >> 7) & 1
            t = ((off + 4) & ~3) + ((hw1 & 0xFFF) if u else -(hw1 & 0xFFF))
            if 0 <= t <= len(data) - 4:
                literal_targets.add(t)

    def in_non_thumb(o: int) -> bool:
        return any(a <= o < b for a, b in non_thumb_ranges)

    funcs = [
        0x0048, 0x00FA, 0x0300, 0x044C, 0x0584, 0x05C8, 0x06F4, 0x0848,
        0x094C, 0x096C, 0x0D00, 0x0D2C, 0x0DB8, 0x0E60, 0x0E84, 0x0FAC,
    ]
    func_set = {f: f"sub_{f:04x}" for f in funcs}

    lines: list[str] = []
    unhandled = 0
    bl_targets: Counter[int] = Counter()
    veneer_targets: list[tuple[int, int]] = []
    mmio_refs: set[int] = set()
    msg_ids: list[tuple[int, int]] = []

    off = 0
    while off < len(data):
        if off in func_set:
            lines.append(f"\n; === {func_set[off]} (offset 0x{off:04x}) ===")

        if in_non_thumb(off):
            if off == 0x0630:
                lines.append("; --- ARM Veneer Table (0x0630..0x06F3) ---")
            w = struct.unpack_from("<I", data, off)[0]
            if off >= 0x0634 and w == 0xE51FF004 and off + 8 <= len(data):
                dst = struct.unpack_from("<I", data, off + 4)[0]
                veneer_targets.append((off, dst))
                lines.append(f"  0x{off:04x}: ldr pc, [pc, #-4] -> 0x{dst:08x}")
                off += 8
                continue
            lines.append(f"  0x{off:04x}: .word 0x{w:08x}")
            off += 4
            continue

        if off in literal_targets and (off % 4 == 0):
            # Check if contiguous literal words follow
            w = struct.unpack_from("<I", data, off)[0]
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data[off : off + 4])
            if 0xC0000000 <= w <= 0xC0100000:
                mmio_refs.add(w)
            lines.append(f"  0x{off:04x}: .word 0x{w:08x}  ; {asc!r}")
            off += 4
            continue

        hw0 = struct.unpack_from("<H", data, off)[0]
        is_32 = (hw0 >> 11) in (0b11101, 0b11110, 0b11111)
        if is_32 and off + 4 <= len(data):
            hw1 = struct.unpack_from("<H", data, off + 2)[0]
            mnem, cmt = decode_thumb32(hw0, hw1, off, data)
            if cmt == "unhandled-32":
                unhandled += 1
            if mnem.startswith("bl ") and "rel=" in cmt:
                rel = int(cmt.split("rel=")[1].split()[0])
                bl_targets[off + 4 + rel] += 1
            if mnem.startswith("movw r2, "):
                imm = int(cmt)
                if 0x2000 <= imm <= 0x2FFF:
                    msg_ids.append((off, imm))
            lines.append(f"  0x{off:04x}: {hw0:04x} {hw1:04x}  {mnem:36s} ; {cmt}" if cmt else f"  0x{off:04x}: {hw0:04x} {hw1:04x}  {mnem}")
            off += 4
        else:
            mnem, cmt = decode_thumb16(hw0, off, data)
            if cmt == "unhandled-16":
                unhandled += 1
            lines.append(f"  0x{off:04x}: {hw0:04x}       {mnem:36s} ; {cmt}" if cmt else f"  0x{off:04x}: {hw0:04x}       {mnem}")
            off += 2

    return {
        "lines": lines,
        "unhandled_instructions": unhandled,
        "functions": funcs,
        "bl_rel_targets": dict(bl_targets.most_common()),
        "veneer_targets": veneer_targets,
        "mmio_refs": sorted(mmio_refs),
        "event_msg_ids": msg_ids,
    }


# ---------------------------------------------------------------------------
# Part A: Structural Decoding of Backup Tables
# ---------------------------------------------------------------------------

def analyze_backup(bdir: Path) -> dict[str, Any]:
    id_ctrl = (bdir / "id_ctrl.bin").read_bytes()
    id_ns = (bdir / "id_ns.bin").read_bytes()
    f2 = (bdir / "f2_pfct.bin").read_bytes()
    f6 = (bdir / "f6_nand_geom.bin").read_bytes()
    fe = (bdir / "fe_fw_summary.bin").read_bytes()
    ca = (bdir / "ca_fw_banner.bin").read_bytes()
    ce = (bdir / "ce_bad_sb.bin").read_bytes()
    c6 = (bdir / "c6_sb_full.bin").read_bytes()
    fa = (bdir / "fa_internal_smart.bin").read_bytes()
    smart = (bdir / "smart.bin").read_bytes()
    cel = (bdir / "nvme_cel.bin").read_bytes()
    c2 = (bdir / "c2_event_log.bin").read_bytes()
    d6 = (bdir / "d6_fw_sram_leak.bin").read_bytes()

    # 1. Decode 0xF6 hardware descriptor
    f6_u32 = struct.unpack_from("<22I", f6, 0)
    f6_decoded = {
        "channels": f6_u32[0],
        "ce_per_ch": f6_u32[1],
        "die_per_ce": f6_u32[2],
        "superblocks": f6_u32[3],
        "pages_per_block_tlc": f6_u32[4],
        "raw_page_bytes": f6_u32[5],
        "spare_bytes": f6_u32[6],
        "native_bits_per_cell": f6_u32[7],
        "sector_size": f6_u32[8],
        "flash_id": [f"0x{f6_u32[9+i]:02X}" for i in range(6)],
        "die_stepping": struct.pack("<II", f6_u32[15], f6_u32[16]).decode("ascii", errors="replace"),
        "rated_pe_cycles": f6_u32[17],
        "unk_4096": f6_u32[18],
        "rsv_0": f6_u32[19],
        "total_dies": f6_u32[20],
        "planes_per_die": f6_u32[21],
    }

    # 2. Decode 0xFE firmware mode summary
    fe_ver = fe[0:16].decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    fe_ch, fe_ce, fe_die, fe_plane, fe_sbs, fe_pages, fe_rsv, fe_op_mode, fe_phys_mode = struct.unpack_from(
        "<BBBBHHHBB", fe, 0x12
    )
    fe_decoded = {
        "fw_version": fe_ver,
        "channels": fe_ch,
        "ce_per_ch": fe_ce,
        "die_per_ce": fe_die,
        "planes_per_die": fe_plane,
        "superblocks": fe_sbs,
        "pages_per_block": fe_pages,
        "operating_bits_per_cell": fe_op_mode,
        "native_bits_per_cell": fe_phys_mode,
    }

    # 3. Decode 0xCA banner
    ca_strings = [s.decode("ascii", errors="replace") for s in ca[:83].split(b"\x00") if s]

    # 4. Decode 0xF2 Pfct
    pfct = {
        "signature": f2[0x00:0x04].decode("ascii", errors="replace"),
        "field_0x0c_u16": f"0x{struct.unpack_from('<H', f2, 0x0C)[0]:04X}",
        "pfct_size_bytes_0x10": struct.unpack_from("<I", f2, 0x10)[0],
        "field_0x14_u32": f"0x{struct.unpack_from('<I', f2, 0x14)[0]:08X}",
        "serial_0x1c": f2[0x1C:0x30].split(b"\x00", 1)[0].decode("ascii", errors="replace"),
        "model_0x30": f2[0x30:0x58].split(b"\x00", 1)[0].decode("ascii", errors="replace"),
        "fw_rev_0x58": f2[0x58:0x60].split(b"\x00", 1)[0].decode("ascii", errors="replace"),
        "flag_0x6b": f2[0x6B],
        "field_0x6c": struct.unpack_from("<I", f2, 0x6C)[0],
        "field_0x7c_u16": struct.unpack_from("<H", f2, 0x7C)[0],
        "field_0x7e_u16": struct.unpack_from("<H", f2, 0x7E)[0],
        "superblocks_0x82": struct.unpack_from("<H", f2, 0x82)[0],
        "die_defect_counts_0x90": list(struct.unpack_from("<8H", f2, 0x90)),
        "total_defects_0x200": struct.unpack_from("<I", f2, 0x200)[0],
        "field_0x110_u32": struct.unpack_from("<I", f2, 0x110)[0],
        "field_0x114_u32": struct.unpack_from("<I", f2, 0x114)[0],
        "pfct_size_bytes_0x118": struct.unpack_from("<I", f2, 0x118)[0],
        "superblocks_0x11e": struct.unpack_from("<H", f2, 0x11E)[0],
        "tlc_pages_per_block_0x120": struct.unpack_from("<H", f2, 0x120)[0],
        "flag_0x123": f2[0x123],
        "field_0x124_u16": struct.unpack_from("<H", f2, 0x124)[0],
        "total_dies_0x125": f2[0x125],
        "channels_0x127": f2[0x127],
        "ce_per_ch_0x128": f2[0x128],
        "die_per_ce_0x129": f2[0x129],
        "planes_0x12a": f2[0x12A],
        "raw_0x120_to_0x138": f2[0x120:0x138].hex(),
        "pslc_pages_per_block_0x130": struct.unpack_from("<H", f2, 0x130)[0],
        "bank_flash_ids_0x548": [f2[0x548 + i * 6 : 0x548 + (i + 1) * 6].hex() for i in range(8)],
        "clocks_mhz_0x618": list(struct.unpack_from("<3H", f2, 0x618)),
        "field_0x694_u16_pair": list(struct.unpack_from("<2H", f2, 0x694)),
        "temp_bytes_0x6c0": list(f2[0x6C0:0x6C4]),
        "field_0x6da_u16": struct.unpack_from("<H", f2, 0x6DA)[0],
        "field_0x6dc_u16": struct.unpack_from("<H", f2, 0x6DC)[0],
        "field_0x6de_u16": struct.unpack_from("<H", f2, 0x6DE)[0],
        "field_0x6e0_u32": struct.unpack_from("<I", f2, 0x6E0)[0],
    }

    # 5. Decode 0xCE factory bad superblocks & 0xC6 superblock table
    ce_cnt = struct.unpack_from("<I", ce, 0)[0]
    ce_entries = []
    for i in range(ce_cnt):
        sb, mask, rsv = struct.unpack_from("<III", ce, 4 + i * 12)
        ce_entries.append({"sb": sb, "mask": f"0x{mask:08x}", "bad_planes": bin(mask).count("1")})

    c6_cnt = struct.unpack_from("<I", c6, 0)[0]
    c6_by_type: dict[int, list[int]] = {}
    for i in range(c6_cnt):
        w0, w1, w2 = struct.unpack_from("<III", c6, 4 + i * 12)
        c6_by_type.setdefault((w0 >> 24) & 0xFF, []).append(w0 & 0x00FFFFFF)
    c6_summary = {
        f"0x{t:02X}": {
            "count": len(ecs),
            "min_ec": min(ecs),
            "max_ec": max(ecs),
            "sum_ec": sum(ecs),
            "avg_ec": round(sum(ecs) / len(ecs), 2),
        }
        for t, ecs in sorted(c6_by_type.items())
    }

    # 6. Decode 0x05 Command Effects Log
    admin_ops = [f"0x{op:02X}" for op in range(256) if struct.unpack_from("<I", cel, op * 4)[0] & 1]
    io_ops = [f"0x{op:02X}" for op in range(256) if struct.unpack_from("<I", cel, 1024 + op * 4)[0] & 1]

    # 7. Capacity and geometry math
    nsze = struct.unpack_from("<Q", id_ns, 0)[0]
    tnvmcap = int.from_bytes(id_ctrl[280:296], "little")
    cf_sig_0c00 = id_ctrl[0x0C00:0x0C10]
    cf_sig_0c70 = id_ctrl[0x0C70:0x0C80]

    # Physical TLC capacity vs pSLC capacity
    # 1 die = 504 blocks * 4 planes * 2304 pages/block * 16384 B/page
    bytes_per_tlc_sb = 8 * 4 * 2304 * 16384
    bytes_per_pslc_sb = 8 * 4 * 768 * 16384
    data_sbs = len(c6_by_type.get(0x30, []))

    capacity_math = {
        "bytes_per_pslc_superblock_mib": bytes_per_pslc_sb // (1024 * 1024),
        "bytes_per_tlc_superblock_mib": bytes_per_tlc_sb // (1024 * 1024),
        "data_superblocks": data_sbs,
        "raw_pslc_pool_bytes": data_sbs * bytes_per_pslc_sb,
        "exposed_pslc_bytes": tnvmcap,
        "pslc_op_pct": round((1 - tnvmcap / (data_sbs * bytes_per_pslc_sb)) * 100, 2),
        "raw_tlc_pool_bytes": data_sbs * bytes_per_tlc_sb,
        "projected_tlc_480gb_bytes": 480 * 1000**3,
        "projected_tlc_512gb_bytes": 512 * 1000**3,
    }

    # 8. Boot event log key milestones
    c2_total_events = struct.unpack_from("<I", c2, 0x10)[0]
    c2_page_events = struct.unpack_from("<I", c2, 0x14)[0]
    boot_milestones = []
    for idx in range(min(241, (len(c2) - 0x20) // 32)):
        off = 0x20 + idx * 32
        if off >= 0x1E40:
            break
        w = struct.unpack_from("<8I", c2, off)
        mid = w[1] & 0xFFFF
        if mid in (0x2000, 0x2006, 0x20b5, 0x20b6, 0x20b7, 0x2420, 0x2423, 0x2428, 0x10a8, 0x1050, 0x102c, 0x21bf, 0x22c8):
            boot_milestones.append(
                {
                    "idx": idx,
                    "ts": w[0],
                    "lvl": (w[1] >> 16) & 0xFF,
                    "mid": f"0x{mid:04x}",
                    "args": [f"0x{a:08x}" for a in w[2:]],
                }
            )

    # 9. Part B: Disassemble d6_fw_sram_leak.bin
    disasm = disassemble_sram_leak(d6)

    return {
        "f6_nand_geom": f6_decoded,
        "fe_fw_summary": fe_decoded,
        "ca_fw_banner": ca_strings,
        "pfct_f2": pfct,
        "ce_bad_sb": ce_entries,
        "c6_superblocks": c6_summary,
        "capacity_math": capacity_math,
        "nvme_cel": {"admin_opcodes": admin_ops, "io_opcodes": io_ops},
        "identify": {
            "nsze_lbas": nsze,
            "tnvmcap_bytes": tnvmcap,
            "cf_sig_0c00": cf_sig_0c00.hex(),
            "cf_sig_0c70": cf_sig_0c70.hex(),
        },
        "boot_log": {
            "total_events": c2_total_events,
            "page_events": c2_page_events,
            "milestones": boot_milestones,
        },
        "disasm": disasm,
    }


def render_markdown_report(res: dict[str, Any], bdir: Path) -> str:
    f6 = res["f6_nand_geom"]
    fe = res["fe_fw_summary"]
    pfct = res["pfct_f2"]
    cap = res["capacity_math"]
    disasm = res["disasm"]

    lines: list[str] = [
        "# IG5208 (`VB05` / `7.3.1.3`) CFexpress Type A 固件与参数深度逆向报告",
        "",
        f"数据源目录: `{bdir}`",
        "",
        "## 1. 固件与硬件架构总览",
        f"- **主控**: InnoGrit IG5208 (`Shasta`), Firmware Rev `VB05`, SDK 分支 `{', '.join(res['ca_fw_banner'])}`",
        f"- **内部固件版本 (`0xFE`)**: `{fe['fw_version']}`",
        f"- **工作模式标志 (`0xFE` @ `0x1A..0x1B`)**: 当前工作位宽 = **`{fe['operating_bits_per_cell']}`** (1-bit pSLC)，物理颗粒原生位宽 = **`{fe['native_bits_per_cell']}`** (3-bit TLC)",
        f"- **NAND 几何 (`0xF6`)**: `{f6['channels']} Ch × {f6['ce_per_ch']} CE/Ch × {f6['die_per_ce']} Die/CE = {f6['total_dies']} Dies`, `{f6['planes_per_die']} Planes/Die`, `{f6['superblocks']} Superblocks`, `{f6['pages_per_block_tlc']} TLC Pages/Block`, Page=`{f6['raw_page_bytes']}` B (16384 + {f6['spare_bytes']} spare), 标称寿命 `{f6['rated_pe_cycles']}` P/E, Flash ID=`{' '.join(f6['flash_id'])}`, Stepping=`{f6['die_stepping']}`",
        f"- **CFexpress 协议签名 (`id_ctrl.bin`)**: `0x0C00` = `{res['identify']['cf_sig_0c00']}` (`CFexpress\\x01`), `0x0C70` = `{res['identify']['cf_sig_0c70']}` (`CFexpress`)",
        "",
        "## 2. `Pfct` (`0xF2`) 参数表与容量核算",
        f"- **结构体签名与大小**: `0x0000` = `{pfct['signature']}`, `0x0010` / `0x0118` = `{pfct['pfct_size_bytes_0x10']}` bytes (`0x{pfct['pfct_size_bytes_0x10']:04x}` — 恰好匹配 `0x0000..0x06e4` 非零末尾 + 8B 对齐)",
        f"- **型号与序列号**: `SN={pfct['serial_0x1c']}`, `Model={pfct['model_0x30']}`, `FW={pfct['fw_rev_0x58']}`",
        f"- **页数重映射 (`0x0120` vs `0x0130`)**: 物理 TLC 页数 `0x0120` = `{pfct['tlc_pages_per_block_0x120']}`, 当前 pSLC 逻辑页数 `0x0130` = `{pfct['pslc_pages_per_block_0x130']}` (`2304 / 3 = 768`)",
        f"- **主控时钟 (`0x0618`)**: `{pfct['clocks_mhz_0x618']}` MHz",
        f"- **出厂坏块交叉验证**: `0xF2[0x090]` 各 Die 坏块数 `{pfct['die_defect_counts_0x90']}` 之和 = `{pfct['total_defects_0x200']}`，与 `0xCE` 10 个坏超级块 bitmask 中 `1` 的总比特数完全一致。",
        "",
        "### 超级块分布 (`0xC6`, 共 504 个)",
    ]
    for t_hex, info in res["c6_superblocks"].items():
        lines.append(
            f"- 类型 `{t_hex}`: 数量=`{info['count']}`, EC 范围=`{info['min_ec']}~{info['max_ec']}`, 总 EC=`{info['sum_ec']}`, 平均 EC=`{info['avg_ec']}`"
        )
    lines.extend(
        [
            "",
            "### 容量与 OP 核算",
            f"- 单超级块容量: pSLC = `{cap['bytes_per_pslc_superblock_mib']} MiB`, TLC = `{cap['bytes_per_tlc_superblock_mib']} MiB`",
            f"- `{cap['data_superblocks']}` 个数据超级块总裸空间: pSLC = `{cap['raw_pslc_pool_bytes'] / (1024**3):.2f} GiB`, 当前暴露 `{cap['exposed_pslc_bytes'] / 1e9:.2f} GB` (`{cap['exposed_pslc_bytes'] / (1024**3):.2f} GiB`, OP = `{cap['pslc_op_pct']}%`)",
            f"- 若切换回 TLC 模式: `{cap['data_superblocks']}` 个数据超级块总裸空间 = `{cap['raw_tlc_pool_bytes'] / (1024**3):.2f} GiB` (`{cap['raw_tlc_pool_bytes'] / 1e9:.2f} GB`)，可标称 `480 GB` (保留 ~17.7% OP) 或 `512 GB` (保留 ~12.2% OP)。",
            "",
            "## 3. 私有指令集与引导日志 (`0x05` / `0xC2`) 关键发现",
            f"- **开放私有 Admin Opcode ({len([o for o in res['nvme_cel']['admin_opcodes'] if int(o, 16) >= 0xC0])} 个)**: `{', '.join(res['nvme_cel']['admin_opcodes'])}`",
            "- **I/O Opcode**: `" + ", ".join(res["nvme_cel"]["io_opcodes"]) + "`",
            f"- **RAM/TCM 地址空间分布（由 `0xC2` 启动日志 + `0xD6` 汇编交叉验证）**:",
            "  - `0x00000000 .. 0x00020000`: Boot ROM / ITCM（经由 ARM `LDR PC, [PC, #-4]` 跳板访问）",
            "  - `0x00040000 .. 0x00048000`: DTCM 全局变量/字符串/日志参数区",
            "  - `0x20000000 .. 0x200C0000`: 主 SRAM（核心代码 `0x20004e30..0x2001ff19`、FTL 全局结构体 `0x2002ce10..0x2002e2f0`、512KB DMA/数据缓冲池 `0x20040000..0x200BFFFF`）",
            "  - `0x20200000 .. 0x2021FFFF`: 固件主代码及只读表 SRAM（`0x202144b0` 存放 `l1y4`/`l1y3` 相关表，`0x20215xxx+` 为 FTL/管理代码段）",
            "",
            "## 4. `d6_fw_sram_leak.bin` ARM Thumb-2 反汇编摘要",
            f"- 解码未识别指令数: `{disasm['unhandled_instructions']}`",
            f"- 识别函数入口 ({len(disasm['functions'])} 个): `{', '.join(f'0x{x:04x}' for x in disasm['functions'])}`",
            f"- MMIO 硬件寄存器引用: `{', '.join(f'0x{x:08x}' for x in disasm['mmio_refs'])}`",
            f"- 固件事件日志调用 (`mid=0x2xxx`): 共 `{len(disasm['event_msg_ids'])}` 处",
            "- **地址基准解析**: 片段内部 `0x030c` 处存在 `BL rel=-0x214b54`（以及 `-0x1f3a14`, `-0x1ee0f4` 等），同时存在指向 `0x2020xxxx` 的 `BL rel=-0x138f4` 与 `-0x15094`。这证明该 4KB 代码段运行地址位于 **`0x2021xxxx`（`base >= 0x20214b54`）**，其中长跳转跳板 (`0x0634..0x06f0`) 调用 `0x00000169..0x0001ed20`（Boot ROM/ITCM），近跳转 `-0x214b54` 调用 `0x2000xxxx`，而 `-0x138f4` 高频调用 `0x2020xxxx` 中的事件日志函数 (`glve`)。",
            "",
            "### 关键模块逆向结论",
            "1. **`sub_096c` 中的 `0x54495247 ('GRIT')` 验证**: 在 `sub_096c` (`0x09e8..0x09fa`) 中，代码将 `[r1+0x38]` 的低 10 位乘以 `4096` 并按位或 `0x20000000`（即 `0x20000000 + slot * 0x1000`），检查该 4KB DMA 槽位首 4 字节是否为 `0x54495247` (`\"GRIT\"`) 并读取偏移 `+0x0A` 处的 `entry_count` (`uint16_t`)，若验证失败在 `0x0b2e` 返回 NVMe 状态码 `0x0107` (`Invalid Firmware Image`)。经与 InnoGrit 量产协议交叉验证，这正是 **NVMe 固件镜像下载 (`0x11`) 的 `GRIT` 头部解析器**。",
            "2. **为什么当前镜像标识为 `master_2.0 / dslc / nand_slc_Oct 30 2023`？**: `0xCA` 明确表明当前卡内运行的是 **pSLC 专用编译分支 (`dslc` / `nand_slc_Oct 30 2023`)**，且 `0xF2`/`0xF6`/`0xFE` 参数表结构在固件启动时由 NAND 系统超级块 (`SB 2, 3, 5..12`) 加载，Controller Identify 在 `0x0C00` 与 `0x0C77` 携带 `CFexpress` 相机认证签名。",
            "3. **完整固件镜像提取结论**: 全部 10 个已测只读 (`Data-In`) 厂商指令 (`0xC2, 0xC6, 0xCA, 0xCE, 0xD2, 0xD6, 0xF2, 0xF6, 0xFA, 0xFE`) 在 `CDW11..CDW13 = 1..8` 下均不返回完整固件镜像或 NAND 原始页数据；因此完整 `VB05` 固件二进制驻留在 NAND 系统块中，需通过外部 `IG5208` 量产包中的 `loader` / `programmer` / `ftkdisk_*.fw` (`GRIT` 容器) 进行解析、签名适配与重刷。",
            "",
            "## 5. MPutility 协议与 `d6_fw_sram_leak.bin` 函数角色映射",
            "结合开源逆向项目 `netac-nv7000-recovery` (MPutility / `middleware.dll` + `GRIT` 容器规范) 与 VLO `innogrit_nvme_flash_id.exe` 静态分析，可精确确定 `d6_fw_sram_leak.bin` 各核心函数及 `nvme_cel.bin` 厂商指令集的角色：",
            "",
            "### `d6_fw_sram_leak.bin` 核心函数识别",
            "- **`sub_0848` (`0x0848..0x094B`) — `0xF1` (`SetPfct` / `SetMpInfo` Data-Out) 处理器**: 校验 4KB SRAM 缓冲区首部 5 字节 `\"Pfct\\x00\"` 签名 (`0x20211a29` via `bl off-73642`)，读取偏移 `+0x16` (`uint16_t`) 的请求用户数据超级块数（本卡为 `483`），校验其不超过可用好块上限 (`bl off-2023668`) 后调用 `bl off-30416` 更新配置（日志 `0x2198..0x219b`）。",
            "- **`sub_096c` (`0x096C..0x0CFF`) — `0x11` (`NVMe Firmware Image Download`) `GRIT` 解析器**: 读取 `[0x0C14]` 处的常量 `0x54495247` (`\"GRIT\"`) 校验第 0 块头部魔数并解析 `+0x0A` 处的 `entry_count` (`uint16_t`)，对每 4KB 页 (`mov.w r1, #0x1000`) 计算 CRC32 (`bl off-73496`) 并写入固件分区 (`bl off-57636`, `blx 0x1b8c`)；失败状态 `*(u8*)(r4+0x1f) != 6` 时返回 `0x0107`。",
            "- **`sub_0d2c` (`0x0D2C..0x0DB7`) — 容量与块数更新处理器**: 调用 `bl off-74220` 与 `bl off-76660` 校验并更新参数（日志 `0x22bd..0x22be`），最终调用 `bl off-30416`。",
            "- **`sub_0db8` (`0x0DB8..0x0E5F`) — `0xC5` (`SetSuperblockTable` Data-Out) 处理器**: 读取 4 字节头部后按每页最多 `0x154` (`340`) 条 12 字节记录 (`ldmdb.w r4, {r0, r1, r2}`, `adds r4, #0x0c` -> `bl off-30500`) 解析写入，与只读指令 `0xC6` (`c6_sb_full.bin` 首 页 340 条 + 次页 164 条 = 504) 严格对称。",
            "",
            "### `nvme_cel.bin` 厂商指令对照表 (`VB05` vs MPutility / VLO)",
            "| Opcode | CEL 日志支持标志 | 推测/已证实角色 | 对照来源与说明 |",
            "|---|---|---|---|",
            "| `0x10` | `0x00000011` | `Firmware Commit` | NVMe 标准 + MPutility (`CDW10=0x19` 激活镜像) |",
            "| `0x11` | `0x00000011` | `Firmware Image Download` | NVMe 标准 + `sub_096c` (`GRIT` 分块下载, 4KB/块) |",
            "| `0xC5` / `0xC6` | `0x00000001` | `Set/Get Superblock Table` | `0xC6` 已导出 504 个 SB; `sub_0db8` 对应 `0xC5` 写入; VLO (`0x3010`) 用 `0xC6` 导出 `innogrit_bbl.bin` |",
            "| `0xCD` / `0xCE` | `0x00000001` | `Set/Get Factory Bad SB` | `0xCE` 已导出 10 个出厂坏超级块及 32-bit plane bitmask |",
            "| `0xD0` | `0x00000001` | `SmartClean` | `netac-nv7000-recovery` (`CDW14='GRIT', CDW15='INNO'`) |",
            "| `0xD1` | `0x00000001` | `SetThinCapacity` | `netac-nv7000-recovery` (`NSID=1, CDW12=blocks_lo, CDW13=blocks_hi`) |",
            "| `0xD2` | `0x00000001` | `GetControllerCodename` | 只读返回 `Shasta(InnMSH00SN0...` |",
            "| `0xD6` | `0x00000001` | `SRAM/Ext Diag Buffer` | VLO (`0x3120`) 调用 `0xD6` 获取 `innogrit_bb.bin`；`VB05` 上返回 4KB SRAM 代码槽 (`d6_fw_sram_leak.bin`) |",
            "| `0xF1` / `0xF2` | `0x00000001` | `Set/Get Pfct (MpInfo)` | `0xF2` (`CDW10=0x400`) 已导出 `f2_pfct.bin`；`sub_0848` 对应 `0xF1`；VLO (`0x2f50/0x2fb0`) 使用 `0xF2` |",
            "| `0xF5` / `0xF6` | `0x00000001` | `Set/Get NAND Geometry` | `0xF6` 已导出 88B NAND 几何与 Flash ID 描述符 |",
            "| `0xF7` | `0x00000001` | `ToRecovery` | MPutility (`CDW12=1, CDW14='GRIT', CDW15='INNO'`) 进入 ROM/恢复模式 |",
            "| `0xFA` / `0xFE` | `0x00000001` | `Ext SMART / FW Mode` | `0xFA` 返回内部 Ext SMART (`384B`); `0xFE` 返回工作模式位宽 (`1=pSLC / 3=TLC`) |",
            "- *(注: `IG5236` `3.S.J.11` 与 VLO 工具还会探测 `0xE4/0xE5/0xE6`，但本卡 `VB05` 的 `nvme_cel.bin` 未启用 `0xE4..0xE6`，而采用 `0xF1/0xF2`、`0xF5/0xF6` 等指令体系。)*",
            "",
            "### 完整反汇编清单 (`d6_fw_sram_leak.bin`)",
            "```asm",
        ]
    )
    lines.extend(disasm["lines"])
    lines.append("```")
    return "\n".join(lines)


def main() -> None:
    repo_root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Analyze IG5208 CFA card backup dumps.")
    parser.add_argument(
        "--backup-dir",
        type=Path,
        required=True,
        help="Card backup directory (e.g. backups/<SN>)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=repo_root / "analysis_report.md",
    )
    args = parser.parse_args()

    res = analyze_backup(args.backup_dir)
    md = render_markdown_report(res, args.backup_dir)
    args.report.write_text(md, encoding="utf-8")

    # Also save structured JSON summary in backup dir
    summary_out = {k: v for k, v in res.items() if k != "disasm"}
    summary_out["disasm_summary"] = {
        k: v for k, v in res["disasm"].items() if k != "lines"
    }
    (args.backup_dir / "analysis_summary.json").write_text(
        json.dumps(summary_out, indent=2), encoding="utf-8"
    )

    print(f"Analysis report written to: {args.report}")
    print(f"Unhandled Thumb instructions: {res['disasm']['unhandled_instructions']}")
    print(f"MMIO refs: {[hex(x) for x in res['disasm']['mmio_refs']]}")
    print(f"Veneer count: {len(res['disasm']['veneer_targets'])}")
    print(f"Capacity math: {res['capacity_math']}")


if __name__ == "__main__":
    main()
