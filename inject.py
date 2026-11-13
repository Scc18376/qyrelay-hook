#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
inject.py — 向 Mach-O 注入 LC_LOAD_DYLIB（不依赖 insert_dylib/optool）

原理:
  1. 解析 load commands，找到 __TEXT 段头与之之间的空隙，或扩展 header 区
  2. 在 ncmds 之后插入一条 LC_LOAD_DYLIB
  3. 修正 sizeofcmds / ncmds
  4. 后续所有 segment 的 fileoff 若在插入点之后，统一后移

用法:
  python3 inject.py <macho> <dylib_path> [--dry]
"""
import struct
import sys
import os
import shutil

MH_MAGIC_64 = 0xfeedfacf
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xc
LC_CODE_SIGNATURE = 0x1d
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xb
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
LC_DYLIB_CODE_SIGN_DRS = 0x2b
LC_LINKER_OPTIMIZATION_HINT = 0x2e
LC_EXPORTS_TRIE = 0x80000033
LC_CHAINED_FIXUPS = 0x80000034

# 这些 load command 内部含 file offset，需要随插入点后移
OFFSET_BEARING = {
    LC_SEGMENT_64,            # +40 fileoff
    LC_CODE_SIGNATURE,        # +8  dataoff
    LC_SYMTAB,                # +8 symoff, +16 stroff
    LC_DYLD_INFO, LC_DYLD_INFO_ONLY,   # +8..+40 五个 offset
    LC_FUNCTION_STARTS,
    LC_DATA_IN_CODE,
    LC_DYLIB_CODE_SIGN_DRS,
    LC_LINKER_OPTIMIZATION_HINT,
    LC_EXPORTS_TRIE,
    LC_CHAINED_FIXUPS,
}


def align(v, a=8):
    return (v + a - 1) & ~(a - 1)


def make_dylib_cmd(path: str, timestamp=2, cur_ver=0x10000, compat=0x10000) -> bytes:
    name = path.encode("utf-8") + b"\0"
    # 头部 24 字节 + 名称，8 字节对齐
    size = align(24 + len(name))
    name_off = 24
    cmd = struct.pack("<IIIIII", LC_LOAD_DYLIB, size, name_off,
                      timestamp, cur_ver, compat)
    cmd += name
    cmd = cmd.ljust(size, b"\0")
    return cmd


def parse_header(data):
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = \
        struct.unpack_from("<IiiIIIII", data, 0)
    if magic != MH_MAGIC_64:
        raise SystemExit(f"不是 64 位 Mach-O (magic={magic:#x})")
    return dict(magic=magic, cputype=cputype, cpusubtype=cpusubtype,
                filetype=filetype, ncmds=ncmds, sizeofcmds=sizeofcmds,
                flags=flags, reserved=reserved)


def iter_cmds(data, hdr):
    off = 32
    for i in range(hdr["ncmds"]):
        cmd, size = struct.unpack_from("<II", data, off)
        yield off, cmd, size
        off += size


def inject(macho: str, dylib: str, dry=False):
    data = bytearray(open(macho, "rb").read())
    hdr = parse_header(data)

    # 若已注入过则跳过
    for off, cmd, size in iter_cmds(data, hdr):
        if cmd == LC_LOAD_DYLIB:
            body = data[off:off + size]
            name_off = struct.unpack_from("<I", body, 8)[0]
            nm = bytes(body[name_off:]).split(b"\0")[0].decode("utf-8", "replace")
            if dylib in nm:
                print(f"[=] 已存在 LC_LOAD_DYLIB: {nm}")
                return True

    new_cmd = make_dylib_cmd(dylib)
    add = len(new_cmd)
    insert_at = 32 + hdr["sizeofcmds"]

    # 检查插入点之后到第一个 section 数据之间是否有足够空隙
    # __TEXT 段第一个 section 的文件偏移通常 >= 0x4000，可安全容纳
    first_content = None
    for off, cmd, size in iter_cmds(data, hdr):
        if cmd == LC_SEGMENT_64:
            fileoff = struct.unpack_from("<Q", data, off + 40)[0]
            filesize = struct.unpack_from("<Q", data, off + 48)[0]
            if fileoff == 0 and filesize > 0:
                # 找该段里第一个 section 的 offset
                nsects = struct.unpack_from("<I", data, off + 64)[0]
                if nsects:
                    sec_off = struct.unpack_from("<I", data, off + 72 + 48)[0]
                    first_content = sec_off
                break
    if first_content is None:
        first_content = insert_at + add
    if insert_at + add > first_content:
        raise SystemExit(
            f"头部空间不足: 插入需至 {insert_at+add:#x}，但首个 section 起于 {first_content:#x}")

    print(f"[*] ncmds {hdr['ncmds']} -> {hdr['ncmds']+1}")
    print(f"[*] sizeofcmds {hdr['sizeofcmds']} -> {hdr['sizeofcmds']+add}")
    print(f"[*] 插入点 {insert_at:#x}，新命令 {add} 字节，首个 section @ {first_content:#x}")
    print(f"[*] 剩余空隙 {first_content - (insert_at+add)} 字节")

    if dry:
        print("[dry-run] 未写入")
        return True

    shutil.copy2(macho, macho + ".orig")

    # 1) 插入命令
    data[insert_at:insert_at] = new_cmd

    # 2) 更新 header
    struct.pack_into("<II", data, 16, hdr["ncmds"] + 1, hdr["sizeofcmds"] + add)

    # 3) 修正“位于插入点之后”的所有 file offset
    #    新命令插在 header 空隙里，但整个文件尾部数据后移了 add 字节，
    #    因此所有 >= insert_at 的偏移必须同步 +add，否则签名/LINKEDIT 全部错位。
    for off, cmd, size in iter_cmds(data, header_of(data)):
        if cmd == 0x19:                                  # LC_SEGMENT_64
            fileoff = struct.unpack_from("<Q", data, off + 40)[0]
            if fileoff and fileoff >= insert_at:
                struct.pack_into("<Q", data, off + 40, fileoff + add)
        elif cmd == 0x1d:                                # LC_CODE_SIGNATURE
            fo = off + 8
            v = struct.unpack_from("<I", data, fo)[0]
            if v and v >= insert_at:
                struct.pack_into("<I", data, fo, v + add)
        elif cmd == 0x2:                                 # LC_SYMTAB
            for fo in (off + 8, off + 16):
                v = struct.unpack_from("<I", data, fo)[0]
                if v and v >= insert_at:
                    struct.pack_into("<I", data, fo, v + add)
        elif cmd in (0x22, 0x80000022):                  # LC_DYLD_INFO[_ONLY]
            for k in range(5):
                fo = off + 8 + k * 8
                v = struct.unpack_from("<I", data, fo)[0]
                if v and v >= insert_at:
                    struct.pack_into("<I", data, fo, v + add)
        elif cmd in (0x26, 0x29, 0x2b, 0x2e, 0x80000033, 0x80000034):
            # FUNCTION_STARTS / DATA_IN_CODE / DYLIB_CODE_SIGN_DRS /
            # LINKER_OPT_HINT / EXPORTS_TRIE / CHAINED_FIXUPS
            fo = off + 8
            v = struct.unpack_from("<I", data, fo)[0]
            if v and v >= insert_at:
                struct.pack_into("<I", data, fo, v + add)

    # 4) 结构校验：段不得重叠、不得越界
    segs = []
    symend = 0
    for off, cmd, size in iter_cmds(data, header_of(data)):
        if cmd == 0x19:
            nm = data[off + 8:off + 24].rstrip(b"\0").decode("latin1")
            fileoff = struct.unpack_from("<Q", data, off + 40)[0]
            filesize = struct.unpack_from("<Q", data, off + 48)[0]
            if filesize:
                segs.append((nm, fileoff, filesize))
        elif cmd == 0x1d:
            do, ds = struct.unpack_from("<II", data, off + 8)
            symend = do + ds
    segs.sort(key=lambda x: x[1])
    for i in range(len(segs) - 1):
        n1, f1, s1 = segs[i]
        n2, f2, s2 = segs[i + 1]
        if f1 + s1 > f2:
            raise SystemExit(f"段重叠: {n1} 尾 {f1+s1:#x} > {n2} 头 {f2:#x}")
    if max(f + s for _, f, s in segs) > len(data):
        raise SystemExit("段越界")
    if symend and symend > len(data):
        raise SystemExit(f"签名区越界: {symend:#x} > {len(data):#x}")
    print(f"[+] 偏移已修正，结构校验通过 (签名区 {symend:#x} / 文件 {len(data):#x})")

    open(macho, "wb").write(data)
    print(f"[+] 已注入 {dylib}")
    return True


def header_of(data):
    return parse_header(data)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    inject(sys.argv[1], sys.argv[2], dry="--dry" in sys.argv)
