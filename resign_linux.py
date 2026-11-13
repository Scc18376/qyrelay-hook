#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
resign_linux.py — 纯 Linux 环境下的 iOS 重签工具（不依赖 macOS/security/codesign）

功能:
  1. 用 ldid 生成签名（ad-hoc 或带 entitlements）
  2. 改写 Info.plist 的 CFBundleIdentifier
  3. 写入 embedded.mobileprovision
  4. 重新打包 IPA

用法:
  python3 resign_linux.py --app <解包目录里的 .app> --bid <新bundleid> \
                          --prov <mobileprovision> --ent <entitlements.plist>
"""
import argparse
import os
import plistlib
import shutil
import subprocess
import sys
import zipfile


def sh(cmd, check=True):
    print("  $", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.stdout.strip():
        print("   ", r.stdout.strip()[:400])
    if r.stderr.strip():
        print("   !", r.stderr.strip()[:400])
    if check and r.returncode != 0:
        raise SystemExit(f"命令失败: {cmd[0]} rc={r.returncode}")
    return r


def set_bundle_id(app, newbid):
    pl = os.path.join(app, "Info.plist")
    with open(pl, "rb") as f:
        d = plistlib.load(f)
    old = d.get("CFBundleIdentifier")
    d["CFBundleIdentifier"] = newbid
    # 部分 App 的扩展也有独立 bundle id，一并处理
    for k in ("CFBundleName", "CFBundleDisplayName"):
        pass
    with open(pl, "wb") as f:
        plistlib.dump(d, f)
    print(f"    bundle id: {old} -> {newbid}")
    return old


def resign_all(app, ent, ldid):
    exe = None
    pl = os.path.join(app, "Info.plist")
    with open(pl, "rb") as f:
        exe = plistlib.load(f).get("CFBundleExecutable")

    # 1) 先签所有嵌套的 dylib / framework / appex / bundle
    targets = []
    for root, dirs, files in os.walk(app):
        for d in list(dirs):
            p = os.path.join(root, d)
            if d.endswith((".framework", ".appex", ".app")) and p != app:
                targets.append(p)
        for f in files:
            if f.endswith(".dylib"):
                targets.append(os.path.join(root, f))

    # 深度优先：越深越先签
    targets.sort(key=lambda p: p.count(os.sep), reverse=True)
    for t in targets:
        print(f"  签 {os.path.relpath(t, app)}")
        sh([ldid, f"-S{ent}", t], check=False)

    # 2) 签主二进制
    binp = os.path.join(app, exe)
    if not os.path.exists(binp):
        raise SystemExit(f"主二进制不存在: {binp}")
    print(f"  签主二进制 {exe}")
    sh([ldid, f"-S{ent}", binp])

    return binp


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--app", required=True, help=".app 目录")
    a.add_argument("--bid", required=True, help="新 bundle id")
    a.add_argument("--prov", required=True, help="mobileprovision")
    a.add_argument("--ent", required=True, help="entitlements plist")
    a.add_argument("--ldid", default="/usr/local/bin/ldid")
    args = a.parse_args()

    app = args.app
    if not os.path.isdir(app):
        raise SystemExit(f"目录不存在: {app}")

    print("[1] 写入 embedded.mobileprovision")
    shutil.copy2(args.prov, os.path.join(app, "embedded.mobileprovision"))

    print("[2] 改写 bundle id")
    set_bundle_id(app, args.bid)

    print("[3] 清理旧签名")
    shutil.rmtree(os.path.join(app, "_CodeSignature"), ignore_errors=True)
    bs = os.path.join(app, "SC_Info")
    if os.path.isdir(bs):
        print("   注意: 存在 SC_Info（FairPlay 残留），脱壳包应无此项")

    print("[4] 重签")
    binp = resign_all(app, args.ent, args.ldid)

    print("[5] 校验")
    r = sh([args.ldid, "-d", binp], check=False)
    print("\n✅ 重签完成")
    print(f"   主二进制: {binp}")


if __name__ == "__main__":
    main()
