# QyRelayHook

腾讯视频 iOS 取流劫持 dylib（对位 Android 版 `local.mobile.DefinitionRelay`）。

## 构建

推送到 main 分支，或手动触发 `Build QyRelayHook dylib` 工作流。
产物在 Actions 页面的 Artifacts 里。

## 注入

```bash
python3 inject.py <主二进制> "@executable_path/Frameworks/QyRelayHook.dylib"
```

## 签名

```bash
ldid -S<entitlements.plist> -I<bundleid> -K<cert.p12> -U<password> <主二进制>
```
