# Lesson1 作业解答 —— MoMoWords

| 项 | 内容 |
|---|---|
| 学员 | deathbook |
| 样本 | `maimemo_v5.6.00_900_1788339161.apk`（`com.maimemo.android.momo` v5.6.00 / build 900，123,994,114 B，SHA256 `A2801079…D2D06D`） |
| 目标 | 将可用单词上限修改到无限 |
| **答案仓库** | **https://github.com/deathbook/maimemo-v5.6.0-crack** |
| 真机环境 | Xiaomi 23116PN5BC / Android 16 / arm64 |

---

## 一、结果

| 项 | 结果 |
|---|---|
| 本地效果 | `a.s()` / `x1d.f(false)` / `r47.getAvailableWordLimit()` **= 2147483647（无限）** |
| 上报效果 | 上报路径仍返回**服务端真实值**（实测 5012），服务端看不到任何异常 |
| 交付形态 | ① **无 root 独立包**（Frida gadget，普通安装即生效）② **LSPosed 模块**（12.7 KB，官方包不动） |

真机日志（自定义 tag，无 root、无 frida-server）：

```
I MoMoBoot : dladdr self=/data/data/com.maimemo.android.momo/cache/momoco-host-native-…/libmomoco.so
I MoMoBoot : chain dlopen(libmomoco.so) -> 0xc748…   real libmomoco JNI_OnLoad=0x6e8351d458
I MoMoBoot : extract ok=1 js=…/mmc.js so=…/libmmcore.so
I MoMoBoot : dlopen(gadget) -> 0x1f97…
I MoMoCrack: [OK] hook a.s()  => 2147483647（仅上报路径回落真实值）
I MoMoCrack: [OK] hook x1d.f(boolean)  => 2147483647
I MoMoCrack: [OK] 已包装上报构造 ada.b() / s40.m() / gq2.m()
I MoMoCrack: [INFO] x1d.f(false) = 2147483647
I MoMoCrack: [INFO] 上报模式读到的真实值: 单词上限=5012 可用上限=5012
I MoMoCrack: SELFTEST ok local=2147483647 reporting=5012 stealth=true origCallOk
```

---

## 二、保护分析

| 层 | 组件 | 说明 |
|---|---|---|
| 壳 | 梆梆 SecNeo | `libDexHelper.so` + 77 MB `classes.dex`（**只有 35 个类**，真正内容是其后的加密载荷） |
| 方法抽取 | Fort `andjni` | `libdexjni.so` 里 1018 个类的函数体是 nop 桩，业务逻辑搬进了 native |
| 反调试 | — | `frida spawn` 会 `SIGSEGV SI_TKILL` 自毁；壳会把自己从 `/proc` 枚举里隐藏 |

**脱壳**：hook `libdexfile.so` 的 `DexFileLoader::OpenCommon`，落盘得到 4 个业务 dex（31,086 个类）。

**目标链路**：

```
a.s()                    = JniLib0.cI(a.class, 23)      单词上限（默认 600）
x1d.f(boolean)           = a.s() − 已学词数             可用单词上限
r47.getAvailableWordLimit(fb2)                           Compose 侧同一式子
gq2.c() / gq2.h()                                        欠债数 / 欠债开关
dma.a(int,String,String) 解密本地 inf_tb.inf_words_limit
```

---

## 三、四个关键结论

### 1. 壳的完整性校验只覆盖 `lib/` 目录

往 `lib/arm64-v8a/` 加**任何一个文件**（一个字节都不改）都会自毁：

```
Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0xa98
```

但 `META-INF/native/` 的增删改完全放行 —— 这是无 root 方案的地基。
（后续 LSPatch 实验进一步确认：连改 `AndroidManifest.xml`、追加 loader dex 都不触发自毁，
壳**不校验 Manifest、也不校验 dex 数量**。）

### 2. 无 root 注入点：`BaseAppContext.<clinit>`

它发现 classpath 存在 `META-INF/native/libmomoco.so` 时，会解到 App cache 目录再 `System.load()`。
于是可以**一个字节都不动 `lib/`，却执行任意 arm64 原生代码**。

### 3. 难点：frida-gadget 找不到配置文件

gadget 只认「自己所在目录 / `<stem>.config.so`」，而那个临时目录名随机、`g57.k()` 又只写一个文件
—— 配置无法预置，gadget 回落到默认 `on_load: wait`，卡死启动页。

**解法**：自制 17 KB 引导层 `libmmboot.so` 顶替 `libmomoco.so`，在 `JNI_OnLoad` 里：
① `dladdr` 定位自身 → ② `dlopen("libmomoco.so")` 把真身链式加载回来 → ③ 从自身文件尾部 footer
自解包出内嵌的 gadget + JS 写到同目录 → ④ 生成配置并 `dlopen` gadget（**不监听端口、不等 attach**）。

### 4. 反封号：上报一致性（「表里不一」）

服务端三条聚合上报链路会带上限值：`/log/study_log`（`ada.b()`）、`/misc/system/check`（`s40.m()`）、
债务上报（`gq2.m()`）。如果本地无限、上报也报 2147483647，一次请求就是破解特征。

做法：包装这三个构造函数，进入时置**线程级**「上报模式」标志，期间 `a.s()/x1d.f()/dma.a()`
返回**真实值**，出栈立刻恢复无限。逐词 oplog 与备份 ZIP 保持诚实，记忆曲线同步不受影响。

还有一个必须避开的坑：**hook 里不能先调原实现** —— `a.s()` 走 JNI 会开 SQLite，
未登录/DB 未建立时抛异常，异常会直接从 hook 冒出去。正确写法是**非上报路径直接 setResult**。

---

## 四、答案仓库结构

```
https://github.com/deathbook/maimemo-v5.6.0-crack

docs/     Lesson1_Writeup.md              完整技术报告（保护分析 / 脱壳 / 链路 / 验证）
          Lesson1_Noroot_Standalone.md    无 root 独立包专题
          Install_Troubleshooting.md      安装失败（packageInfo is null）排查
          Performance_Notes.md            性能实测：Frida 的开销地板
          LSPatch_Probe_Result.md         LSPatch 在 Android 16 不可用的实测
native/     loader.c                        自解包引导层（arm64，zig 交叉编译，无需 NDK）
frida/      entry_crack.js                  破解 + 反封号脚本
            dump_dex.js                     OpenCommon 脱壳
scripts/    build_standalone.py / verify_standalone.py / bench_app.py / apk_struct_diff.py …
module/     momocrack-module.apk            LSPosed 模块（12.7 KB）+ smali 源码
```

**二进制产物在 Releases**：`maimemo_v5.6.0_cracked_standalone.apk`（134 MB，普通安装即生效）、
`unpacked_dex.zip`（脱壳 dex ×5 + 手工补丁后的 dex）、`native_libs.zip`（原版/补丁/payload 的 .so）。

```bash
adb install -r maimemo_v5.6.0_cracked_standalone.apk
adb logcat -s MoMoBoot:I MoMoCrack:I
```

---

## 五、已知边界

* 独立包只内嵌 arm64-v8a 的 gadget（`META-INF/native/libmomoco.so` 只能是一个文件，无法同时满足两种 ABI）。
* Android 16 上 `System.load` 可写的 cache 文件会打警告 `Attempt to load writable file`，
  未来版本若改为抛错，这条注入路径需要换落点。
* 性能：Frida 的 hook 有"在场成本"（相关类退出 ART AOT/JIT），到不了官方版跟手度；
  要更好体验用 LSPosed 模块。
* 安装：重打包包与官方包**签名不同**，手机上必须先卸载官方版，否则报
  `解析软件包时出现问题 / packageInfo is null`。
