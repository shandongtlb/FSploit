# 需求:构建一个可被 Android App 直接调用的「完整功能 nmap」原生包

我在做一个 Android 渗透工具 App(已 root)。App 里已经写好了 nmap 的「下载-校验-解压-安装-调用」逻辑,现在缺一个**原生 arm64 的 nmap 发行包**。请你帮我产出这个包(`.tar.gz`),它必须严格满足下面的「打包契约」和「运行契约」,装进 App 后能跑 `-sn / -sV / -O / -A` 并输出 XML。

本包的定位与 bettercap 完全一致:**原生 Android 二进制,直接在 Android 用户空间以 root 运行,不依赖任何 chroot / Termux 运行时**。

---

## 1. 运行环境(目标设备)

- 设备:OnePlus 13,SoC arm64(aarch64)。
- 系统:Android 16,内核 Linux 6.6。
- C 库:**bionic**(Android 原生 libc),**不是 glibc**。二进制必须能在 bionic 上运行。
- 权限:以 **root(`su -c`)** 运行。
- 执行位置:从 App 私有目录执行,路径形如
  `/data/data/<appId>/files/toolchain/nmap/nmap`
  (即解压后整棵树放在 App 私有存储里,以 root 执行。bettercap、mitmdump 已用同样方式成功运行,可行性已验证。)

---

## 2. 运行契约(App 会怎么调用它)

App 通过 `su -c "<命令>"` 执行,命令前缀固定为:

```
LD_LIBRARY_PATH='<INSTALL_DIR>':$LD_LIBRARY_PATH '<INSTALL_DIR>/nmap' --datadir '<INSTALL_DIR>' <其余参数>
```

其中 `<INSTALL_DIR>` = 解压后那棵树的根目录(包含 `nmap` 可执行文件的那一层)。

具体会用到的三类命令(参数固定,你必须保证它们都能正常工作并输出 XML):

```bash
# A. 主机发现(局域网,秒级)
nmap --datadir <D> -sn -n --max-retries 2 -e <iface> -oX - <network>/<prefix>

# B. 端口扫描·普通(服务/版本探测)
nmap --datadir <D> -sS -sV -n -Pn -T4 -e <iface> -p <ports> -oX - <host>

# C. 端口扫描·高级(等价 -O -sV -sC --traceroute)
nmap --datadir <D> -A -n -Pn -T4 -e <iface> -p <ports> -oX - <host>

# D. UDP 扫描(精选高价值端口,固定端口集)
nmap --datadir <D> -sU -sV -n -Pn -T4 -e <iface> \
  -p 53,67,69,123,137,138,161,162,500,514,520,1434,1900,5060,5353 -oX - <host>
```

要点:
- 输出统一走 **`-oX -`**(XML 到 stdout),App 用 XmlPullParser 解析。必须保证以下 XML 字段能正常出现:
  - `<host>`、`<status state=...>`
  - `<address addr=... addrtype="ipv4">` 和 `<address addr=... addrtype="mac" vendor="...">`(**`vendor` 依赖 `nmap-mac-prefixes` 数据文件,务必打包**)
  - `<ports><port protocol=... portid=...><state state=...><service name=... product=... version=... extrainfo=.../></port></ports>`
  - `<os><osmatch name=... accuracy=.../></os>`
- 所有数据文件必须能通过 **`--datadir <INSTALL_DIR>`** 被找到(包括 NSE 的 `scripts/`、`nselib/`)。
- App 始终传 `-n`(不做 DNS 反查),所以**不需要可用的 DNS/NSS**,这点可以简化你的构建(避免静态 glibc 的 NSS 坑)。
- 需要 raw socket / 抓包能力(`-sS`、`-sn` 的 ARP、`-O`)——以 root 在真实内核上跑没问题,但 nmap 依赖 **libpcap**,必须随包提供(静态进二进制或带 `.so`)。

---

## 3. 打包契约(App 的安装器会怎么处理这个 tar.gz)——**硬性要求**

App 端安装器(已写死)的行为,你必须迎合:

1. **格式**:`.tar.gz`(gzip 压缩的 tar)。
2. **定位**:安装器会在解压结果里找到**第一个文件名为 `nmap` 的可执行文件**,把它所在目录当作「payload 根目录」,整目录搬为安装树。
   → 所以 `nmap` 这个可执行文件必须直接位于某一层目录的顶层(可以是 `./nmap` 或 `./nmap-android/nmap`,都行)。
3. **必需且非空的文件(安装器会校验,缺一个就判定安装失败)**,均位于 payload 根目录顶层:
   - `nmap`(可执行文件,文件名必须就叫 `nmap`)
   - `nmap-services`
   - `nmap-service-probes`
   - `nmap-os-db`
4. **绝对不能有符号链接 / 硬链接**:安装器解压时**直接跳过所有 symlink 和 hardlink 条目**。任何被链接的数据文件/库都必须**解引用成真实文件**打进包里(很多发行版的 nmap 数据文件或 NSE 是软链,务必展平)。
5. **共享库**:所有依赖的 `.so` 放进**安装树里(建议放 payload 根目录)**,安装器会把树里所有 `.so` 自动 chmod 可执行;运行时 `LD_LIBRARY_PATH` 指向根目录,所以 `.so` 放根目录即可被解析。
6. **子目录可以有**(如 `scripts/`、`nselib/`):安装器会递归把目录设为可读可进入,文件设为可读,`nmap` 设为可执行。

---

## 4. nmap 必须具备的功能 & 对应必带数据/依赖

功能(由上面的命令决定):主机发现(ARP/`-sn`)、SYN 扫描(`-sS`)、服务/版本探测(`-sV`)、OS 指纹(`-O`)、默认 NSE 脚本(`-sC`,经 `-A`)、traceroute(`--traceroute`)、**UDP 扫描(`-sU`)**、XML 输出(`-oX`)。

必带数据文件(全部解引用为真实文件,放 `--datadir` 根目录):
- `nmap-services`、`nmap-service-probes`、`nmap-os-db`(前述必校验三件)
- `nmap-mac-prefixes`(**`-sn` 输出 MAC 厂商名靠它**,务必带)
- `nmap-protocols`、`nmap-rpc`
- `nselib/`(整目录)和 `scripts/`(整目录,**含预生成的 `scripts/script.db`**,否则 `-sC`/`-A` 会报 NSE 加载失败)
- UDP 探测载荷(服务于 `-sU`):**本 App 已有 UDP 档,需要它**。`-sU` 靠这些载荷诱发回包,把端口判成 `open` 而非一片 `open|filtered`,缺了 UDP 结果会明显变差。处理方式取决于 nmap 版本:
  - 老版本读独立的 `nmap-payloads` 文件 → 解引用后打进包;
  - 你用的版本(如对方所述 7.99)若已把载荷**并入 `nmap-service-probes`** → 无需单独的 `nmap-payloads`,但要确保 `nmap-service-probes` 完整(本来就在必校验清单)。
  - 判定标准只有一个:用第 6 节 UDP 验收命令,确认 `-sU` 能在 53/161/123/5353 这类端口跑出 `open` 和 `<service>`。

依赖库(随包 `.so` 或静态进二进制):
- libpcap(必须)
- OpenSSL(libssl/libcrypto,`-sV` 探测 TLS 服务、部分 NSE 需要)
- liblua(NSE 引擎)
- libpcre2(或 libpcre)、zlib;如启用相关功能还需 libssh2
- C++ 运行时(nmap 是 C++):若动态链接需带 `libc++_shared.so`(NDK)

---

## 5. 建议构建路线(任选,推荐第一种)

**路线一(推荐):Android NDK 交叉编译。**
- 用 NDK(如 r26d)交叉编译 aarch64、API level 对齐 Android 16(如 `android-34`+)。
- 依次交叉编译依赖:zlib → OpenSSL → libpcap → liblua(5.3/5.4)→ libpcre2 →(可选 libssh2),再编译 nmap 主体,`--with-libpcap=...` 等指向你编的库。
- 尽量静态链接依赖以减少 `.so`;C++ 运行时按 NDK 方式处理(带 `libc++_shared.so` 或静态)。
- 产物:`nmap` 二进制 + 上面列的全部数据文件(从 nmap 源码 `nmap-*` 与 `scripts/`、`nselib/` 取)+ 残余 `.so`,按第 3 节布局打包。

**路线二(快速):重打包 Termux 的 nmap。**
- Termux 的 aarch64 仓库有为 Android bionic 构建的 `nmap`(数据文件在 `nmap` / `nmap-doc` 包里)。
- 取出 `bin/nmap`、`share/nmap/*`(数据文件 + `scripts/` + `nselib/`)、以及 `usr/lib` 下它依赖的 `.so`(libpcap、libssl、libcrypto、liblua、libpcre2、libc++_shared 等)。
- **务必解引用所有软链**(Termux 数据/库大量用软链),展平成真实文件,按第 3 节布局重组,再打 tar.gz。
- 注意 Termux 二进制默认按 Termux 前缀找库 → 用 `LD_LIBRARY_PATH` 覆盖(App 已做);数据路径用 `--datadir` 覆盖(App 已做)。验证 `nmap --version` 不缺库即可。

---

## 6. 验收清单(产出后请自测,最好在 aarch64 设备/模拟器以 root 跑)

```bash
D=<INSTALL_DIR>
# 1) 能启动、不缺 .so
LD_LIBRARY_PATH=$D nmap --version

# 2) 主机发现 + MAC/厂商(局域网内)
LD_LIBRARY_PATH=$D nmap --datadir $D -sn -n <局域网>/24 -oX - | grep -E 'addrtype="mac"|osmatch|service' 

# 3) 服务/版本
LD_LIBRARY_PATH=$D nmap --datadir $D -sV -n -Pn -p 22,80,443 <host> -oX -

# 4) 高级(OS + 默认脚本 + traceroute)——确认无 "NSE: failed to load"
LD_LIBRARY_PATH=$D nmap --datadir $D -A -n -Pn -p 22,80,443 <host> -oX -

# 5) UDP(精选端口)——确认能跑出 open 与 <service>,而非清一色 open|filtered
LD_LIBRARY_PATH=$D nmap --datadir $D -sU -sV -n -Pn -p 53,123,161,5353 <host> -oX -
```

包本身的检查:
```bash
tar tzvf nmap-android-arm64-package.tar.gz | grep '^l'   # 必须为空(无符号链接)
tar tzf  nmap-android-arm64-package.tar.gz | grep -E '/nmap$|nmap-services$|nmap-service-probes$|nmap-os-db$|nmap-mac-prefixes$|scripts/script.db$'
```
要求:无 symlink;`nmap` + 四个必校验文件 + `nmap-mac-prefixes` + `scripts/script.db` 都在。

---

## 7. 交付物(给我这三样)

1. `nmap-android-arm64-package.tar.gz`(满足上述全部契约)。
2. 该文件的 **SHA-256**(十六进制,大小写均可)。
3. (可选)你放它的下载直链(我会发布到自己的 GitHub release)。

我拿到后只需在 App 里填两行常量即可启用:
```kotlin
NMAP_ARCHIVE_URL    = "<下载直链>"
NMAP_ARCHIVE_SHA256 = "<SHA-256>"
```

---

### 备注(给构建方的关键提醒)
- 目标是 **bionic / aarch64 / Android 16**,不是 glibc Linux;别交给我一个 PC Linux 的 nmap。
- **零符号链接**是硬要求(安装器会跳过软链),所有链接必须展平为真实文件。
- `--datadir` 必须能让 nmap 找到**全部**数据文件**和** `scripts/`、`nselib/`。
- `nmap-mac-prefixes` 和 `scripts/script.db` 容易漏,直接影响 `-sn` 的厂商名和 `-A` 的脚本——务必包含。
