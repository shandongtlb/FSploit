# FSploit 研究会话总结：三星 SM8750 (S25 系列) MITM 分析

## 会话概述
本次会话深入调查了在高端三星设备 (SM8750，Android 15，One UI 7) 上，尽管拥有 Root 权限和功能完备的工具链 (Bettercap/arpspoof)，传统的同 Wi-Fi ARP MITM (欺骗) 依然失败的根本原因。

## 技术发现

### 1. “无形的墙”
即使在 UID 0 (root) 下，ARP 欺骗包在离开物理天线前，也会在 STA（Wi-Fi 客户端）模式下被静默丢弃。
- **现象**：Bettercap 能够通过 `AF_PACKET` 成功发包，但网关的 ARP 表完全没有改变。
- **对比**：同样搭载 SM8750 (高通网卡) 的一加 13 (ColorOS) 在相同环境下 **能够成功** 进行 ARP 欺骗。这证明了底层硬件完全具备该能力，差异在于软件/固件的实现。

### 2. Framework 层的干预 (Android/三星)
通过 dump `dumpsys wifi`，我们发现了 `system_server` 进程通过 `ClientModeImpl` 状态机主动发起的干扰：
- **`CMD_CONFIG_ND_OFFLOAD`**：动态向固件下发开启 Neighbor Discovery/ARP 硬件代答的指令。
- **`CMD_INSTALL_PACKET_FILTER`**：动态下发 APF (Android Packet Filter) BPF 过滤程序，在硬件级别丢弃非单播/伪造的流量。

### 3. 控制面的成功绕过 (Frida 实验)
我们成功使用 Frida 对 Wi-Fi 安全策略进行了“斩首行动”：
- **目标进程**：`android.hardware.wifi-service` (Native HAL)。
- **Hook 逻辑**：拦截 `libc.so` 中的 `sendto` / `sendmsg` 函数，检测并抹除发往驱动的高通 Vendor Commands (OUI `0x001374`)：
  - Subcommand `74` (ARP/NS Offload) -> 强制抹零。
  - Subcommand `83` (APF Filter) -> 强制抹零。
- **结果**：虽然我们成功在内存中阻断了系统*动态*下发这些防御规则，但在该三星设备上，ARP 欺骗**依然失败**。

### 4. 根本原因分析 (Root Cause)
在三星定制版的高通 `qcacld-3.0` 驱动和固件中：
- **出厂默认的硬件加固**：防欺骗机制（当发送包的源 MAC 与网卡真实 MAC 不符时直接丢弃）在 STA 模式下似乎是固件/内核数据面中**硬编码的默认行为 (Hardcoded Default)**。
- **三星深度定制**：与一加/AOSP 不同，三星的内核网络栈（可能通过 Knox 或隐藏的 eBPF 挂钩）对原始套接字 (Raw Sockets) 执行了极其严格的数据面审计。

## FSploit 的战略转向

### 阶段 1：诊断 UI (就绪度检查)
FSploit 应该实现一个“硬件/固件兼容性诊断”面板：
- 如果检测到 `Build.MANUFACTURER == "samsung"`，在 UI 上高亮警告底层硬件存在 ARP 隔离。
- 探测 `/d/wlan0/offload_info` 以展示 ARP/APF Offload 的实时状态。

### 阶段 2：功能降级 - 热点模式 (SoftAP)
既然 STA 模式的伪造包被三星固件物理封杀：
- **主要攻击路径**：将高安全设备的攻击方式转向 **SoftAP（个人热点）模式**。
- **原因**：在 AP（热点）模式下，Android 系统和高通固件天然会关闭所有的 APF 过滤和 ARP Offload。
- **实现**：无需 ARP 欺骗，直接使用 `iptables` / `nftables` 对 80/443 端口进行透明重定向 (PREROUTING DNAT)，将流量导向 FSploit 的本地代理后端。

### 阶段 3：针对 OEM 的绕过研究
后续可研究三星的“手机 MAC”设置（关闭随机 MAC）或特定的 `vendor.samsung.hardware.wifi` HIDL 调用，看是否能暂时降低其数据面的包审计阈值。

---

## 本次生成的代码/技术资产
- `docs/mitm-root-research.md`: 初步的可行性研究文档。
- `app/src/main/cpp/qca_unsealer.c`: 实验性的 Netlink 解封工具 (因 SELinux/内核域隔离而失败，返回 ENOENT)。
- `hook_native.js`: 经过实战验证的 Frida 脚本，能够成功拦截并抹除 Wi-Fi HAL 层的安全配置指令 (铁甲通用版)。

## 最终结论
**硬件是无辜的，但三星极度定制的软件/固件环境对 STA 模式下的 MITM 充满了敌意。** FSploit 必须演进为针对高安全 OEM 设备采用“热点优先 (Hotspot-first)”架构，同时保留对诸如一加/Pixel 等更“开放” ROM 的传统（STA 模式）ARP 欺骗支持。
