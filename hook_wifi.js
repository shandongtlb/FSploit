/**
 * FSploit - Wi-Fi Offload Unsealer (Frida Hook) - Deep Injection Version
 * Target: system_server -> com.android.server.wifi.WifiNative
 * Device: Samsung (SM8750, arm64)
 */

console.log("[*] Frida attached. Attempting to force ART execution...");

function hookWifiNative() {
    console.log("[*] Inside Java context. Searching for ClassLoaders...");
    var hooked = false;

    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                // 尝试用每一个找到的 ClassLoader 去加载 WifiNative
                var WifiNative = Java.ClassFactory.get(loader).use("com.android.server.wifi.WifiNative");
                console.log("[+] Found WifiNative in loader: " + loader);

                // 拦截 APF (Android Packet Filter) 安装规则
                if (WifiNative.installPacketFilter) {
                    WifiNative.installPacketFilter.overload('java.lang.String', '[B').implementation = function(iface, filterByteArray) {
                        console.log("[!] [WifiNative] Caught installPacketFilter! Interface: " + iface + ", Length: " + filterByteArray.length);
                        console.log("[!] [WifiNative] DROPPING APF rules to unseal environment for MITM.");
                        return true; 
                    };
                }

                // 拦截 ND/ARP Offload (Neighbor Discovery 代答)
                if (WifiNative.configureNdOffload) {
                    WifiNative.configureNdOffload.overload('java.lang.String', 'boolean').implementation = function(iface, enable) {
                        console.log("[!] [WifiNative] Caught configureNdOffload! Interface: " + iface + ", Requested state: " + enable);
                        if (enable === true) {
                            console.log("[!] [WifiNative] FORCING NdOffload to FALSE.");
                            return this.configureNdOffload(iface, false);
                        } else {
                            return this.configureNdOffload(iface, enable);
                        }
                    };
                }

                console.log("[+++] HOOKS PLANTED SUCCESSFULLY [+++]");
                console.log("[+++] ACTION REQUIRED: Toggle Wi-Fi OFF and ON on the device! [+++]");
                hooked = true;
                return 'stop'; // 找到了就停止遍历 ClassLoader
            } catch(e) {
                // 这个 loader 里没有我们要的类，忽略
            }
        },
        onComplete: function() {
            if (!hooked) {
                console.log("[-] Could not find com.android.server.wifi.WifiNative in any ClassLoader.");
            }
        }
    });
}

setImmediate(function() {
    try {
        // 尝试立即执行
        Java.performNow(hookWifiNative);
    } catch(e) {
        console.log("[-] Java.performNow failed, falling back to Java.perform. Error: " + e);
        Java.perform(hookWifiNative);
    }
});
