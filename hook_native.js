/**
 * FSploit - Wi-Fi Offload Unsealer (ULTIMATE IRONCLAD VERSION)
 * Target: android.hardware.wifi-service (PID 1851)
 */

console.log("[*] Frida Ultimate Native Hook Script Loaded.");

var OUI_QCA = 0x001374;
var CMD_OFFLOAD = 74;
var CMD_FILTER = 83;

function scanPayload(ptrBuffer, length) {
    if (ptrBuffer.isNull() || length < 16) return;
    try {
        for (var i = 0; i < length - 12; i++) {
            var val = ptrBuffer.add(i).readU32();
            if (val === OUI_QCA) {
                var window = 32;
                var end = (i + window > length - 4) ? length - 4 : i + window;
                for (var j = i; j < end; j += 4) {
                    var cmd = ptrBuffer.add(j).readU32();
                    if (cmd === CMD_OFFLOAD || cmd === CMD_FILTER) {
                        console.log("[!] [Native] INTERCEPTED QCA Command: " + cmd + ". Wiping payload...");
                        for (var k = j + 4; k < length; k++) {
                            ptrBuffer.add(k).writeU8(0);
                        }
                        return;
                    }
                }
            }
        }
    } catch (e) {}
}

var sendtoAddr = null;
var sendmsgAddr = null;

var modules = Process.enumerateModules();
for (var i = 0; i < modules.length; i++) {
    if (modules[i].name.indexOf("libc.so") !== -1) {
        var exports = modules[i].enumerateExports();
        for (var j = 0; j < exports.length; j++) {
            if (exports[j].name === "sendto") sendtoAddr = exports[j].address;
            if (exports[j].name === "sendmsg") sendmsgAddr = exports[j].address;
        }
    }
}

if (sendtoAddr) {
    Interceptor.attach(sendtoAddr, {
        onEnter: function(args) {
            try {
                var buf = args[1];
                var len = args[2].toInt32();
                if (!buf.isNull() && len > 16 && len < 8192) scanPayload(buf, len);
            } catch (e) {}
        }
    });
    console.log("[+] Interceptor attached to sendto.");
}

if (sendmsgAddr) {
    Interceptor.attach(sendmsgAddr, {
        onEnter: function(args) {
            try {
                var msgPtr = args[1];
                if (msgPtr.isNull()) return;

                // LP64 msghdr offset for msg_iov is 16, msg_iovlen is 24
                var iov = msgPtr.add(16).readPointer();
                var iovlen = msgPtr.add(24).readPointer().toInt32();

                if (!iov.isNull() && iovlen > 0 && iovlen < 16) {
                    for (var i = 0; i < iovlen; i++) {
                        // iovec: base (8 bytes), len (8 bytes)
                        var base = iov.add(i * 16).readPointer();
                        var len = iov.add(i * 16 + 8).readPointer().toInt32();
                        if (!base.isNull() && len > 16 && len < 8192) scanPayload(base, len);
                    }
                }
            } catch (e) {}
        }
    });
    console.log("[+] Interceptor attached to sendmsg.");
}

console.log("[*] ALL SYSTEMS GO. Ready for Wi-Fi toggle.");
