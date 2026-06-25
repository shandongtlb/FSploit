package org.fsploit.android.domain.model

/**
 * Port-scan profile. NORMAL runs nmap service/version detection (`-sS -sV`); ADVANCED runs the
 * aggressive `-A` profile (OS + version + default scripts + traceroute); both fall back to the
 * builtin socket connect-scan when nmap is absent.
 *
 * UDP runs `nmap -sU -sV` over a small curated set of high-value UDP ports (DNS/SNMP/mDNS/SSDP/…).
 * It is nmap-only — the builtin socket scan can't probe UDP reliably — and uses its own port list,
 * not the TCP port spec.
 */
enum class PortScanMode {
    NORMAL,
    ADVANCED,
    UDP
}
