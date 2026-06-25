package org.fsploit.android.data.msf

/**
 * Curated list of common MSF auxiliary scanner modules surfaced in the "vuln scan" dropdown, so the
 * operator picks a familiar check instead of typing module paths. All run against the selected host
 * as RHOSTS inside the shared msgrpc instance. Labels carry the well-known name; paths are passed to
 * `use <path>` verbatim.
 */
object MsfScanners {

    data class Scanner(val label: String, val modulePath: String)

    val COMMON: List<Scanner> = listOf(
        Scanner("MS17-010 / EternalBlue", "auxiliary/scanner/smb/smb_ms17_010"),
        Scanner("SMB version", "auxiliary/scanner/smb/smb_version"),
        Scanner("RDP / BlueKeep (CVE-2019-0708)", "auxiliary/scanner/rdp/cve_2019_0708_bluekeep"),
        Scanner("SSH version", "auxiliary/scanner/ssh/ssh_version"),
        Scanner("HTTP version", "auxiliary/scanner/http/http_version"),
        Scanner("TCP portscan", "auxiliary/scanner/portscan/tcp"),
        Scanner("VNC none-auth", "auxiliary/scanner/vnc/vnc_none_auth"),
        Scanner("FTP anonymous", "auxiliary/scanner/ftp/anonymous")
    )
}
