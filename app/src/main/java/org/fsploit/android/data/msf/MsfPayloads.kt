package org.fsploit.android.data.msf

/**
 * Curated list of common reverse payloads for the one-tap handler dropdown — selection over typing,
 * since a hand-typed payload string is exactly the kind of thing better done in the terminal.
 */
object MsfPayloads {

    val COMMON: List<String> = listOf(
        "windows/x64/meterpreter/reverse_tcp",
        "windows/meterpreter/reverse_tcp",
        "linux/x64/meterpreter/reverse_tcp",
        "linux/x86/meterpreter/reverse_tcp",
        "android/meterpreter/reverse_tcp",
        "php/meterpreter/reverse_tcp",
        "python/meterpreter/reverse_tcp",
        "java/jsp_shell_reverse_tcp",
        "cmd/unix/reverse_bash"
    )
}
