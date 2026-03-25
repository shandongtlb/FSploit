package org.fsploit.android.domain.model

data class MitmReadiness(
    val iptablesAvailable: Boolean,
    val tcpdumpAvailable: Boolean,
    val arpspoofAvailable: Boolean,
    val ettercapAvailable: Boolean,
    val mitmdumpAvailable: Boolean,
    val certificateStoreAccessible: Boolean,
    val summary: String
)
