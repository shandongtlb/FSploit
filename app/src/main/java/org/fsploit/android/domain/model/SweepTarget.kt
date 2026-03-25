package org.fsploit.android.domain.model

data class SweepTarget(
    val interfaceName: String,
    val localAddress: String,
    val prefixLength: Int,
    val networkAddress: String,
    val hostCandidates: List<String>
)
