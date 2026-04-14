package org.fsploit.android.domain.model

data class MsfRpcOverview(
    val connected: Boolean,
    val frameworkVersion: String,
    val rubyVersion: String,
    val apiVersion: String,
    val sessions: List<MsfSessionInfo>,
    val jobs: List<MsfJobInfo>,
    val summary: String
)
