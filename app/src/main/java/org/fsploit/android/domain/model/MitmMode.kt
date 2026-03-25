package org.fsploit.android.domain.model

import androidx.annotation.StringRes
import org.fsploit.android.R

enum class MitmMode(
    @StringRes val titleRes: Int,
    @StringRes val descriptionRes: Int
) {
    CONNECTION_KILL(
        titleRes = R.string.mitm_mode_connection_kill,
        descriptionRes = R.string.mitm_mode_connection_kill_desc
    ),
    SNIFFER(
        titleRes = R.string.mitm_mode_sniffer,
        descriptionRes = R.string.mitm_mode_sniffer_desc
    ),
    PASSWORD_SNIFFER(
        titleRes = R.string.mitm_mode_password_sniffer,
        descriptionRes = R.string.mitm_mode_password_sniffer_desc
    ),
    DNS_SPOOF(
        titleRes = R.string.mitm_mode_dns_spoof,
        descriptionRes = R.string.mitm_mode_dns_spoof_desc
    ),
    REDIRECT(
        titleRes = R.string.mitm_mode_redirect,
        descriptionRes = R.string.mitm_mode_redirect_desc
    ),
    IMAGE_REPLACE(
        titleRes = R.string.mitm_mode_image_replace,
        descriptionRes = R.string.mitm_mode_image_replace_desc
    ),
    VIDEO_REPLACE(
        titleRes = R.string.mitm_mode_video_replace,
        descriptionRes = R.string.mitm_mode_video_replace_desc
    ),
    SCRIPT_INJECTION(
        titleRes = R.string.mitm_mode_script_injection,
        descriptionRes = R.string.mitm_mode_script_injection_desc
    ),
    CUSTOM_FILTER(
        titleRes = R.string.mitm_mode_custom_filter,
        descriptionRes = R.string.mitm_mode_custom_filter_desc
    ),
    SESSION_HIJACK(
        titleRes = R.string.mitm_mode_session_hijack,
        descriptionRes = R.string.mitm_mode_session_hijack_desc
    )
}
