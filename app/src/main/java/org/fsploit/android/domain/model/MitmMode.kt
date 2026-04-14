package org.fsploit.android.domain.model

import androidx.annotation.StringRes
import org.fsploit.android.R

enum class MitmMode(
    @StringRes val titleRes: Int,
    @StringRes val descriptionRes: Int,
    @StringRes val primaryHintRes: Int? = null,
    @StringRes val secondaryHintRes: Int? = null,
    @StringRes val payloadHintRes: Int? = null
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
        descriptionRes = R.string.mitm_mode_dns_spoof_desc,
        payloadHintRes = R.string.mitm_payload_hint_dns_rules
    ),
    REDIRECT(
        titleRes = R.string.mitm_mode_redirect,
        descriptionRes = R.string.mitm_mode_redirect_desc,
        primaryHintRes = R.string.mitm_primary_hint_redirect_host,
        secondaryHintRes = R.string.mitm_secondary_hint_redirect_port
    ),
    IMAGE_REPLACE(
        titleRes = R.string.mitm_mode_image_replace,
        descriptionRes = R.string.mitm_mode_image_replace_desc,
        primaryHintRes = R.string.mitm_primary_hint_image_url
    ),
    VIDEO_REPLACE(
        titleRes = R.string.mitm_mode_video_replace,
        descriptionRes = R.string.mitm_mode_video_replace_desc,
        primaryHintRes = R.string.mitm_primary_hint_video_url
    ),
    SCRIPT_INJECTION(
        titleRes = R.string.mitm_mode_script_injection,
        descriptionRes = R.string.mitm_mode_script_injection_desc,
        payloadHintRes = R.string.mitm_payload_hint_script
    ),
    CUSTOM_FILTER(
        titleRes = R.string.mitm_mode_custom_filter,
        descriptionRes = R.string.mitm_mode_custom_filter_desc,
        payloadHintRes = R.string.mitm_payload_hint_filter_rules
    ),
    SESSION_HIJACK(
        titleRes = R.string.mitm_mode_session_hijack,
        descriptionRes = R.string.mitm_mode_session_hijack_desc
    )

    ;

    val showsPrimaryInput: Boolean
        get() = primaryHintRes != null

    val showsSecondaryInput: Boolean
        get() = secondaryHintRes != null

    val showsPayloadInput: Boolean
        get() = payloadHintRes != null

    val usesHttpMitmAddon: Boolean
        get() = this in setOf(
            REDIRECT,
            IMAGE_REPLACE,
            VIDEO_REPLACE,
            SCRIPT_INJECTION,
            CUSTOM_FILTER,
            SESSION_HIJACK
        )
}
