package org.fsploit.android.domain.model

import androidx.annotation.StringRes
import org.fsploit.android.R

enum class ConnectionBlockMode(
    @StringRes val titleRes: Int,
    @StringRes val descriptionRes: Int
) {
    NORMAL(
        titleRes = R.string.block_mode_normal,
        descriptionRes = R.string.block_mode_normal_desc
    ),
    HOTSPOT(
        titleRes = R.string.block_mode_hotspot,
        descriptionRes = R.string.block_mode_hotspot_desc
    )
}
