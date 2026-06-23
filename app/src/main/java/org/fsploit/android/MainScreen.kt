package org.fsploit.android

import androidx.annotation.IdRes
import androidx.annotation.StringRes

enum class MainScreen(
    @IdRes val menuItemId: Int,
    @StringRes val titleRes: Int
) {
    OVERVIEW(R.id.nav_overview, R.string.nav_overview),
    DISCOVERY(R.id.nav_discovery, R.string.nav_discovery),
    TARGET_DETAIL(R.id.nav_target_detail, R.string.nav_target_detail),
    MSF(R.id.nav_msf, R.string.nav_msf),
    TOOLS(R.id.nav_tools, R.string.nav_tools),
    SETTINGS(R.id.nav_settings, R.string.nav_settings);

    companion object {
        fun fromMenuItemId(@IdRes itemId: Int): MainScreen? {
            return entries.firstOrNull { it.menuItemId == itemId }
        }
    }
}
