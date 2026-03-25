package org.fsploit.android.data.settings

import android.content.Context

class AppPreferencesRepository(
    context: Context
) {
    private val preferences = context.applicationContext.getSharedPreferences(
        "fsploit_preferences",
        Context.MODE_PRIVATE
    )

    fun getPreferredInterfaceName(): String = preferences.getString(KEY_PREFERRED_INTERFACE, "").orEmpty()

    fun setPreferredInterfaceName(interfaceName: String) {
        preferences.edit().putString(KEY_PREFERRED_INTERFACE, interfaceName.trim()).apply()
    }

    companion object {
        private const val KEY_PREFERRED_INTERFACE = "preferred_interface"
    }
}
