package org.fsploit.android.core

import android.content.Context
import androidx.annotation.StringRes

interface ResourceProvider {
    fun getString(@StringRes resId: Int, vararg formatArgs: Any): String
}

class AndroidResourceProvider(
    context: Context
) : ResourceProvider {
    private val appContext = context.applicationContext

    override fun getString(resId: Int, vararg formatArgs: Any): String {
        return appContext.getString(resId, *formatArgs)
    }
}
