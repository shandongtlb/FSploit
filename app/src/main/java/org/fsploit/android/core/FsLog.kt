package org.fsploit.android.core

import android.util.Log
import org.fsploit.android.BuildConfig

/**
 * Thin wrapper over [android.util.Log] so the app has one place that decides verbosity.
 *
 * The whole tool shells out to root binaries and external toolchains whose failures are otherwise
 * swallowed by defensive `catch` blocks that return a null/empty fallback. Routing those through
 * [warn]/[error] keeps the graceful behaviour while leaving a breadcrumb in logcat for field
 * debugging. Debug-level chatter is compiled out of release builds via [BuildConfig.DEBUG].
 */
object FsLog {
    fun debug(tag: String, message: String) {
        if (BuildConfig.DEBUG) Log.d(tag, message)
    }

    fun warn(tag: String, message: String, throwable: Throwable? = null) {
        Log.w(tag, message, throwable)
    }

    fun error(tag: String, message: String, throwable: Throwable? = null) {
        Log.e(tag, message, throwable)
    }
}
