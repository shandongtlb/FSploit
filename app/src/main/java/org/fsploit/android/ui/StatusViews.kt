package org.fsploit.android.ui

import android.content.res.ColorStateList
import android.widget.ImageView
import androidx.core.content.ContextCompat
import org.fsploit.android.R

/** Visual status of a single indicator dot. */
enum class DotStatus { OK, BAD, WARN, IDLE }

/** Tints a status-dot [ImageView] (drawable/status_dot) by [status]. */
fun ImageView.setStatusDot(status: DotStatus) {
    val colorRes = when (status) {
        DotStatus.OK -> R.color.fsploit_ok
        DotStatus.BAD -> R.color.fsploit_danger
        DotStatus.WARN -> R.color.fsploit_warn
        DotStatus.IDLE -> R.color.fsploit_text_muted
    }
    imageTintList = ColorStateList.valueOf(ContextCompat.getColor(context, colorRes))
}

/** Boolean convenience: ok -> green, else red. */
fun ImageView.setStatusDot(ok: Boolean) {
    setStatusDot(if (ok) DotStatus.OK else DotStatus.BAD)
}
