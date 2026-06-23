package org.fsploit.android.ui

import android.view.View
import android.widget.ImageView

/**
 * Wires a clickable [header] to expand/collapse a [body]. The [chevron] points
 * down when collapsed (0°) and up when expanded (180°). This is pure view-state
 * — nothing leaks into the ViewModel/UiState; the section resets to
 * [startCollapsed] whenever the fragment view is recreated.
 */
fun bindCollapsible(
    header: View,
    body: View,
    chevron: ImageView,
    startCollapsed: Boolean = true
) {
    fun apply(collapsed: Boolean) {
        body.visibility = if (collapsed) View.GONE else View.VISIBLE
        chevron.rotation = if (collapsed) 0f else 180f
    }
    apply(startCollapsed)
    header.setOnClickListener {
        apply(body.visibility == View.VISIBLE)
    }
}
