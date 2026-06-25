package org.fsploit.android.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.PopupWindow
import android.widget.TextView
import android.widget.Toast
import com.google.android.material.button.MaterialButton
import org.fsploit.android.R

/**
 * Shows a small tappable info bubble anchored to [anchor]. Keeps low-frequency guidance (e.g. how
 * to bring up the msgrpc console) and its copy-paste command tucked behind an info icon instead of
 * permanently cluttering the card. Tapping "copy" puts [copyText] on the clipboard.
 */
fun showInfoBubble(anchor: View, body: CharSequence, copyText: String) {
    val context = anchor.context
    val content = LayoutInflater.from(context).inflate(R.layout.view_info_bubble, null)
    content.findViewById<TextView>(R.id.infoBubbleBody).text = body
    content.findViewById<TextView>(R.id.infoBubbleCommand).text = copyText

    val popup = PopupWindow(
        content,
        ViewGroup.LayoutParams.WRAP_CONTENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
        true
    )
    popup.elevation = 24f

    content.findViewById<MaterialButton>(R.id.infoBubbleCopy).setOnClickListener {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("msf", copyText))
        Toast.makeText(context, R.string.msf_help_copied, Toast.LENGTH_SHORT).show()
        popup.dismiss()
    }

    popup.showAsDropDown(anchor, 0, 8)
}
