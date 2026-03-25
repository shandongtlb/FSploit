package org.fsploit.android

import android.app.Application
import org.fsploit.android.core.AppContainer

class FSploitApp : Application() {
    val appContainer: AppContainer by lazy {
        AppContainer(this)
    }
}
