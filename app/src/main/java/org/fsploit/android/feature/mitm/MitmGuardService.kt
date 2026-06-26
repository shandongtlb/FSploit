package org.fsploit.android.feature.mitm

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.fsploit.android.FSploitApp
import org.fsploit.android.MainActivity
import org.fsploit.android.R

/**
 * Foreground service that keeps an always-visible, ongoing notification while a MITM session or a
 * standalone connection block is active. Two jobs:
 *  - Visibility: the user (and the OS) always sees that FSploit is actively mangling network traffic.
 *  - Safety: the notification carries a "stop all / restore network" action that unconditionally
 *    tears down every session/block and restores ip_forward + iptables from the stored records, so a
 *    left-on MITM can be killed from the shade without digging back into the app.
 *
 * Drive it from the UI with [sync]: it's idempotent, so call it on every render with the current
 * "is anything active" flag.
 */
class MitmGuardService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_ALL -> {
                restoreNetworkAndStop()
            }

            else -> {
                ensureChannel()
                startForegroundCompat()
            }
        }
        return START_STICKY
    }

    private fun startForegroundCompat() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun restoreNetworkAndStop() {
        val container = (application as FSploitApp).appContainer
        scope.launch {
            withContext(Dispatchers.IO) {
                runCatching { container.restoreNetworkUseCase() }
            }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun buildNotification(): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE
        )
        val stopAllIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, MitmGuardService::class.java).setAction(ACTION_STOP_ALL),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_guard)
            .setContentTitle(getString(R.string.mitm_guard_notification_title))
            .setContentText(getString(R.string.mitm_guard_notification_text))
            .setOngoing(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(contentIntent)
            .addAction(
                R.drawable.ic_stat_guard,
                getString(R.string.mitm_guard_stop_all),
                stopAllIntent
            )
            .build()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL_ID) != null) {
            return
        }
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.mitm_guard_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.mitm_guard_channel_description)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val CHANNEL_ID = "mitm_guard"
        private const val NOTIFICATION_ID = 0x5F50 // "FP"
        private const val ACTION_STOP_ALL = "org.fsploit.android.action.STOP_ALL"

        /**
         * Idempotently reflect whether anything is active. [active] true ⇒ ensure the foreground
         * notification is up; false ⇒ tear the service (and its notification) down. Safe to call on
         * every UI render. Stopping here does NOT run network restore — a normal in-app stop already
         * cleaned up; this only removes the now-stale notification.
         */
        fun sync(context: Context, active: Boolean) {
            val appContext = context.applicationContext
            val intent = Intent(appContext, MitmGuardService::class.java)
            if (active) {
                ContextCompat.startForegroundService(appContext, intent)
            } else {
                appContext.stopService(intent)
            }
        }
    }
}
