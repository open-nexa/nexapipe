package com.nexa.pipe.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import android.util.Log
import com.nexa.pipe.IrohProxy
import com.nexa.pipe.MainActivity
import com.nexa.pipe.R
import com.nexa.pipe.formatByteRate
import com.nexa.pipe.parseNodeTraffic
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * The notification the VPN service shows, and the foreground service around it.
 *
 * Everything here is about what the user sees and about the two moments the
 * system insists on: the foreground notification a service started with
 * `startForegroundService()` has to post within five seconds, and the removal
 * of that notification when the session ends.
 *
 * The log tag is the one the service has always used: these logs are read by
 * that tag, and splitting the service must not change what they say.
 */
internal class VpnNotification(private val service: NexaVpnService) {
    private val TAG = "NexaVpnService"

    // The last text handed to NotificationManager. Android throttles rapid updates, so a
    // tick that worked out the same text posts nothing rather than queueing behind one.
    //
    // Written from two threads and from two different ideas of what the notification is
    // showing: the poller sets it to whatever it just posted, and anything that re-posts
    // the plain notification — `startForeground` on a rebuild — has to clear it, because
    // the content on screen no longer matches what it remembers. Both happen under this
    // lock together with the post itself.
    private val notificationLock = Any()
    @Volatile private var lastNotificationText: String? = null
    // The poll that keeps the notification's throughput current. It lives here and not in the
    // ViewModel on purpose: the ViewModel's polling only runs while its UI is in the
    // foreground, and a notification that freezes the moment the user leaves the app is the
    // one thing it must not do.
    private var trafficJob: Job? = null
    // The counters are cumulative, so a rate takes two samples: this is the previous one.
    private var lastTrafficSample: TrafficSample? = null
    /** One read of the cumulative counters, with the moment it was taken. */
    private data class TrafficSample(val sent: Long, val received: Long, val atMs: Long)

    /**
     * Meets the obligation a service started with `startForegroundService()`
     * has: it has five seconds to call `startForeground()`, and the system
     * takes the app down when it does not.
     *
     * Every path that starts the service meets it here, before anything that
     * can take longer than five seconds: the boot path waits for a network,
     * and the start path waits for the consent check, for `establish()` and
     * for Android to register the VPN network.
     *
     * The text says what is true: the tunnel is not up yet. A refusal is not
     * swallowed — the service never enters the foreground state that way, and
     * the log is what says why.
     */
    fun startForegroundConnecting() {
        runCatching {
            createNotificationChannel()
            service.startForeground(
                NOTIFICATION_ID,
                createNotification(service.getString(R.string.notification_text_connecting))
            )
        }.onFailure { error ->
            Log.w(TAG, "the foreground was refused: ${error.message}")
        }
    }

    /**
     * Posts the plain notification — the one that says the tunnel is up.
     *
     * Posted with the cache together, and not in two steps: this replaces whatever
     * the poller last showed, so the cache has to hear about it in the same breath.
     * Cleared separately it would still hold the old rate text, and a tick whose new
     * text happened to equal that one would be skipped as "already showing" while
     * the banner sat there saying only "Connected" — which is what a network switch
     * looked like when the rates were quietly zero.
     */
    fun startForegroundConnected() {
        createNotificationChannel()
        synchronized(notificationLock) {
            service.startForeground(NOTIFICATION_ID, createNotification())
            lastNotificationText = null
        }
    }

    /**
     * Stops the service cleanly after a failed establish.
     *
     * The service is started with startForegroundService(), which obligates it
     * to call startForeground() once; skipping that throws
     * ForegroundServiceDidNotStartInTimeException. If the VPN was never
     * established the brief startForeground here satisfies the obligation, and
     * the notification is removed immediately afterwards.
     */
    fun shutdownService() {
        runCatching {
            createNotificationChannel()
            // The text says what is true: the tunnel is not up. The default
            // says "Connected", and this notification is posted rather than
            // skipped — so for as long as the removal takes, the shade would
            // claim a tunnel that was never there.
            service.startForeground(
                NOTIFICATION_ID,
                createNotification(service.getString(R.string.notification_text_connecting))
            )
        }
        service.stopForeground(Service.STOP_FOREGROUND_REMOVE)
        service.stopSelf()
    }

    /**
     * Starts refreshing the throughput in the notification; no-op when a poll is running.
     *
     * The baseline is dropped here as well as in [stopTrafficPolling]: the counters restart
     * from zero when the proxy does, and a rate carried across a restart would be fiction.
     */
    fun startTrafficPolling() {
        if (trafficJob?.isActive == true) return
        lastTrafficSample = null
        trafficJob = service.serviceScope.launch {
            while (isActive) {
                publishThroughput()
                delay(TRAFFIC_POLL_INTERVAL_MS)
            }
        }
    }

    fun stopTrafficPolling() {
        trafficJob?.cancel()
        trafficJob = null
        lastTrafficSample = null
        synchronized(notificationLock) { lastNotificationText = null }
    }

    /**
     * One tick: reads the counters, works out the rates and updates the notification when the
     * text has actually changed.
     *
     * The counters are cumulative, so the first sample only sets the baseline — a rate needs
     * two. A later sample that is *lower* is not negative throughput: the counters reset when
     * the proxy is stopped and started, which a network-switch rebuild does, so the baseline
     * is re-taken and this tick reports nothing rather than a rate that went backwards.
     */
    private suspend fun publishThroughput() {
        val raw = try {
            IrohProxy.nativeTraffic()
        } catch (e: Exception) {
            Log.w(TAG, "Could not read traffic counters: ${e.message}")
            return
        }
        if (raw == null) {
            // Nothing started yet, or the endpoint group is gone: no rate to show, and the
            // baseline is stale either way.
            lastTrafficSample = null
            return
        }

        var sent = 0L
        var received = 0L
        for (volume in parseNodeTraffic(raw).values) {
            sent += volume.sent
            received += volume.received
        }

        // Monotonic: a wall clock that jumps (NTP, user, sleep) would invent a rate.
        val now = SystemClock.elapsedRealtime()
        val previous = lastTrafficSample
        lastTrafficSample = TrafficSample(sent, received, now)
        if (previous == null) return

        val elapsedMs = now - previous.atMs
        if (elapsedMs <= 0L) return
        if (sent < previous.sent || received < previous.received) return

        // Per second, so the number is quoted the way a transfer is: KiB/s, not bytes/tick.
        val up = (sent - previous.sent) * 1000L / elapsedMs
        val down = (received - previous.received) * 1000L / elapsedMs
        publishNotificationText(
            service.getString(
                R.string.notification_text_rate,
                formatByteRate(up),
                formatByteRate(down)
            )
        )
    }

    /**
     * Re-posts the notification with [text], unless it is the text already showing.
     *
     * Same id as the one `startForeground` used, so this updates that notification instead of
     * adding a second one. Android throttles posts that come faster than it can render, and a
     * rate that has not changed is not worth spending one on.
     *
     * The two checks are what make it safe to call from anywhere: cancelling the poller does
     * not wait for the tick already running, and that tick reaches this line after the tunnel
     * is down and its notification has been taken away. Posting then would put a rate back on
     * screen for a service the user has stopped, which is why the teardown marker is read —
     * and written — inside the same lock the post itself takes.
     */
    private fun publishNotificationText(text: String) {
        synchronized(notificationLock) {
            if (service.isStopping) return
            if (text == lastNotificationText) return
            lastNotificationText = text
            val notificationManager = service.getSystemService(NotificationManager::class.java)
            notificationManager.notify(NOTIFICATION_ID, createNotification(text))
        }
    }

    // minSdk is 26, so this check never fails: it is kept because it says
    // which builder to use, and the finding it raises is silenced here rather
    // than in the lint baseline, which names the file the code used to live
    // in. The behaviour is the one it always was.
    @Suppress("ObsoleteSdkInt")
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                service.getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = service.getString(R.string.notification_channel_description)
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            }
            val notificationManager = service.getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    /**
     * The notification, with [text] as its second line — the plain "Connected" until the
     * first rate is known, then the current up and down rates.
     */
    // The same reasoning as in createNotificationChannel(): minSdk is 26, so
    // the check never fails, and it is silenced here because the lint
    // baseline names the file the code used to live in.
    @Suppress("ObsoleteSdkInt")
    private fun createNotification(text: String = service.getString(R.string.notification_text)): Notification {
        val intent = Intent(service, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            service, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(service, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(service)
        }

        return builder
            .setContentTitle(service.getString(R.string.notification_title))
            .setContentText(text)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            // The line under the title changes about once a second. Without this every tick
            // would replay the alert — sound, heads-up — that belongs to a notification that
            // has only just appeared.
            .setOnlyAlertOnce(true)
            .build()
    }

    private companion object {
        const val CHANNEL_ID = "NexaVPN"
        // The one notification this service owns: startForeground posts it, and every rate
        // update replaces it rather than adding another.
        const val NOTIFICATION_ID = 1
        // How often the counters are read for the notification. One second is what makes the
        // figure read as a rate; more often and the text rarely changes, less often and it
        // lags what the tunnel is doing.
        const val TRAFFIC_POLL_INTERVAL_MS = 1_000L
    }
}
