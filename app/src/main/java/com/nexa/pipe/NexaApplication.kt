package com.nexa.pipe

import android.app.Application
import com.nexa.pipe.locale.AppStrings

/**
 * Only job: make the localized strings reachable from the code that has no
 * context of its own (see `AppStrings`), before any Activity or service runs.
 *
 * The language itself is not applied here — resources are resolved per
 * context, so `MainActivity` and `NexaVpnService` each wrap their own.
 */
class NexaApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        AppStrings.init(this)
    }
}
