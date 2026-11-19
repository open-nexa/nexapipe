package com.nexa.pipe

import android.os.Build

/**
 * What this phone tells a server about itself when it enrolls.
 *
 * Four labels and no identity: the device is known by the fingerprint of its
 * key, worked out from the public half on both sides. A model is the obvious
 * thing to call a phone, but models repeat — "Pixel 9 Pro" describes millions
 * of them — so it is reported as a label, where a repeat is fine, and never as
 * an id. Nothing here is persisted: an enrollment carries these through to the
 * Rust side, which reports them beside the credential it issues.
 */
internal object DeviceInfo {
    /** The name the phone calls itself. */
    fun label(): String = Build.MODEL.orEmpty()

    /** The platform this app runs on. */
    fun platform(): String = "android"

    /** The operating system's version, as a label rather than an identity. */
    fun model(): String = Build.VERSION.RELEASE.orEmpty()

    /** The version of this app, from the generated BuildConfig. */
    fun appVersion(): String = BuildConfig.VERSION_NAME.orEmpty()
}
