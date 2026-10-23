package com.nexa.pipe

import android.content.SharedPreferences

/**
 * A preferences file that lives in a map.
 *
 * What matters about the migration is the order its writes are made in and
 * whether they reach the disk, so the fake records both — and can be told
 * to fail a commit, which is the failure the migration has to survive.
 *
 * Shared by the tests that need one, so that the rules they pin are the rules
 * and not the fake.
 */
internal class FakePrefs(
    private val name: String,
    private val values: MutableMap<String, Any?> = mutableMapOf(),
    private val log: MutableList<String> = mutableListOf(),
    private val failCommit: Boolean = false
) : SharedPreferences {

    /** Seeds a value the way an older version would have left it. */
    fun put(key: String, value: String) {
        values[key] = value
    }

    override fun getAll(): MutableMap<String, *> = values.toMutableMap()

    override fun getString(key: String, defValue: String?): String? =
        values[key] as? String ?: defValue

    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? =
        (values[key] as? MutableSet<String>) ?: defValues

    override fun getInt(key: String, defValue: Int): Int = values[key] as? Int ?: defValue

    override fun getLong(key: String, defValue: Long): Long = values[key] as? Long ?: defValue

    override fun getFloat(key: String, defValue: Float): Float = values[key] as? Float ?: defValue

    override fun getBoolean(key: String, defValue: Boolean): Boolean =
        values[key] as? Boolean ?: defValue

    override fun contains(key: String): Boolean = values.containsKey(key)

    override fun edit(): SharedPreferences.Editor = FakeEditor()

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?
    ) = Unit

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?
    ) = Unit

    private inner class FakeEditor : SharedPreferences.Editor {
        private val pending = mutableMapOf<String, Any?>()
        private val removed = mutableSetOf<String>()

        override fun putString(key: String, value: String?): SharedPreferences.Editor {
            pending[key] = value
            return this
        }

        override fun putStringSet(key: String, values: MutableSet<String>?): SharedPreferences.Editor {
            pending[key] = values
            return this
        }

        override fun putInt(key: String, value: Int): SharedPreferences.Editor {
            pending[key] = value
            return this
        }

        override fun putLong(key: String, value: Long): SharedPreferences.Editor {
            pending[key] = value
            return this
        }

        override fun putFloat(key: String, value: Float): SharedPreferences.Editor {
            pending[key] = value
            return this
        }

        override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor {
            pending[key] = value
            return this
        }

        override fun remove(key: String): SharedPreferences.Editor {
            removed += key
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            pending.clear()
            removed.clear()
            return this
        }

        override fun commit(): Boolean {
            log += "commit:$name"
            if (failCommit) return false
            flush()
            return true
        }

        override fun apply() {
            log += "apply:$name"
            flush()
        }

        private fun flush() {
            pending.forEach { (key, value) -> values[key] = value }
            removed.forEach { values.remove(it) }
            pending.clear()
            removed.clear()
        }
    }
}
