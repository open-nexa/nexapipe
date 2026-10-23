package com.nexa.pipe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which key an endpoint proves itself with.
 *
 * A key belongs to the device, not to the endpoint that happened to enroll
 * first: the server files it under this device's *name*, and that name does
 * not change when the server does. A server that is rebuilt or copied keeps
 * the row, while the endpoint id it answers to changes — and an endpoint id
 * that changes must not change the key, or the device comes back to a server
 * that holds its key under its name with a different one, and the enrollment
 * is refused as a takeover.
 *
 * The endpoint's own key still wins where there is one: that is the key the
 * server holds for it, and a new one would not be recognized.
 */
class DeviceKeyScopeTest {

    private fun manager(secrets: FakePrefs): SettingsManager =
        SettingsManager(FakePrefs("prefs"), secrets, SecretStore())

    /**
     * An endpoint with no key of its own answers with the device's.
     *
     * This is the whole of the rule: one phone, one key, and every endpoint
     * of it that has no key of its own offers the same one.
     */
    @Test
    fun an_endpoint_without_a_key_of_its_own_answers_with_the_devices() {
        val secrets = FakePrefs("secrets")
        secrets.put(SettingsManager.KEY_DEVICE_KEY, "device-key")

        val manager = manager(secrets)

        assertEquals("device-key", manager.deviceKeyFor("node-b"))
    }

    /**
     * An endpoint that enrolled with a key of its own keeps it.
     *
     * The server holds that half under this device's name: a different one
     * would not be recognized, and the endpoint would be refused.
     */
    @Test
    fun an_endpoint_with_a_key_of_its_own_keeps_it() {
        val secrets = FakePrefs("secrets")
        secrets.put(SettingsManager.KEY_DEVICE_KEY, "device-key")
        secrets.put(SettingsManager.DEVICE_KEY_PREFIX + "node-a", "node-a-key")

        val manager = manager(secrets)

        assertEquals("node-a-key", manager.deviceKeyFor("node-a"))
    }

    /**
     * The endpoint's own key is a question of its own.
     *
     * A caller that wants *this endpoint's* key and is handed the device's one
     * would drop a key the server still holds — which is what clearing a
     * credential does.
     */
    @Test
    fun the_endpoints_own_key_is_asked_for_on_its_own() {
        val secrets = FakePrefs("secrets")
        secrets.put(SettingsManager.KEY_DEVICE_KEY, "device-key")
        secrets.put(SettingsManager.DEVICE_KEY_PREFIX + "node-a", "node-a-key")

        val manager = manager(secrets)

        assertEquals("node-a-key", manager.deviceKeyForNode("node-a"))
        assertEquals("", manager.deviceKeyForNode("node-b"))
        assertEquals("device-key", manager.deviceKey())
    }

    /**
     * A device key that is already there is never replaced.
     *
     * The servers holding it are the ones that would stop recognizing this
     * device, so adopting another one is not a thing that happens.
     */
    @Test
    fun an_existing_device_key_is_never_replaced() {
        val secrets = FakePrefs("secrets")
        secrets.put(SettingsManager.KEY_DEVICE_KEY, "device-key")

        val manager = manager(secrets)

        assertFalse(
            "a key the servers already hold was replaced",
            manager.adoptDeviceKeyIfEmpty("another-key")
        )
        assertEquals("device-key", manager.deviceKey())
    }

    /**
     * A device with no key of its own adopts the one an endpoint enrolled
     * with.
     *
     * That key is the one the server holds under this device's name, so
     * adopting it is what keeps the two the same — the endpoint this phone
     * enrolls with next then offers a key the server already knows.
     */
    @Test
    fun a_device_without_a_key_adopts_the_one_an_endpoint_enrolled_with() {
        assertEquals("node-a-key", deviceKeyToAdopt("", "node-a-key"))
    }

    /**
     * A device that has a key keeps it.
     *
     * The servers holding it are the ones that would stop recognizing this
     * device, so there is nothing to write.
     */
    @Test
    fun a_device_that_has_a_key_keeps_it() {
        assertNull(deviceKeyToAdopt("device-key", "node-a-key"))
        assertNull(deviceKeyToAdopt("device-key", ""))
        assertNull(deviceKeyToAdopt("", ""))
    }

    /**
     * The device key is a credential, and the secrets file holds it sealed.
     *
     * A device key is the private half of the device's proof of who it is,
     * and there is no second copy of it anywhere.
     */
    @Test
    fun the_device_key_is_a_credential() {
        assertTrue(isCredentialKey(SettingsManager.KEY_DEVICE_KEY))
        assertTrue(isCredentialKey(SettingsManager.DEVICE_KEY_PREFIX + "node-a"))
    }
}
