package com.nexa.pipe

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The plaintext fallback is deliberate — refusing to store a credential would
 * cut the user off from their own endpoint — but it used to be silent, and a
 * device whose keystore would not take the key looked exactly like a working
 * one. These pin the part that makes it visible.
 */
class SecretStoreTest {
    /**
     * Off-device there is no `AndroidKeyStore` at all, which is the very case
     * the fallback exists for.
     */
    @Test
    fun a_keystore_that_will_not_take_the_key_is_reported() {
        val store = SecretStore()
        val plain = "JBSWY3DPEHPK3PXP"

        assertEquals("the value is still stored", plain, store.seal(plain))
        assertEquals(
            "but the caller is told it is not protected",
            SecretStore.Protection.NoKeystore,
            store.protection()
        )
    }

    /**
     * An empty value is returned before any key is looked for, so a node with
     * no 2FA must not be able to make the app look unprotected.
     */
    @Test
    fun an_empty_value_leaves_the_reported_state_alone() {
        val store = SecretStore()

        assertEquals("", store.seal(""))
        assertEquals(SecretStore.Protection.Sealed, store.protection())
    }

    /**
     * A value without the marker is the plaintext an older version wrote, and
     * it is the user's only copy, so it is handed back as it stands.
     *
     * Only the marked path is skipped here: decoding one needs `Base64`, which
     * is a stub returning null on the host, so what it does with a damaged
     * value is not something a host test can say.
     */
    @Test
    fun an_unmarked_value_is_read_as_the_plaintext_it_is() {
        val store = SecretStore()

        assertEquals("JBSWY3DPEHPK3PXP", store.unseal("JBSWY3DPEHPK3PXP"))
        assertEquals("", store.unseal(null))
        assertEquals("", store.unseal(""))
    }
}
