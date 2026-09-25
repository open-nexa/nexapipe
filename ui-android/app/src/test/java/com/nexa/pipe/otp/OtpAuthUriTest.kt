package com.nexa.pipe.otp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the `otpauth://` reader/writer used by the QR scanner.
 *
 * The parser runs on the JVM (no Android APIs), so these tests need no
 * instrumentation.
 */
class OtpAuthUriTest {

    private fun success(uri: String): OtpAuthConfig {
        val result = OtpAuth.parse(uri)
        assertTrue("expected success but got $result", result is OtpAuthParseResult.Success)
        return (result as OtpAuthParseResult.Success).config
    }

    private fun failure(uri: String): String {
        val result = OtpAuth.parse(uri)
        assertTrue("expected failure but got $result", result is OtpAuthParseResult.Failure)
        return (result as OtpAuthParseResult.Failure).message
    }

    @Test
    fun `parses a fully specified uri`() {
        val config = success(
            "otpauth://totp/NexaPipe:client-001" +
                "?secret=JBSWY3DPEHPK3PXP&issuer=NexaPipe&algorithm=SHA256&digits=6&period=30"
        )

        assertEquals("client-001", config.clientId)
        assertEquals("JBSWY3DPEHPK3PXP", config.secret)
        assertEquals("sha256", config.algorithm)
        assertEquals("NexaPipe", config.issuer)
        assertEquals(emptyList<String>(), config.warnings)
    }

    @Test
    fun `defaults to sha1 with six digits and a thirty second step`() {
        val config = success("otpauth://totp/NexaPipe:client-001?secret=JBSWY3DPEHPK3PXP")

        assertEquals("sha1", config.algorithm)
        assertEquals(6, config.digits)
        assertEquals(30, config.period)
    }

    @Test
    fun `upper cases the secret and drops whitespace and padding`() {
        val config = success("otpauth://totp/NexaPipe:client-001?secret=jbsw%20y3dp%20ehpk%203pxp%3D")

        assertEquals("JBSWY3DPEHPK3PXP", config.secret)
    }

    @Test
    fun `accepts a label without an issuer prefix`() {
        val config = success("otpauth://totp/client-001?secret=JBSWY3DPEHPK3PXP")

        assertEquals("client-001", config.clientId)
    }

    @Test
    fun `strips the issuer prefix even when it is only in the label`() {
        val config = success("otpauth://totp/NexaPipe%3AMy%20Phone?secret=JBSWY3DPEHPK3PXP")

        assertEquals("My Phone", config.clientId)
    }

    @Test
    fun `rejects hotp codes`() {
        assertTrue(failure("otpauth://hotp/client-001?secret=JBSWY3DPEHPK3PXP&counter=1").contains("HOTP"))
    }

    @Test
    fun `rejects a non otpauth uri`() {
        assertTrue(failure("https://example.com/2fa").contains("otpauth"))
        assertTrue(failure("JBSWY3DPEHPK3PXP").contains("otpauth"))
    }

    @Test
    fun `rejects a uri without a client id`() {
        assertTrue(failure("otpauth://totp/?secret=JBSWY3DPEHPK3PXP").contains("client ID"))
    }

    @Test
    fun `rejects a uri without a secret`() {
        assertTrue(failure("otpauth://totp/NexaPipe:client-001?issuer=NexaPipe").contains("secret"))
    }

    @Test
    fun `rejects a secret outside the base32 alphabet`() {
        assertTrue(failure("otpauth://totp/NexaPipe:client-001?secret=JBSW1Y3DP").contains("Base32"))
    }

    @Test
    fun `rejects an unsupported algorithm`() {
        assertTrue(
            failure("otpauth://totp/NexaPipe:client-001?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")
                .contains("Unsupported algorithm")
        )
    }

    @Test
    fun `warns about digits and period the client cannot produce`() {
        val config = success(
            "otpauth://totp/NexaPipe:client-001?secret=JBSWY3DPEHPK3PXP&digits=8&period=60"
        )

        assertEquals(8, config.digits)
        assertEquals(60, config.period)
        assertEquals(2, config.warnings.size)
    }

    @Test
    fun `warns about an impossible secret length`() {
        // 14 characters cannot be produced by an unpadded Base32 encoder.
        val config = success("otpauth://totp/NexaPipe:client-001?secret=JBSWY3DPEHPK3P")

        assertEquals(1, config.warnings.size)
    }

    @Test
    fun `build round trips through parse`() {
        val uri = OtpAuth.build("client-001", "jbswy3dpehpk3pxp", "sha1")
        val config = success(uri)

        assertEquals("client-001", config.clientId)
        assertEquals("JBSWY3DPEHPK3PXP", config.secret)
        assertEquals("sha1", config.algorithm)
        assertEquals(emptyList<String>(), config.warnings)
    }

    @Test
    fun `build escapes the issuer separator only where required`() {
        val uri = OtpAuth.build("My Phone", "JBSWY3DPEHPK3PXP", "sha256")

        assertTrue(uri.startsWith("otpauth://totp/NexaPipe:My%20Phone?secret=JBSWY3DPEHPK3PXP"))
        assertEquals("My Phone", success(uri).clientId)
    }

    @Test
    fun `build keeps a colon inside the client id intact`() {
        val uri = OtpAuth.build("group:client-001", "JBSWY3DPEHPK3PXP", "sha1")

        assertEquals("group:client-001", success(uri).clientId)
    }
}
