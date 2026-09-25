import java.security.KeyStore
import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    // AGP 9 ships Kotlin itself: applying org.jetbrains.kotlin.android on top
    // of it is rejected ("no longer required for Kotlin support since AGP 9.0").
    alias(libs.plugins.kotlin.compose)
    kotlin("plugin.serialization") version "2.4.20"
}

// ---------------------------------------------------------------------------
// Release signing configuration
//
// Value precedence: keystore.properties (local, ignored by .gitignore) >
// environment variables (CI). The CI injects RELEASE_KEYSTORE_PATH /
// RELEASE_KEYSTORE_PASSWORD / RELEASE_KEY_ALIAS / RELEASE_KEY_PASSWORD from
// .github/workflows/release.yml.
//
// The release build is only signed when every value is present; otherwise it is
// left unsigned, which keeps assembleDebug and local builds working.
// ---------------------------------------------------------------------------
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.inputStream().use { load(it) }
    }
}

fun signingValue(propertyKey: String, envKey: String): String? =
    (keystoreProperties.getProperty(propertyKey) ?: System.getenv(envKey))?.takeIf { it.isNotBlank() }

val releaseStoreFile = signingValue("storeFile", "RELEASE_KEYSTORE_PATH")
val releaseStorePassword = signingValue("storePassword", "RELEASE_KEYSTORE_PASSWORD")
val releaseKeyAlias = signingValue("keyAlias", "RELEASE_KEY_ALIAS")
val releaseKeyPassword = signingValue("keyPassword", "RELEASE_KEY_PASSWORD")
val releaseStoreType = signingValue("storeType", "RELEASE_KEYSTORE_TYPE") ?: KeyStore.getDefaultType()

// AGP needs all four of storeFile / storePassword / keyAlias / keyPassword; a
// config missing even one of them is discarded (SigningConfigImpl.createSigningConfigInfo
// returns null) and the release build then fails with "Keystore file not set".
val releaseSigningComplete = releaseStoreFile != null &&
    releaseStorePassword != null &&
    releaseKeyAlias != null &&
    releaseKeyPassword != null

if (!releaseSigningComplete) {
    val missing = listOfNotNull(
        "RELEASE_KEYSTORE_PATH".takeIf { releaseStoreFile == null },
        "RELEASE_KEYSTORE_PASSWORD".takeIf { releaseStorePassword == null },
        "RELEASE_KEY_ALIAS".takeIf { releaseKeyAlias == null },
        "RELEASE_KEY_PASSWORD".takeIf { releaseKeyPassword == null },
    )
    logger.warn(
        "Release signing is not configured (missing: ${missing.joinToString(", ")}); " +
            "assembleRelease will produce an unsigned APK."
    )
}

android {
    namespace = "com.nexa.pipe"
    // Compose 1.12.x (BOM 2026.09) refuses to compile against anything older
    // than API 37; AGP resolves 37 to platforms;android-37.0. targetSdk stays
    // at 36 so the app's runtime behaviour is unchanged.
    compileSdk = 37

    defaultConfig {
        applicationId = "com.nexa.pipe"
        minSdk = 26
        targetSdk = 36
        versionCode = (findProperty("versionCode") as String?)?.toIntOrNull() ?: 1
        versionName = (findProperty("versionName") as String?) ?: "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters.add("arm64-v8a")
        }
    }

    signingConfigs {
        if (releaseSigningComplete) {
            create("release") {
                storeFile = file(releaseStoreFile!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
                storeType = releaseStoreType
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Only bind the signingConfig when the signing information is
            // complete; an incomplete one is dropped by AGP and then fails the
            // build with a misleading "Keystore file not set" message.
            if (releaseSigningComplete) {
                signingConfigs.findByName("release")?.let { signingConfig = it }
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
    sourceSets {
        named("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

// AGP 9 compiles Kotlin itself and drops the old android.kotlinOptions{} DSL;
// the compiler options now live in the Kotlin extension AGP registers.
kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_11
    }
}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    // androidx.compose.material.icons.Icons: material3 no longer brings the
    // icon artifact in transitively (BOM 2026.09), so declare it explicitly.
    implementation(libs.androidx.material.icons.core)
    // QR code scanning (camera) and generation. CameraX is used directly with
    // ZXing's core decoder instead of ML Kit so that scanning works without
    // Google Play Services and offline.
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.zxing.core)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)
}