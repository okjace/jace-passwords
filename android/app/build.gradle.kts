import java.util.Base64

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.parcelize")
}

// The version comes from jace_passwords/__init__.py (APP_VERSION), like every other Jace Passwords build.
val appVersion: String = run {
    val init = rootProject.file("../jace_passwords/__init__.py").readText()
    Regex("""APP_VERSION = "([^"]+)"""").find(init)?.groupValues?.get(1) ?: "0.0.0"
}
val appVersionCode: Int = appVersion.split(".").map { it.toIntOrNull() ?: 0 }.let { (it + listOf(0, 0, 0)).take(3) }
    .let { (a, b, c) -> a * 10000 + b * 100 + c }

// Release signing: the keystore from packaging/android_keystore.py, given to CI as secrets. Every release must
// be signed with the same key, or Android refuses the update.
val keystoreB64: String? = System.getenv("ANDROID_KEYSTORE_B64")
val keystorePassword: String? = System.getenv("ANDROID_KEYSTORE_PASSWORD")
val keystoreFile = layout.buildDirectory.file("release.p12").get().asFile

android {
    namespace = "com.okjace.jacepasswords"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.okjace.jacepasswords"
        minSdk = 26
        targetSdk = 35
        versionCode = appVersionCode
        versionName = appVersion
    }

    signingConfigs {
        if (!keystoreB64.isNullOrBlank() && !keystorePassword.isNullOrBlank()) {
            create("release") {
                keystoreFile.parentFile.mkdirs()
                keystoreFile.writeBytes(Base64.getDecoder().decode(keystoreB64.trim()))
                storeFile = keystoreFile
                storeType = "pkcs12"
                storePassword = keystorePassword
                keyAlias = "jacepasswords"
                keyPassword = keystorePassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.browser:browser:1.8.0")
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303") // the real org.json for JVM tests (android.jar's is a stub)
}
