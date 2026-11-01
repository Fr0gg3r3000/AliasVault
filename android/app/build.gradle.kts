plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Passed in by the release workflow:  -PversionName=1.0.0 -PversionCode=12
val appVersionName = (project.findProperty("versionName") as String?) ?: "0.1.0"
val appVersionCode = (project.findProperty("versionCode") as String?)?.toIntOrNull() ?: 1

android {
    namespace = "io.github.fr0gg3r3000.aliasvault"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.fr0gg3r3000.aliasvault"
        minSdk = 26
        targetSdk = 35
        versionCode = appVersionCode
        versionName = appVersionName
    }

    // The signing key never lives in the repo: the workflow decodes it from a GitHub secret
    // and points these environment variables at it.
    val keystorePath: String? = System.getenv("AV_KEYSTORE")
    signingConfigs {
        if (keystorePath != null && File(keystorePath).exists()) {
            create("release") {
                storeFile = File(keystorePath)
                storePassword = System.getenv("AV_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("AV_KEY_ALIAS")
                keyPassword = System.getenv("AV_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    lint {
        abortOnError = false
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.webkit:webkit:1.12.1")
}

// The web page and its libraries are copied into src/main/assets by android/prepare_assets.py.
val assetIndex = file("src/main/assets/index.html")
tasks.register("checkAssets") {
    doFirst {
        if (!assetIndex.exists()) {
            throw GradleException("Missing web assets. Run:  python3 android/prepare_assets.py --download")
        }
    }
}
tasks.named("preBuild") { dependsOn("checkAssets") }
