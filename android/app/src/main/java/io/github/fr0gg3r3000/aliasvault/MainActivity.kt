package io.github.fr0gg3r3000.aliasvault

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.webkit.WebViewAssetLoader
import java.io.ByteArrayInputStream

/**
 * A thin, locked-down shell around the AliasVault web page (bundled in assets/).
 *
 *  - No INTERNET permission, and every request that is not for a bundled file is answered with 403.
 *  - The page can never navigate away, open windows, read files or use location.
 *  - Screenshots and the recent-apps preview are blocked (FLAG_SECURE).
 *  - The vault is locked if you leave the app for more than LOCK_AFTER_MS.
 *  - Copied passwords are flagged as sensitive so Android hides them from clipboard previews.
 */
class MainActivity : Activity() {

    private lateinit var webView: WebView
    private var leftAt = 0L

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        WindowCompat.setDecorFitsSystemWindows(window, false)

        val assetLoader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()

        webView = WebView(this).apply {
            setBackgroundColor(Color.parseColor("#0E0206"))
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS

            settings.apply {
                javaScriptEnabled = true          // the app is a JavaScript page
                domStorageEnabled = true          // the encrypted vault lives in localStorage
                allowFileAccess = false
                allowContentAccess = false
                mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
                javaScriptCanOpenWindowsAutomatically = false
                setSupportMultipleWindows(false)
                setGeolocationEnabled(false)
                cacheMode = WebSettings.LOAD_NO_CACHE
            }

            webViewClient = object : WebViewClient() {
                override fun shouldInterceptRequest(
                    view: WebView,
                    request: WebResourceRequest
                ): WebResourceResponse? =
                    assetLoader.shouldInterceptRequest(request.url) ?: blocked()

                override fun shouldOverrideUrlLoading(
                    view: WebView,
                    request: WebResourceRequest
                ): Boolean = true // never navigate anywhere else
            }

            addJavascriptInterface(ClipBridge(applicationContext), "AndroidClip")
        }

        val root = FrameLayout(this).apply {
            setBackgroundColor(Color.parseColor("#0E0206"))
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            addView(
                webView,
                FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            )
        }
        setContentView(root)

        // Edge-to-edge: keep the page clear of the status bar, navigation bar, cut-outs and keyboard.
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or
                    WindowInsetsCompat.Type.displayCutout() or
                    WindowInsetsCompat.Type.ime()
            )
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            WindowInsetsCompat.CONSUMED
        }

        webView.loadUrl(START_URL)
    }

    override fun onStop() {
        super.onStop()
        leftAt = SystemClock.elapsedRealtime()
    }

    override fun onStart() {
        super.onStart()
        if (leftAt != 0L && SystemClock.elapsedRealtime() - leftAt > LOCK_AFTER_MS) {
            webView.evaluateJavascript(
                "if(typeof lock==='function')lock('Locked when you left the app.')",
                null
            )
        }
        leftAt = 0L
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onBackPressed() {
        // Close an open dialog first; otherwise send the app to the background.
        webView.evaluateJavascript(
            "(function(){var d=document.getElementById('dlg');if(d&&d.open){d.close();return 1}return 0})()"
        ) { result -> if (result != "1") moveTaskToBack(true) }
    }

    override fun onDestroy() {
        webView.destroy()
        super.onDestroy()
    }

    private fun blocked() = WebResourceResponse(
        "text/plain", "utf-8", 403, "Blocked", emptyMap(), ByteArrayInputStream(ByteArray(0))
    )

    private companion object {
        const val START_URL = "https://appassets.androidplatform.net/assets/index.html"
        const val LOCK_AFTER_MS = 60_000L
    }
}

/** Lets the page copy a password as "sensitive" and clear it again. Only our own bundled page can call this. */
class ClipBridge(private val context: Context) {

    private val clipboard: ClipboardManager
        get() = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    @JavascriptInterface
    fun copy(text: String) {
        val clip = ClipData.newPlainText("AliasVault", text)
        clip.description.extras = PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
        clipboard.setPrimaryClip(clip)
    }

    @JavascriptInterface
    fun clear(expected: String) {
        // Android only lets the foreground app read the clipboard; if we can't, clear it anyway.
        val current: String? = try {
            val clip = clipboard.primaryClip
            if (clip != null && clip.itemCount > 0) clip.getItemAt(0).text?.toString() else null
        } catch (e: Exception) {
            null
        }
        if (current == null || current == expected) {
            if (Build.VERSION.SDK_INT >= 28) {
                clipboard.clearPrimaryClip()
            } else {
                clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        }
    }
}
