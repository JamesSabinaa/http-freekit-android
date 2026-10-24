package com.httpfreekit.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.ViewModelProvider
import com.httpfreekit.android.preview.PreviewApp
import com.httpfreekit.android.preview.PreviewViewModel
import com.httpfreekit.android.apps.PackageManagerInstalledAppCatalog
import androidx.lifecycle.ViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val factory = object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                require(modelClass.isAssignableFrom(PreviewViewModel::class.java))
                @Suppress("UNCHECKED_CAST")
                return PreviewViewModel(PackageManagerInstalledAppCatalog(applicationContext)) as T
            }
        }
        val preview = ViewModelProvider(this, factory)[PreviewViewModel::class.java]
        setContent {
            PreviewApp(preview.state, preview.apps, preview::dispatch, preview::dispatchApps, preview::reviewInvitation)
        }
    }
}
