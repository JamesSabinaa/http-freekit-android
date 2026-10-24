package com.httpfreekit.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.ViewModelProvider
import com.httpfreekit.android.preview.PreviewApp
import com.httpfreekit.android.preview.PreviewViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val preview = ViewModelProvider(this)[PreviewViewModel::class.java]
        setContent {
            PreviewApp(preview.state, preview::dispatch, preview::reviewInvitation)
        }
    }
}
