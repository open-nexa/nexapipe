package com.nexa.pipe

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.viewmodel.compose.viewModel
import com.nexa.pipe.locale.AppLocale
import com.nexa.pipe.ui.VpnControlScreen
import com.nexa.pipe.ui.VpnViewModel
import com.nexa.pipe.ui.theme.NexaTheme

class MainActivity : ComponentActivity() {
    // Resources are resolved per context, so the selected language is applied
    // here rather than once for the process: a language switch recreates this
    // activity and it comes back through this hook with the new one.
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(AppLocale.apply(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val viewModel: VpnViewModel = viewModel()
            // Load the persisted settings once, when the composition enters,
            // instead of on every recomposition: re-reading them each time is
            // wasteful and can stomp on in-memory state that is being edited.
            LaunchedEffect(Unit) {
                viewModel.initSettings(this@MainActivity)
                viewModel.loadSettings()
                // Sync UI state: after the activity is recreated, the
                // ViewModel's isVpnRunning may be false while the VPN service
                // is still running. Check the service-level flag to restore
                // the correct UI state.
                viewModel.syncVpnServiceState()
            }
            NexaTheme {
                // No Scaffold here: VpnControlScreen brings its own (top bar +
                // FAB + padding), and wrapping it in a second one would mean
                // dropping the outer padding on the floor.
                VpnControlScreen()
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun VpnControlPreview() {
    NexaTheme {
        VpnControlScreen()
    }
}