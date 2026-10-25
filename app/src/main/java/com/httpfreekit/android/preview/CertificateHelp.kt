package com.httpfreekit.android.preview

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.httpfreekit.android.R

/** Preparation help only; this component has no connection, credential or trust-state action. */
@Composable
fun CertificateHelp(onOpenSecuritySettings: () -> Boolean, onCopyConfiguration: (String) -> Unit) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    var showConfiguration by rememberSaveable { mutableStateOf(false) }
    var settingsUnavailable by rememberSaveable { mutableStateOf(false) }
    var copyStatus by rememberSaveable { mutableIntStateOf(0) }
    val manifest = stringResource(R.string.certificate_debug_manifest)
    val trust = stringResource(R.string.certificate_debug_trust)

    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.help_https_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.help_https_body), style = MaterialTheme.typography.bodyMedium)
            OutlinedButton(onClick = { expanded = true }, modifier = Modifier.testTag("certificate-help-toggle")) {
                Text(stringResource(R.string.certificate_help_open))
            }
        }
    }
    if (expanded) AlertDialog(
        onDismissRequest = { expanded = false },
        modifier = Modifier.testTag("certificate-help-panel"),
        title = { Text(stringResource(R.string.certificate_help_title)) },
        text = {
            Column(Modifier.heightIn(max = 420.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text(stringResource(R.string.certificate_help_scope), style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary)
                HelpSection(R.string.certificate_identity_title, R.string.certificate_identity_body)
                HelpSection(R.string.certificate_fingerprint_title, R.string.certificate_fingerprint_body)
                HelpSection(R.string.certificate_install_title, R.string.certificate_install_body)
                OutlinedButton(onClick = { settingsUnavailable = !onOpenSecuritySettings() },
                    modifier = Modifier.testTag("certificate-open-security-settings")) {
                    Text(stringResource(R.string.certificate_open_settings))
                }
                if (settingsUnavailable) Text(stringResource(R.string.certificate_settings_unavailable),
                    modifier = Modifier.testTag("certificate-settings-unavailable"), color = MaterialTheme.colorScheme.error)
                HelpSection(R.string.certificate_debug_title, R.string.certificate_debug_body)
                TextButton(onClick = { showConfiguration = !showConfiguration }, modifier = Modifier.testTag("debug-config-toggle")) {
                    Text(stringResource(if (showConfiguration) R.string.certificate_hide_config else R.string.certificate_show_config))
                }
                if (showConfiguration) {
                    Text(stringResource(R.string.certificate_existing_config))
                    Text(stringResource(R.string.certificate_resource_path), fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall)
                    Text(stringResource(R.string.certificate_resource_body))
                    ConfigurationExample(R.string.certificate_manifest_path, manifest, "debug-manifest-code", "debug-manifest-copy",
                        R.string.certificate_copy_manifest) {
                        copyStatus = copyExample(manifest, onCopyConfiguration, 1)
                    }
                    ConfigurationExample(R.string.certificate_trust_path, trust, "debug-trust-code", "debug-trust-copy",
                        R.string.certificate_copy_trust) {
                        copyStatus = copyExample(trust, onCopyConfiguration, 2)
                    }
                    if (copyStatus != 0) Text(stringResource(when (copyStatus) {
                        1 -> R.string.certificate_manifest_copied
                        2 -> R.string.certificate_trust_copied
                        else -> R.string.certificate_copy_unavailable
                    }), modifier = Modifier.testTag("debug-copy-status"), style = MaterialTheme.typography.labelMedium)
                }
                Text(stringResource(R.string.certificate_pinning_body))
                HelpSection(R.string.certificate_remove_title, R.string.certificate_remove_body)
            }
        },
        confirmButton = {
            TextButton(onClick = { expanded = false }, modifier = Modifier.testTag("certificate-help-close")) {
                Text(stringResource(R.string.certificate_help_close))
            }
        },
    )
}

private fun copyExample(value: String, copy: (String) -> Unit, status: Int): Int =
    try { copy(value); status } catch (_: RuntimeException) { 3 }

@Composable
private fun HelpSection(title: Int, body: Int) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(title), style = MaterialTheme.typography.titleSmall)
        Text(stringResource(body), style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ConfigurationExample(path: Int, code: String, codeTag: String, copyTag: String, copyLabel: Int, onCopy: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(path), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
        OutlinedCard(Modifier.fillMaxWidth()) {
            SelectionContainer {
                Text(code, modifier = Modifier.padding(12.dp).horizontalScroll(rememberScrollState()).testTag(codeTag),
                    fontFamily = FontFamily.Monospace, fontSize = 12.sp)
            }
        }
        TextButton(onClick = onCopy, modifier = Modifier.testTag(copyTag)) { Text(stringResource(copyLabel)) }
    }
}
