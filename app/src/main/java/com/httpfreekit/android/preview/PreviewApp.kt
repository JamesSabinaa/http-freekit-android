package com.httpfreekit.android.preview

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.httpfreekit.android.R
import com.httpfreekit.android.apps.AppCatalogMode
import com.httpfreekit.android.apps.AppFilter
import com.httpfreekit.android.apps.AppSelectionAction
import com.httpfreekit.android.apps.AppSelectionState
import com.httpfreekit.android.apps.InstalledAppEntry
import com.httpfreekit.protocol.PairingInvitationParser
import java.time.Instant
import java.util.Locale
import kotlinx.coroutines.delay

private enum class PreviewPage(val label: Int) {
    HOME(R.string.page_home), APPS(R.string.page_apps), SETUP(R.string.page_setup), DIAGNOSTICS(R.string.page_diagnostics),
}

private val LightColors = lightColorScheme(
    primary = Color(0xFF155B52), onPrimary = Color.White,
    primaryContainer = Color(0xFFD4F3E8), onPrimaryContainer = Color(0xFF0C3630),
    secondary = Color(0xFF42646D), background = Color(0xFFF5F8F7),
    surface = Color(0xFFF5F8F7),
)
private val DarkColors = darkColorScheme(
    primary = Color(0xFF83D5BE), onPrimary = Color(0xFF00382D),
    primaryContainer = Color(0xFF164E43), onPrimaryContainer = Color(0xFFBEF3E3),
    secondary = Color(0xFFB5CED4), background = Color(0xFF0E171A), surface = Color(0xFF0E171A),
)

@Composable
fun PreviewApp(state: PreviewState, apps: AppSelectionState, onAction: (PreviewAction) -> Unit,
    onAppsAction: (AppSelectionAction) -> Unit, onInvitation: (String) -> Unit,
    onOpenSecuritySettings: () -> Boolean, onCopyConfiguration: (String) -> Unit) {
    var page by rememberSaveable { mutableStateOf(PreviewPage.HOME.name) }
    var addingComputer by remember { mutableStateOf(false) }
    var forgettingComputer by remember { mutableStateOf<PreviewComputer?>(null) }
    val keyboardVisible = WindowInsets.ime.getBottom(LocalDensity.current) > 0

    LaunchedEffect(state.phase, state.attempt, state.gatewayAvailable) {
        if (state.phase == PreviewPhase.CONNECTING || state.phase == PreviewPhase.RECONNECTING) {
            delay(900)
            onAction(PreviewAction.GatewayResult(state.attempt, state.gatewayAvailable))
        }
    }

    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors) {
        Scaffold(
            contentWindowInsets = WindowInsets.safeDrawing,
            topBar = {
                Column(Modifier.statusBarsPadding().fillMaxWidth()) {
                    if (!keyboardVisible) {
                        Row(
                            Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(stringResource(R.string.brand_eyebrow), style = MaterialTheme.typography.labelMedium)
                                Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
                            }
                            AssistChip(onClick = { page = PreviewPage.SETUP.name }, label = { Text(stringResource(R.string.preview_badge)) })
                        }
                    }
                    Row(
                        Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 24.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        PreviewPage.entries.forEach { destination ->
                            FilterChip(
                                selected = page == destination.name,
                                onClick = { page = destination.name },
                                label = { Text(stringResource(destination.label)) },
                            )
                        }
                    }
                    Text(
                        stringResource(R.string.preview_banner),
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            },
        ) { padding ->
            LazyColumn(
                modifier = Modifier.padding(padding),
                contentPadding = PaddingValues(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                when (PreviewPage.valueOf(page)) {
                    PreviewPage.HOME -> {
                        item { SessionCard(state, onAction) { page = PreviewPage.APPS.name } }
                        state.problem?.let { problem -> item { ProblemCard(problem) } }
                        if (state.phase == PreviewPhase.AWAITING_APPROVAL) item { PendingApprovalCard(onAction) }
                        item { ReadinessCard(state) { page = PreviewPage.SETUP.name } }
                        item {
                            ComputersCard(state, onAction, { addingComputer = true }, { forgettingComputer = it })
                        }
                    }
                    PreviewPage.APPS -> {
                        item {
                            SectionIntro(R.string.apps_title, R.string.apps_description)
                            if (state.canStop) Text(stringResource(R.string.apps_locked), color = MaterialTheme.colorScheme.error)
                        }
                        item { AppCatalogControls(apps, state.canStop, onAppsAction) }
                        if (apps.mode == AppCatalogMode.SAMPLE) {
                            items(PreviewApps, key = { "sample:${it.id}" }) { app ->
                                AppChoice(app, app.id in apps.selectedIds, !state.canStop) {
                                    onAction(PreviewAction.SelectApp(app.id, it))
                                }
                            }
                        } else {
                            items(apps.visibleInstalled, key = { "installed:${it.packageName}" }) { app ->
                                InstalledAppChoice(app, app.packageName in apps.selectedIds, !state.canStop) {
                                    onAction(PreviewAction.SelectApp(app.packageName, it))
                                }
                            }
                            if (apps.loaded && !apps.loading && apps.visibleInstalled.isEmpty()) {
                                item { Text(stringResource(if (apps.installed.isEmpty()) R.string.apps_empty else R.string.apps_no_matches)) }
                            }
                        }
                        item {
                            Text(stringResource(R.string.selected_apps_count, state.selectedAppIds.size), style = MaterialTheme.typography.titleMedium)
                            TextButton(onClick = { page = PreviewPage.HOME.name }) { Text(stringResource(R.string.return_home)) }
                        }
                    }
                    PreviewPage.SETUP -> {
                        item { SectionIntro(R.string.setup_title, R.string.setup_description) }
                        item { HelpCard(R.string.help_pair_title, R.string.help_pair_body) }
                        item { HelpCard(R.string.help_vpn_title, R.string.help_vpn_body) }
                        item { CertificateHelp(onOpenSecuritySettings, onCopyConfiguration) }
                        item { HelpCard(R.string.help_privacy_title, R.string.help_privacy_body) }
                        item { HelpCard(R.string.help_stop_title, R.string.help_stop_body) }
                    }
                    PreviewPage.DIAGNOSTICS -> {
                        item { SectionIntro(R.string.diagnostics_title, R.string.diagnostics_description) }
                        state.problem?.let { problem -> item { ProblemCard(problem) } }
                        item { ScenarioCard(state, onAction) }
                        item {
                            OutlinedCard(Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Text(stringResource(R.string.recent_events), style = MaterialTheme.typography.titleMedium)
                                    if (state.diagnostics.isEmpty()) Text(stringResource(R.string.no_events))
                                    state.diagnostics.asReversed().forEach { event ->
                                        Text(event.name.lowercase(Locale.ROOT), fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (addingComputer) AddComputerDialog(
            onDismiss = { addingComputer = false },
            onReview = { payload -> onInvitation(payload); addingComputer = false },
        )
        state.review?.let { review -> ReviewDialog(review, onAction) }
        forgettingComputer?.let { computer ->
            AlertDialog(
                onDismissRequest = { forgettingComputer = null },
                title = { Text(stringResource(R.string.forget_title, computer.name)) },
                text = { Text(stringResource(R.string.forget_body)) },
                confirmButton = {
                    TextButton(onClick = { onAction(PreviewAction.ForgetComputer(computer.id)); forgettingComputer = null }) {
                        Text(stringResource(R.string.forget))
                    }
                },
                dismissButton = { TextButton(onClick = { forgettingComputer = null }) { Text(stringResource(R.string.cancel)) } },
            )
        }
        if (state.phase == PreviewPhase.AWAITING_NOTIFICATIONS) AlertDialog(
            onDismissRequest = { onAction(PreviewAction.NotificationPermission(false)) },
            title = { Text(stringResource(R.string.notification_title)) },
            text = { Text(stringResource(R.string.notification_body)) },
            confirmButton = { TextButton(onClick = { onAction(PreviewAction.NotificationPermission(true)) }) { Text(stringResource(R.string.allow_preview)) } },
            dismissButton = { TextButton(onClick = { onAction(PreviewAction.NotificationPermission(false)) }) { Text(stringResource(R.string.deny)) } },
        )
        if (state.phase == PreviewPhase.AWAITING_VPN_CONSENT) AlertDialog(
            onDismissRequest = { onAction(PreviewAction.VpnConsent(false)) },
            title = { Text(stringResource(R.string.vpn_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.vpn_body))
                    if (state.existingVpn) Text(stringResource(R.string.vpn_conflict), color = MaterialTheme.colorScheme.error)
                }
            },
            confirmButton = { TextButton(onClick = { onAction(PreviewAction.VpnConsent(true)) }) { Text(stringResource(R.string.allow_preview)) } },
            dismissButton = { TextButton(onClick = { onAction(PreviewAction.VpnConsent(false)) }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

@Composable
private fun SessionCard(state: PreviewState, onAction: (PreviewAction) -> Unit, onChooseApps: () -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
        Column(Modifier.fillMaxWidth().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.connection_preview), style = MaterialTheme.typography.labelLarge)
            Text(stringResource(phaseTitle(state.phase)), style = MaterialTheme.typography.headlineMedium)
            Text(stringResource(phaseDescription(state.phase)))
            state.selectedComputer?.let { computer ->
                Text(stringResource(R.string.computer_transport, computer.name, computer.transport), style = MaterialTheme.typography.titleSmall)
            }
            TextButton(onClick = onChooseApps, enabled = !state.canStop) {
                Text(stringResource(R.string.selected_apps_count, state.selectedAppIds.size))
            }
            if (state.phase == PreviewPhase.CONNECTING || state.phase == PreviewPhase.RECONNECTING) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                if (state.phase == PreviewPhase.RECONNECTING) Text(
                    stringResource(R.string.retry_count, state.reconnectAttempts, PreviewCoordinator.MAX_RECONNECT_ATTEMPTS),
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            if (state.canStop) {
                Button(onClick = { onAction(PreviewAction.Stop) }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.stop_preview)) }
            } else {
                Button(onClick = { onAction(PreviewAction.Connect) }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.start_preview)) }
            }
            Text(stringResource(R.string.no_traffic_captured), style = MaterialTheme.typography.labelMedium)
        }
    }
}

@Composable
private fun ReadinessCard(state: PreviewState, onHelp: () -> Unit) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.setup_checks), style = MaterialTheme.typography.titleMedium)
            CheckRow(R.string.check_computer, if (state.selectedComputer?.credentials == PreviewCredentials.AVAILABLE) R.string.check_preview_only else R.string.check_needed)
            CheckRow(R.string.check_vpn, if (state.vpnConsent) R.string.check_simulated else R.string.check_not_requested)
            CheckRow(R.string.check_gateway, if (state.phase == PreviewPhase.CONNECTED) R.string.check_simulated else R.string.check_not_connected)
            CheckRow(R.string.check_https, R.string.check_not_verified, "readiness-https")
            CheckRow(R.string.check_traffic, R.string.check_not_verified, "readiness-capture")
            TextButton(onClick = onHelp) { Text(stringResource(R.string.trust_help)) }
        }
    }
}

@Composable
private fun CheckRow(label: Int, value: Int, tag: String? = null) {
    val association = if (tag == null) Modifier else Modifier.semantics(mergeDescendants = true) {}.testTag(tag)
    Row(Modifier.fillMaxWidth().then(association), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(stringResource(label), modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.width(12.dp))
        Text(stringResource(value), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun ComputersCard(state: PreviewState, onAction: (PreviewAction) -> Unit, onAdd: () -> Unit, onForget: (PreviewComputer) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.computers_title), style = MaterialTheme.typography.titleLarge)
        if (state.computers.isEmpty()) Text(stringResource(R.string.computers_empty))
        state.computers.forEach { computer ->
            OutlinedCard(Modifier.fillMaxWidth()) {
                Row(Modifier.fillMaxWidth().selectable(
                    selected = computer.id == state.selectedComputerId, enabled = !state.canStop,
                    role = Role.RadioButton, onClick = { onAction(PreviewAction.SelectComputer(computer.id)) },
                ).padding(12.dp)) {
                    RadioButton(
                        selected = computer.id == state.selectedComputerId,
                        onClick = null, enabled = !state.canStop,
                    )
                    Column(Modifier.weight(1f).padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(computer.name, style = MaterialTheme.typography.titleMedium)
                        Text(stringResource(credentialsLabel(computer.credentials)), style = MaterialTheme.typography.bodySmall)
                        Text(computer.transport, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                    }
                    TextButton(onClick = { onForget(computer) }) { Text(stringResource(R.string.forget)) }
                }
            }
        }
        OutlinedButton(onClick = onAdd, enabled = !state.canStop, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.add_computer)) }
        TextButton(onClick = { onAction(PreviewAction.LoadSampleComputer) }, enabled = !state.canStop) { Text(stringResource(R.string.try_sample)) }
        Text(stringResource(R.string.computers_ephemeral), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun PendingApprovalCard(onAction: (PreviewAction) -> Unit) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.pending_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.pending_body))
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { onAction(PreviewAction.ApprovePairing) }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.simulate_approval)) }
                OutlinedButton(onClick = { onAction(PreviewAction.RejectPairing) }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.simulate_rejection)) }
            }
        }
    }
}

@Composable
private fun AddComputerDialog(onDismiss: () -> Unit, onReview: (String) -> Unit) {
    // Pairing payloads never enter saved instance state, logs, or the preview model.
    var payload by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.add_computer)) },
        text = {
            Column(Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.paste_invitation_body))
                OutlinedTextField(
                    value = payload, onValueChange = { payload = it.take(PairingInvitationParser.MAX_PAYLOAD_BYTES + 1) },
                    label = { Text(stringResource(R.string.pairing_payload)) }, minLines = 4, maxLines = 6,
                    keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
                    visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
                )
                Text(stringResource(R.string.pairing_secret_help), style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { TextButton(onClick = { onReview(payload) }, enabled = payload.isNotBlank()) { Text(stringResource(R.string.review_invitation)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
private fun ReviewDialog(review: InvitationReview, onAction: (PreviewAction) -> Unit) {
    AlertDialog(
        onDismissRequest = { onAction(PreviewAction.DismissReview) },
        title = { Text(stringResource(R.string.review_computer)) },
        text = {
            Column(Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.review_body))
                Text(review.computer.name, style = MaterialTheme.typography.titleLarge)
                Text(review.computer.serverName, style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.identity_fingerprint), style = MaterialTheme.typography.labelMedium)
                SelectionContainer { Text(review.computer.pin, fontFamily = FontFamily.Monospace, fontSize = 12.sp) }
                Text(stringResource(R.string.route_hint, review.computer.transport, review.computer.address))
                Text(stringResource(R.string.invitation_expiry, review.expiresAt.toString()), style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { TextButton(onClick = { onAction(PreviewAction.ConfirmInvitation(Instant.now())) }) { Text(stringResource(R.string.use_preview)) } },
        dismissButton = { TextButton(onClick = { onAction(PreviewAction.DismissReview) }) { Text(stringResource(R.string.cancel)) } },
    )
}

private data class PreviewAppChoice(val id: String, val title: Int, val description: Int)
private val PreviewApps = listOf(
    PreviewAppChoice("example.browser", R.string.sample_browser, R.string.sample_browser_body),
    PreviewAppChoice("example.debugclient", R.string.sample_debug, R.string.sample_debug_body),
    PreviewAppChoice("example.chat", R.string.sample_chat, R.string.sample_chat_body),
)

@Composable
private fun AppCatalogControls(apps: AppSelectionState, locked: Boolean, onAction: (AppSelectionAction) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = apps.mode == AppCatalogMode.SAMPLE, enabled = !locked,
                onClick = { onAction(AppSelectionAction.Mode(AppCatalogMode.SAMPLE)) },
                label = { Text(stringResource(R.string.apps_mode_sample)) }, modifier = Modifier.testTag("apps-mode-sample"))
            FilterChip(selected = apps.mode == AppCatalogMode.INSTALLED, enabled = !locked,
                onClick = { onAction(AppSelectionAction.Mode(AppCatalogMode.INSTALLED)) },
                label = { Text(stringResource(R.string.apps_mode_installed)) }, modifier = Modifier.testTag("apps-mode-installed"))
        }
        if (apps.mode == AppCatalogMode.SAMPLE) {
            Text(stringResource(R.string.apps_sample_body), style = MaterialTheme.typography.bodyMedium)
        } else {
            Text(stringResource(R.string.apps_installed_body), style = MaterialTheme.typography.bodyMedium)
            OutlinedTextField(value = apps.search, onValueChange = { onAction(AppSelectionAction.Search(it)) },
                label = { Text(stringResource(R.string.apps_search)) }, singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("apps-search"))
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = apps.filter == AppFilter.ALL, onClick = { onAction(AppSelectionAction.Filter(AppFilter.ALL)) },
                    label = { Text(stringResource(R.string.apps_filter_all)) }, modifier = Modifier.testTag("apps-filter-all"))
                FilterChip(selected = apps.filter == AppFilter.DEVELOPMENT, onClick = { onAction(AppSelectionAction.Filter(AppFilter.DEVELOPMENT)) },
                    label = { Text(stringResource(R.string.apps_filter_development)) }, modifier = Modifier.testTag("apps-filter-development"))
                TextButton(onClick = { onAction(AppSelectionAction.Refresh) }, enabled = !locked && !apps.loading,
                    modifier = Modifier.testTag("apps-refresh")) { Text(stringResource(R.string.apps_refresh)) }
            }
            if (apps.loading) LinearProgressIndicator(Modifier.fillMaxWidth())
            val status = when { apps.loading -> "loading"; apps.failed -> "error"; apps.loaded -> "ready"; else -> "idle" }
            Text(when {
                apps.loading -> stringResource(R.string.apps_loading)
                apps.failed -> stringResource(R.string.apps_refresh_failed)
                apps.loaded -> stringResource(R.string.apps_loaded, apps.installed.size)
                else -> stringResource(R.string.apps_not_loaded)
            }, modifier = Modifier.testTag("apps-catalog-status").semantics { stateDescription = status },
                style = MaterialTheme.typography.bodySmall,
                color = if (apps.failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun InstalledAppChoice(app: InstalledAppEntry, selected: Boolean, enabled: Boolean, onSelected: (Boolean) -> Unit) {
    OutlinedCard(Modifier.fillMaxWidth().testTag("installed-app:${app.packageName}")
        .toggleable(value = selected, enabled = enabled, role = Role.Checkbox, onValueChange = onSelected)) {
        Row(Modifier.padding(16.dp)) {
            Checkbox(checked = selected, onCheckedChange = null, enabled = enabled)
            Column(Modifier.padding(start = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(app.label, style = MaterialTheme.typography.titleMedium)
                Text(app.packageName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (app.development) Text(stringResource(R.string.apps_development_badge), style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

@Composable
private fun AppChoice(app: PreviewAppChoice, selected: Boolean, enabled: Boolean, onSelected: (Boolean) -> Unit) {
    OutlinedCard(Modifier.fillMaxWidth().toggleable(value = selected, enabled = enabled, role = Role.Checkbox, onValueChange = onSelected)) {
        Row(Modifier.padding(16.dp)) {
            Checkbox(checked = selected, onCheckedChange = null, enabled = enabled)
            Column(Modifier.padding(start = 8.dp, top = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(app.title), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(app.description), style = MaterialTheme.typography.bodyMedium)
                Text(app.id, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun SectionIntro(title: Int, description: Int) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(title), style = MaterialTheme.typography.headlineSmall)
        Text(stringResource(description), color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun HelpCard(title: Int, body: Int) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(body))
        }
    }
}

@Composable
private fun ProblemCard(problem: PreviewProblem) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
        Text(stringResource(problemMessage(problem)), Modifier.fillMaxWidth().padding(20.dp), color = MaterialTheme.colorScheme.onErrorContainer)
    }
}

@Composable
private fun ScenarioCard(state: PreviewState, onAction: (PreviewAction) -> Unit) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.scenarios_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.scenarios_body), style = MaterialTheme.typography.bodySmall)
            Row(Modifier.fillMaxWidth().toggleable(
                value = state.gatewayAvailable, role = Role.Switch,
                onValueChange = { onAction(PreviewAction.GatewayAvailability(it)) },
            ), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(stringResource(R.string.gateway_available), Modifier.weight(1f).padding(top = 12.dp))
                Switch(state.gatewayAvailable, onCheckedChange = null)
            }
            Row(Modifier.fillMaxWidth().toggleable(
                value = state.existingVpn, role = Role.Switch,
                onValueChange = { onAction(PreviewAction.ExistingVpn(it)) },
            ), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(stringResource(R.string.existing_vpn), Modifier.weight(1f).padding(top = 12.dp))
                Switch(state.existingVpn, onCheckedChange = null)
            }
            HorizontalDivider()
            TextButton(onClick = { onAction(PreviewAction.NetworkChanged) }) { Text(stringResource(R.string.change_network)) }
            TextButton(onClick = { onAction(PreviewAction.RevokeVpn) }, enabled = state.vpnConsent) { Text(stringResource(R.string.revoke_vpn)) }
            TextButton(onClick = { onAction(PreviewAction.RemoveCredentials) }, enabled = state.selectedComputer != null) { Text(stringResource(R.string.remove_key)) }
            TextButton(onClick = { onAction(PreviewAction.RevokeDevice) }, enabled = state.selectedComputer != null) { Text(stringResource(R.string.revoke_device)) }
            TextButton(onClick = { onAction(PreviewAction.CameraUnavailable) }) { Text(stringResource(R.string.camera_unavailable)) }
            TextButton(onClick = { onAction(PreviewAction.Restart) }) { Text(stringResource(R.string.restart_preview)) }
        }
    }
}

private fun phaseTitle(phase: PreviewPhase): Int = when (phase) {
    PreviewPhase.IDLE -> R.string.phase_idle
    PreviewPhase.AWAITING_APPROVAL -> R.string.phase_approval
    PreviewPhase.AWAITING_NOTIFICATIONS, PreviewPhase.AWAITING_VPN_CONSENT -> R.string.phase_permission
    PreviewPhase.CONNECTING -> R.string.phase_connecting
    PreviewPhase.CONNECTED -> R.string.phase_connected
    PreviewPhase.RECONNECTING -> R.string.phase_reconnecting
    PreviewPhase.DISCONNECTED -> R.string.phase_disconnected
    PreviewPhase.NEEDS_PAIRING -> R.string.phase_needs_pairing
}

private fun phaseDescription(phase: PreviewPhase): Int = when (phase) {
    PreviewPhase.IDLE -> R.string.phase_idle_body
    PreviewPhase.AWAITING_APPROVAL -> R.string.phase_approval_body
    PreviewPhase.AWAITING_NOTIFICATIONS, PreviewPhase.AWAITING_VPN_CONSENT -> R.string.phase_permission_body
    PreviewPhase.CONNECTING -> R.string.phase_connecting_body
    PreviewPhase.CONNECTED -> R.string.phase_connected_body
    PreviewPhase.RECONNECTING -> R.string.phase_reconnecting_body
    PreviewPhase.DISCONNECTED -> R.string.phase_disconnected_body
    PreviewPhase.NEEDS_PAIRING -> R.string.phase_needs_pairing_body
}

private fun credentialsLabel(credentials: PreviewCredentials): Int = when (credentials) {
    PreviewCredentials.PENDING -> R.string.credentials_pending
    PreviewCredentials.AVAILABLE -> R.string.credentials_preview
    PreviewCredentials.MISSING -> R.string.credentials_missing
    PreviewCredentials.REVOKED -> R.string.credentials_revoked
}

private fun problemMessage(problem: PreviewProblem): Int = when (problem) {
    PreviewProblem.INVALID_INVITATION -> R.string.error_invalid_invitation
    PreviewProblem.INVITATION_TOO_LARGE -> R.string.error_invitation_large
    PreviewProblem.UNSUPPORTED_VERSION -> R.string.error_version
    PreviewProblem.INVITATION_EXPIRED -> R.string.error_expired
    PreviewProblem.PAIRING_REJECTED -> R.string.error_pairing_rejected
    PreviewProblem.PAIRING_CANCELLED -> R.string.error_pairing_cancelled
    PreviewProblem.SELECT_COMPUTER -> R.string.error_select_computer
    PreviewProblem.SELECT_APPS -> R.string.error_select_apps
    PreviewProblem.MISSING_CREDENTIALS -> R.string.error_missing_key
    PreviewProblem.DEVICE_REVOKED -> R.string.error_revoked
    PreviewProblem.NOTIFICATIONS_DENIED -> R.string.error_notifications
    PreviewProblem.CONSENT_CANCELLED -> R.string.error_consent
    PreviewProblem.VPN_REVOKED -> R.string.error_vpn_revoked
    PreviewProblem.GATEWAY_UNAVAILABLE -> R.string.error_gateway
    PreviewProblem.CAMERA_UNAVAILABLE -> R.string.error_camera
}
