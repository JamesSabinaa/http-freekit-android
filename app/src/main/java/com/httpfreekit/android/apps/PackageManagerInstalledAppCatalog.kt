package com.httpfreekit.android.apps

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.util.Locale

/** Current-profile installed applications, including packages with no launcher activity. No I/O export. */
class PackageManagerInstalledAppCatalog(context: Context) : InstalledAppCatalog {
    private val application = context.applicationContext

    override fun load(): List<InstalledAppEntry> {
        val manager = application.packageManager
        val applications = if (Build.VERSION.SDK_INT >= 33) {
            manager.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            manager.getInstalledApplications(0)
        }
        return applications.asSequence().filter { app ->
            app.packageName != application.packageName && app.enabled && app.flags and ApplicationInfo.FLAG_INSTALLED != 0
        }.filter { app ->
            try {
                manager.getApplicationEnabledSetting(app.packageName) !in setOf(
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER,
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED,
                )
            } catch (_: IllegalArgumentException) { false } // Removed while the scan was running.
        }.map { app ->
            val label = try { manager.getApplicationLabel(app).toString().trim().ifEmpty { app.packageName } }
            catch (_: RuntimeException) { app.packageName }
            InstalledAppEntry(app.packageName, label, app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        }.sortedWith(compareBy<InstalledAppEntry> { it.label.lowercase(Locale.ROOT) }.thenBy { it.packageName })
            .distinctBy { it.packageName }.toList()
    }
}
