package com.httpfreekit.android.apps

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

/** Exact-package, current-user lookup only. Retains no activity, inventory or lookup failures. */
class PackageManagerSelectedPackageProbe(context: Context) : SelectedPackageProbe {
    private val application = context.applicationContext

    override fun availability(packageName: String): SelectedPackageAvailability = try {
        val manager = application.packageManager
        // Include disabled applications so they are classified, never treated as available by omission.
        val flags = PackageManager.MATCH_DISABLED_COMPONENTS or PackageManager.MATCH_DISABLED_UNTIL_USED_COMPONENTS
        val info = if (Build.VERSION.SDK_INT >= 33) {
            manager.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            manager.getApplicationInfo(packageName, flags)
        }
        if (info.packageName != packageName) {
            SelectedPackageAvailability.UNAVAILABLE
        } else {
            classifySelectedPackageAvailability(
                installed = info.flags and ApplicationInfo.FLAG_INSTALLED != 0,
                enabled = info.enabled,
                suspended = info.flags and ApplicationInfo.FLAG_SUSPENDED != 0,
                enabledSetting = manager.getApplicationEnabledSetting(packageName),
            )
        }
    } catch (_: PackageManager.NameNotFoundException) {
        SelectedPackageAvailability.NOT_INSTALLED
    } catch (_: RuntimeException) {
        // SecurityException, removed-during-query and other provider failures are finite/redacted.
        SelectedPackageAvailability.UNAVAILABLE
    }
}

/** Pure classification for the public API26+ observations; no Android methods or retained details. */
internal fun classifySelectedPackageAvailability(
    installed: Boolean,
    enabled: Boolean,
    suspended: Boolean,
    enabledSetting: Int,
): SelectedPackageAvailability {
    if (!installed) return SelectedPackageAvailability.NOT_INSTALLED
    return when (enabledSetting) {
        PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
        PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER,
        PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED -> SelectedPackageAvailability.DISABLED
        PackageManager.COMPONENT_ENABLED_STATE_DEFAULT,
        PackageManager.COMPONENT_ENABLED_STATE_ENABLED -> {
            if (enabled && !suspended) SelectedPackageAvailability.AVAILABLE else SelectedPackageAvailability.DISABLED
        }
        else -> SelectedPackageAvailability.UNAVAILABLE
    }
}
