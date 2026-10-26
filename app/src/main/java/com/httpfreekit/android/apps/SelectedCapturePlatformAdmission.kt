package com.httpfreekit.android.apps

/** Finite current-user observations; no package or provider details in failures. */
enum class SelectedPackageAvailability { AVAILABLE, NOT_INSTALLED, DISABLED, UNAVAILABLE }

fun interface SelectedPackageProbe {
    fun availability(packageName: String): SelectedPackageAvailability
}

enum class SelectedCapturePlatformRejection {
    SELECTION_REJECTED, PACKAGE_NOT_INSTALLED, PACKAGE_DISABLED, PACKAGE_LOOKUP_FAILED,
}

sealed interface SelectedCapturePlatformResult {
    class Checked(val plan: SelectedCapturePlan) : SelectedCapturePlatformResult {
        override fun toString() = "SelectedCapturePlatformResult.Checked([REDACTED])"
    }

    class Rejected(val reason: SelectedCapturePlatformRejection) : SelectedCapturePlatformResult {
        override fun toString() = "SelectedCapturePlatformResult.Rejected([REDACTED])"
    }
}

/** Past observations only, never start authorization, VPN consent or transport readiness. */
object SelectedCapturePlatformAdmission {
    fun check(
        selection: AppSelectionState,
        companionPackageName: String,
        probe: SelectedPackageProbe,
    ): SelectedCapturePlatformResult {
        val admitted = SelectedCaptureAdmission.prepare(selection, companionPackageName)
        if (admitted !is SelectedCaptureResult.Accepted) {
            return reject(SelectedCapturePlatformRejection.SELECTION_REJECTED)
        }
        // B5 owns the defensive snapshot. Do not revisit mutable inventory or visible filters.
        for (packageName in admitted.plan.selectedPackages) {
            val availability = try {
                probe.availability(packageName)
            } catch (_: RuntimeException) {
                // Includes SecurityException; intentionally does not catch fatal JVM errors.
                SelectedPackageAvailability.UNAVAILABLE
            }
            val reason = when (availability) {
                SelectedPackageAvailability.AVAILABLE -> null
                SelectedPackageAvailability.NOT_INSTALLED -> SelectedCapturePlatformRejection.PACKAGE_NOT_INSTALLED
                SelectedPackageAvailability.DISABLED -> SelectedCapturePlatformRejection.PACKAGE_DISABLED
                SelectedPackageAvailability.UNAVAILABLE -> SelectedCapturePlatformRejection.PACKAGE_LOOKUP_FAILED
            }
            if (reason != null) return reject(reason)
        }
        return SelectedCapturePlatformResult.Checked(admitted.plan)
    }

    private fun reject(reason: SelectedCapturePlatformRejection) = SelectedCapturePlatformResult.Rejected(reason)
}
