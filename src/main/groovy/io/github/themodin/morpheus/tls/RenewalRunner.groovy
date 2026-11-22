package io.github.themodin.morpheus.tls

import io.github.themodin.morpheus.tls.core.CommandRunner
import io.github.themodin.morpheus.tls.core.RenewalResult
import io.github.themodin.morpheus.tls.core.RenewalService
import io.github.themodin.morpheus.tls.core.RenewalSettings
import groovy.util.logging.Slf4j
import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean

/** Runs checks/renewals in the background, one at a time, remembering the outcome for the admin page. */
@Slf4j
class RenewalRunner {
    final SettingsStore store
    private final AtomicBoolean running = new AtomicBoolean(false)
    volatile Map current = [:]
    volatile Map last

    RenewalRunner(SettingsStore store) { this.store = store; this.last = null }

    boolean isRunning() { running.get() }

    Map lastRun() { last != null ? last : store.lastRun() }

    /** @return true when started, false when another run is still in progress */
    boolean start(String mode, String trigger) {
        if (!running.compareAndSet(false, true)) {
            return false
        }
        current = [mode: mode, trigger: trigger, startedAt: Instant.now().toString()]
        Thread t = new Thread({ -> runNow(mode, trigger) } as Runnable, 'tls-run')
        t.daemon = true
        t.start()
        return true
    }

    private void runNow(String mode, String trigger) {
        Map summary = [mode: mode, trigger: trigger, startedAt: current.startedAt]
        try {
            Map<String, String> stored = store.load()
            RenewalSettings s = store.toRenewalSettings(stored, mode == 'check', mode == 'force')
            RenewalResult r = new RenewalService(new CommandRunner.Local(), { Instant.now() }).run(s)
            summary += [success: r.success, status: r.status.toString(), message: r.message, log: r.logText(),
                        notAfterBefore: r.notAfterBefore?.toString(), notAfterAfter: r.notAfterAfter?.toString()]
        } catch (Throwable t) {
            log.error("TLS run crashed", t)
            summary += [success: false, status: 'ERROR', message: "Unexpected error: ${t.message}", log: t.toString()]
        } finally {
            summary.finishedAt = Instant.now().toString()
            last = summary
            store.saveLastRun(summary)
            running.set(false)
        }
    }
}
