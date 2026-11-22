package io.github.themodin.morpheus.tls

import groovy.util.logging.Slf4j
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit

/**
 * In-plugin timer: Morpheus Jobs are not available on every edition, so the plugin checks by itself once a day
 * (the renewal window is days, so daily is plenty). A check only issues a certificate when one is due.
 */
@Slf4j
class CertScheduler {
    final SettingsStore store
    final RenewalRunner runner
    private ScheduledExecutorService exec

    CertScheduler(SettingsStore store, RenewalRunner runner) { this.store = store; this.runner = runner }

    void start() {
        exec = Executors.newSingleThreadScheduledExecutor({ Runnable r ->
            Thread t = new Thread(r, 'tls-scheduler'); t.daemon = true; t } as ThreadFactory)
        exec.scheduleWithFixedDelay({ -> tick() } as Runnable, 2, 24 * 60, TimeUnit.MINUTES)
    }

    void stop() { exec?.shutdownNow() }

    void tick() {
        try {
            Map<String, String> m = store.load()
            if (m.autoRenew != 'true') {
                return
            }
            if (!runner.start('renew', 'schedule')) {
                log.info('Scheduled check skipped: a run is already in progress')
            }
        } catch (Throwable t) {
            log.warn('Scheduled check failed: {}', t.toString())
        }
    }
}
