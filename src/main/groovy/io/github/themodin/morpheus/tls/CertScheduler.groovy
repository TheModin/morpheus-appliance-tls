package io.github.themodin.morpheus.tls

import groovy.util.logging.Slf4j
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit

/**
 * In-plugin timer: Morpheus Jobs are not available on every edition, so the plugin checks by itself once a day
 * (the renewal window is days, so daily is plenty). A check only issues a certificate when one is due.
 * If the settings cannot be read the check is retried after 10 minutes instead of waiting a whole day.
 */
@Slf4j
class CertScheduler {
    static final long RETRY_MINUTES = 10
    static final int MAX_RETRIES = 3
    private int retries = 0
    final SettingsStore store
    final RenewalRunner runner
    final RunLease lease
    private ScheduledExecutorService exec

    CertScheduler(SettingsStore store, RenewalRunner runner, RunLease lease = new RunLease(store)) {
        this.store = store; this.runner = runner; this.lease = lease
    }

    void start() {
        exec = Executors.newSingleThreadScheduledExecutor({ Runnable r ->
            Thread t = new Thread(r, 'tls-scheduler'); t.daemon = true; t } as ThreadFactory)
        exec.scheduleWithFixedDelay({ -> tick() } as Runnable, 2, 24 * 60, TimeUnit.MINUTES)
    }

    void stop() { exec?.shutdownNow() }

    void tick() {
        try {
            Map<String, String> m = store.load()
            if (store.settingsUnreadable) {
                // may also just mean "never configured": retry a few times, then wait for the next daily tick
                if (retries++ < MAX_RETRIES) {
                    log.warn('Scheduled check: the stored settings could not be read; retrying in {} minutes', RETRY_MINUTES)
                    exec?.schedule({ -> tick() } as Runnable, RETRY_MINUTES, TimeUnit.MINUTES)
                } else {
                    log.warn('Scheduled check: the stored settings could not be read; giving up until the next daily check')
                    retries = 0
                }
                return
            }
            retries = 0
            log.info('Scheduled check: autoRenew={} (account {})', m.autoRenew, store.accountId)
            if (m.autoRenew != 'true') {
                return
            }
            if (!lease.tryAcquire()) {
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
