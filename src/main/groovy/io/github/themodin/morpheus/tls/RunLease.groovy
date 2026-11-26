package io.github.themodin.morpheus.tls

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.util.logging.Slf4j

/**
 * A short lease kept in Cypher so that, on a clustered Morpheus (several app nodes with this plugin), only one node
 * runs the scheduled renewal at a time. Cypher has no compare-and-set, so a node writes its claim and reads it back;
 * the loser backs off. It is best effort, which is enough for a once-a-day job.
 */
@Slf4j
class RunLease {
    static final String KEY = 'secret/appliance-tls/lease'
    final SettingsStore store
    final String owner
    final long ttlMs

    RunLease(SettingsStore store, long ttlMs = 30 * 60 * 1000L) {
        this.store = store
        this.ttlMs = ttlMs
        String host = 'node'
        try { host = InetAddress.localHost.hostName } catch (Throwable ignored) { }
        this.owner = host + '-' + UUID.randomUUID().toString().substring(0, 8)
    }

    /** @return true when this node holds the lease and may run. */
    boolean tryAcquire(long now = System.currentTimeMillis()) {
        try {
            String raw = null
            try { raw = store.readRaw(KEY) } catch (Throwable ignored) { /* no lease stored yet */ }
            Map cur = raw ? (Map) new JsonSlurper().parseText(raw) : [:]
            if (cur.owner && cur.owner != owner && ((cur.until ?: 0) as long) > now) {
                log.info('Scheduled renewal skipped: {} holds the lease for another {} s', cur.owner, (((cur.until as long) - now) / 1000) as long)
                return false
            }
            store.writeRaw(KEY, JsonOutput.toJson([owner: owner, until: now + ttlMs]))
            Map back = (Map) new JsonSlurper().parseText(store.readRaw(KEY))
            return back.owner == owner
        } catch (Throwable t) {
            log.warn('Could not take the run lease ({}); skipping this scheduled run', t.toString())
            return false
        }
    }
}
