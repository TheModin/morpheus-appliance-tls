package io.github.themodin.morpheus.tls

import io.github.themodin.morpheus.tls.core.RenewalSettings
import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.core.cypher.CypherAccess
import com.morpheusdata.model.Account
import com.morpheusdata.model.User
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.util.logging.Slf4j

/**
 * Settings and last-run summary, kept encrypted in Cypher (available on every Morpheus edition).
 * One JSON document, so the Cloudflare token never lives in plain files or in the plugin settings table.
 */
@Slf4j
class SettingsStore {
    static final String SETTINGS_KEY = 'secret/appliance-tls/settings'
    static final String LASTRUN_KEY = 'secret/appliance-tls/lastrun'
    static final List<String> KEYS = ['domains', 'contactEmail', 'useStaging', 'challengeType',
        'cloudflareApiToken', 'cloudflareZoneId', 'renewBeforeDays', 'autoRenew']
    static final Map<String, String> DEFAULTS = [useStaging: 'true', challengeType: 'dns-01',
        renewBeforeDays: '30', autoRenew: 'false']

    final MorpheusContext morpheus
    volatile Long accountId = 1L
    /** Cypher writes are checked against a user; remembered from the last admin request. */
    volatile User user

    SettingsStore(MorpheusContext morpheus) { this.morpheus = morpheus }

    private CypherAccess access() { new CypherAccess(new Account(id: accountId), null, user) }

    /** Last value read or written per key: served when a later read fails, so a hiccup does not look like "no settings". */
    private final Map<String, Map> lastGood = new java.util.concurrent.ConcurrentHashMap<>()
    private final Set<String> readFailed = java.util.concurrent.ConcurrentHashMap.newKeySet()

    /** Thrown instead of overwriting stored settings that could not be read. */
    static class SettingsUnavailableException extends RuntimeException {
        SettingsUnavailableException(String msg) { super(msg) }
    }

    private Map readJson(String key) {
        try {
            String v = morpheus.cypher.read(access(), key).blockingGet()
            Map m = v ? (Map) new JsonSlurper().parseText(v) : [:]
            lastGood.put(key, m)
            readFailed.remove(key)
            return m
        } catch (Throwable t) {
            readFailed.add(key)
            Map g = lastGood.get(key)
            if (g != null) {
                log.warn('Could not read {} ({}); using the last known copy', key, t.toString())
                return new LinkedHashMap(g)
            }
            log.debug('No readable value for {}: {}', key, t.toString())
            return [:]
        }
    }

    /** True when the settings could not be read and no earlier copy exists (they may exist but be unreadable, or not exist yet). */
    boolean isSettingsUnreadable() { readFailed.contains(SETTINGS_KEY) && !lastGood.containsKey(SETTINGS_KEY) }

    private void writeJson(String key, Map m) {
        morpheus.cypher.write(access(), key, JsonOutput.toJson(m), 0L).blockingGet()
        lastGood.put(key, new LinkedHashMap(m))
        readFailed.remove(key)
    }

    /** Small helpers for the run lease (see RunLease). */
    String readRaw(String key) { morpheus.cypher.read(access(), key).blockingGet() }
    void writeRaw(String key, String value) { morpheus.cypher.write(access(), key, value, 0L).blockingGet() }

    /** Stored values with defaults applied. */
    Map<String, String> load() {
        Map<String, String> m = new LinkedHashMap<>(DEFAULTS)
        readJson(SETTINGS_KEY).each { k, v -> if (v != null && KEYS.contains(k.toString())) m[k.toString()] = v.toString() }
        return m
    }

    /** Merge a posted form into the stored settings. A blank or masked token keeps the stored one. */
    Map<String, String> save(Map posted) {
        Map<String, String> m = load()
        String tok = posted.cloudflareApiToken == null ? '' : posted.cloudflareApiToken.toString().trim()
        boolean tokenPosted = !(tok.isEmpty() || tok ==~ /^\*+$/)
        if (isSettingsUnreadable() && !tokenPosted) {
            // the token is the one value the form does not send back, so saving now could silently erase it
            throw new SettingsUnavailableException('The stored settings could not be read (or none exist yet). ' +
                'Enter the Cloudflare API token again when saving, so a saved token is not overwritten.')
        }
        KEYS.each { k ->
            if (!posted.containsKey(k)) return
            String v = posted[k] == null ? '' : posted[k].toString().trim()
            if (k == 'cloudflareApiToken' && (v.isEmpty() || v ==~ /^\*+$/)) return
            m[k] = v
        }
        writeJson(SETTINGS_KEY, m)
        return m
    }

    /** What the browser may see: everything except the token value. */
    static Map<String, Object> masked(Map<String, String> m) {
        Map<String, Object> out = new LinkedHashMap<>(m)
        out.remove('cloudflareApiToken')
        out.tokenSet = !(m.cloudflareApiToken == null || m.cloudflareApiToken.isEmpty())
        return out
    }

    RenewalSettings toRenewalSettings(Map<String, String> m, boolean checkOnly, boolean force) {
        Map<String, String> o = new LinkedHashMap<>(m)
        o.checkOnly = String.valueOf(checkOnly)
        o.forceRenew = String.valueOf(force)
        return RenewalSettings.fromOptions(o)
    }

    Map lastRun() { readJson(LASTRUN_KEY) }
    void saveLastRun(Map m) {
        try { writeJson(LASTRUN_KEY, m) } catch (Throwable t) { log.warn('Could not store last run: {}', t.toString()) }
    }
}
