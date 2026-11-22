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
    static final List<String> KEYS = ['domains', 'contactEmail', 'useStaging', 'challengeType', 'dnsProvider',
        'cloudflareApiToken', 'cloudflareZoneId', 'dnsHookScript', 'renewBeforeDays', 'autoRenew']
    static final Map<String, String> DEFAULTS = [useStaging: 'true', challengeType: 'dns-01', dnsProvider: 'cloudflare',
        renewBeforeDays: '30', autoRenew: 'false']

    final MorpheusContext morpheus
    volatile Long accountId = 1L
    /** Cypher writes are checked against a user; remembered from the last admin request. */
    volatile User user

    SettingsStore(MorpheusContext morpheus) { this.morpheus = morpheus }

    private CypherAccess access() { new CypherAccess(new Account(id: accountId), null, user) }

    private Map readJson(String key) {
        try {
            String v = morpheus.cypher.read(access(), key).blockingGet()
            return v ? (Map) new JsonSlurper().parseText(v) : [:]
        } catch (Throwable t) {
            log.debug('No value for {}: {}', key, t.toString())
            return [:]
        }
    }

    private void writeJson(String key, Map m) {
        morpheus.cypher.write(access(), key, JsonOutput.toJson(m), 0L).blockingGet()
    }

    /** Stored values with defaults applied. */
    Map<String, String> load() {
        Map<String, String> m = new LinkedHashMap<>(DEFAULTS)
        readJson(SETTINGS_KEY).each { k, v -> if (v != null && KEYS.contains(k.toString())) m[k.toString()] = v.toString() }
        return m
    }

    /** Merge a posted form into the stored settings. A blank or masked token keeps the stored one. */
    Map<String, String> save(Map posted) {
        Map<String, String> m = load()
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
