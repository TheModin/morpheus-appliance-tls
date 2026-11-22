package io.github.themodin.morpheus.tls

import io.github.themodin.morpheus.tls.core.CertStatus
import io.github.themodin.morpheus.tls.core.CommandRunner
import io.github.themodin.morpheus.tls.core.SetupCheck
import io.github.themodin.morpheus.tls.core.RenewalSettings
import io.github.themodin.morpheus.tls.core.TlsProbe
import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.core.Plugin
import com.morpheusdata.model.Permission
import com.morpheusdata.views.HTMLResponse
import com.morpheusdata.views.HandlebarsRenderer
import com.morpheusdata.views.JsonResponse
import com.morpheusdata.views.Renderer
import com.morpheusdata.views.ViewModel
import com.morpheusdata.web.PluginController
import com.morpheusdata.web.Route
import groovy.json.JsonSlurper
import groovy.util.logging.Slf4j
import java.security.MessageDigest
import java.time.Instant
import java.util.zip.GZIPOutputStream

/** The admin page and its JSON API. All routes need the plugin permission; POSTs also need an XHR header (CSRF). */
@Slf4j
class AdminController implements PluginController {
    Plugin plugin
    MorpheusContext morpheus
    SettingsStore store
    RenewalRunner runner
    private HandlebarsRenderer renderer
    private volatile Map badgeCache
    private volatile long badgeCachedAt = 0L
    static final long BADGE_TTL_MS = 5 * 60 * 1000L

    AdminController(Plugin plugin, MorpheusContext morpheus, SettingsStore store, RenewalRunner runner) {
        this.plugin = plugin; this.morpheus = morpheus; this.store = store; this.runner = runner
    }

    String getCode() { 'tlsAdminController' }
    String getName() { "TLS admin" }
    MorpheusContext getMorpheus() { morpheus }

    List<Route> getRoutes() {
        Permission p = Permission.build('tlsApplianceCert', 'full')
        [Route.build('/tls/admin', 'admin', p),
         Route.build('/tls/api/status', 'status', p),
         Route.build('/tls/api/badge', 'badge', p),
         Route.build('/tls/api/setup', 'setup', p),
         Route.build('/tls/api/settings', 'settings', p),
         Route.build('/tls/api/run', 'run', p)]
    }

    private Renderer<?> getRenderer() {
        if (renderer == null) {
            renderer = new HandlebarsRenderer('renderer', plugin.getClassLoader())
            renderer.registerAssetHelper(plugin.getName())
            renderer.registerNonceHelper(morpheus.getWebRequest())
        }
        return renderer
    }

    def admin(ViewModel<Object> model) {
        remember(model)
        getRenderer().renderTemplate('hbs/admin', model)
    }

    def status(ViewModel<Map> model) {
        remember(model)
        Map<String, String> m = store.load()
        RenewalSettings s = store.toRenewalSettings(m, true, false)
        Map cert = CertStatus.collect(s, Instant.now(), CertStatus.tlsProber())
        JsonResponse.of([cert: cert, settings: SettingsStore.masked(m), running: runner.running,
                         current: runner.running ? runner.current : null, last: runner.lastRun()])
    }

    /**
     * Footer badge data. Shown on every page, so it must be cheap: a cached summary (5 minutes) and a short TLS
     * probe timeout, instead of the full status call.
     */
    def badge(ViewModel<Map> model) {
        remember(model)
        long now = System.currentTimeMillis()
        Map cached = badgeCache
        if (cached == null || now - badgeCachedAt > BADGE_TTL_MS) {
            RenewalSettings s = store.toRenewalSettings(store.load(), true, false)
            Map full = CertStatus.collect(s, Instant.now(), { RenewalSettings x ->
                TlsProbe.fetchLeaf(x.verifyHost, x.verifyPort, x.primaryDomain(), 3000) } as CertStatus.Prober)
            cached = [state: full.state, daysRemaining: full.daysRemaining]
            badgeCache = cached
            badgeCachedAt = now
        }
        JsonResponse.of(cached)
    }

    /**
     * One-time root-side setup: checklist (what the plugin can see as the unprivileged app user) plus a one-line
     * command that carries the whole setup script. The script itself is only included with ?script=1.
     */
    def setup(ViewModel<Map> model) {
        remember(model)
        RenewalSettings s = store.toRenewalSettings(store.load(), true, false)
        List<Map<String, Object>> checks = SetupCheck.run(new CommandRunner.Local(), s.helperPath, s.nginxConfPath,
                s.certPath, s.keyPath)
        boolean ready = SetupCheck.ready(checks)
        Map out = [ready: ready, checks: checks]
        String script = setupScript()
        if (script != null) {
            out.sha256 = MessageDigest.getInstance('SHA-256').digest(script.getBytes('UTF-8')).encodeHex().toString()
            ByteArrayOutputStream bos = new ByteArrayOutputStream()
            GZIPOutputStream gz = new GZIPOutputStream(bos)
            gz.write(script.getBytes('UTF-8')); gz.close()
            String b64 = Base64.encoder.encodeToString(bos.toByteArray())
            out.command = "f=\$(mktemp) && echo '" + b64 + "' | base64 -d | gunzip > \"\$f\" && sudo bash \"\$f\" install; rm -f \"\$f\""
            out.scriptBytes = script.getBytes('UTF-8').length
            String q = model.request?.getParameter('script')
            if (q == '1') out.script = script
        }
        JsonResponse.of(out)
    }

    private String setupScript() {
        try {
            InputStream is = plugin.getClassLoader().getResourceAsStream('setup/morpheus-tls-setup.sh')
            return is == null ? null : new String(is.readAllBytes(), 'UTF-8')
        } catch (Throwable t) {
            log.warn('Could not read the setup script: {}', t.toString())
            return null
        }
    }

    def settings(ViewModel<Map> model) {
        remember(model)
        if (!isPost(model)) return JsonResponse.of(SettingsStore.masked(store.load()))
        if (!xhr(model)) return forbidden()
        Map body = readBody(model)
        Map<String, String> saved = store.save(body)
        badgeCache = null
        try {
            store.toRenewalSettings(saved, true, false).validate()
        } catch (IllegalArgumentException e) {
            return JsonResponse.of([saved: true, warning: e.message, settings: SettingsStore.masked(saved)])
        }
        JsonResponse.of([saved: true, settings: SettingsStore.masked(saved)])
    }

    def run(ViewModel<Map> model) {
        remember(model)
        if (!isPost(model) || !xhr(model)) return forbidden()
        String mode = readBody(model).mode?.toString()
        if (!(mode in ['check', 'renew', 'force'])) {
            return error('mode must be check, renew or force')
        }
        try {
            // fail early, with a readable message, instead of inside the background thread
            store.toRenewalSettings(store.load(), mode == 'check', mode == 'force').validate()
        } catch (IllegalArgumentException e) {
            return error('Invalid settings: ' + e.message)
        }
        if (mode != 'check') {
            RenewalSettings rs = store.toRenewalSettings(store.load(), false, false)
            List<Map<String, Object>> sc = SetupCheck.run(new CommandRunner.Local(), rs.helperPath, rs.nginxConfPath, rs.certPath, rs.keyPath)
            if (!SetupCheck.ready(sc)) {
                return error('Setup is not complete - see the setup checklist at the top of the page')
            }
        }
        badgeCache = null
        boolean started = runner.start(mode, 'manual:' + (model.user?.username ?: '?'))
        JsonResponse.of([started: started, running: runner.running, message: started ? 'Started' : 'A run is already in progress'])
    }

    // ---- helpers -------------------------------------------------------------------------

    private void remember(ViewModel model) {
        Long id = model.user?.account?.id
        if (id != null) store.accountId = id
        if (model.user != null) store.user = model.user
    }

    private static boolean isPost(ViewModel model) { 'POST'.equalsIgnoreCase(model.request?.method?.toString()) }

    /** A cross-site form cannot set custom headers, so this blocks CSRF. */
    private static boolean xhr(ViewModel model) { 'XMLHttpRequest' == model.request?.getHeader('X-Requested-With') }

    /**
     * Morpheus parses the request before the route runs: depending on the content type the payload is in
     * model.object, in the request parameters, or (rarely) still readable from the stream. Try them in order.
     */
    private static Map readBody(ViewModel model) {
        try {
            if (model.object instanceof Map && !((Map) model.object).isEmpty()) {
                return new LinkedHashMap((Map) model.object)
            }
            Map<String, String[]> params = model.request?.parameterMap
            if (params && !params.isEmpty()) {
                return params.collectEntries { k, v -> [k, v.length > 0 ? v[0] : ''] }
            }
            String text = model.request?.reader?.text
            Object parsed = text ? new JsonSlurper().parseText(text) : [:]
            return parsed instanceof Map ? (Map) parsed : [:]
        } catch (Throwable t) {
            log.warn('Could not read request body: {}', t.toString())
            return [:]
        }
    }

    private static JsonResponse forbidden() { error('Forbidden', 403) }

    private static JsonResponse error(String msg, int status = 400) {
        JsonResponse r = JsonResponse.of([error: msg]) as JsonResponse
        r.status = status
        return r
    }
}
