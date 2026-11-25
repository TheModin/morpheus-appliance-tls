package io.github.themodin.morpheus.tls

import com.morpheusdata.core.Plugin
import com.morpheusdata.model.Permission
import com.morpheusdata.views.HandlebarsRenderer

/**
 * Admin page (/plugin/tls/admin), JSON endpoints and a daily in-plugin check that issue and renew the
 * Morpheus appliance's own TLS certificate with Let's Encrypt. Uses only features present on every edition
 * (controller routes, global UI component, Cypher) - no Tasks, Jobs or Reports.
 */
class TlsAppliancePlugin extends Plugin {
    CertScheduler scheduler

    @Override
    String getCode() { 'morpheus-appliance-tls' }

    @Override
    void initialize() {
        this.setName("TLS Appliance Certificate")
        this.setDescription("Issues and renews the Morpheus appliance TLS certificate with Let's Encrypt (DNS-01 / HTTP-01). Admin page at /plugin/tls/admin.")
        this.setAuthor('Martin Modin')
        this.setRenderer(new HandlebarsRenderer(this.classLoader))
        SettingsStore store = new SettingsStore(morpheus)
        RenewalRunner runner = new RenewalRunner(store)
        BadgeProvider badge = new BadgeProvider(this, morpheus)
        this.pluginProviders.put(badge.code, badge)
        this.controllers.add(new AdminController(this, morpheus, store, runner))
        scheduler = new CertScheduler(store, runner)
        scheduler.start()
    }

    @Override
    void onDestroy() { scheduler?.stop() }

    @Override
    List<Permission> getPermissions() {
        [new Permission("TLS Appliance Certificate", 'tlsApplianceCert', [Permission.AccessType.full]),
         new Permission("TLS Appliance Setup (run the root-side setup through Morpheus)", 'tlsApplianceSetup', [Permission.AccessType.full])]
    }
}
