package io.github.themodin.morpheus.tls.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * All user-configurable settings for one renewal run. Built from the Task option values.
 */
public class RenewalSettings {

    public static final String LE_PRODUCTION = "acme://letsencrypt.org";
    public static final String LE_STAGING = "acme://letsencrypt.org/staging";

    public List<String> domains = new ArrayList<>();
    public String contactEmail;
    public boolean useStaging = true;
    /** Optional full ACME directory URI; overrides useStaging when set (e.g. acme://pebble for tests). */
    public String acmeDirectoryOverride;
    public int renewBeforeDays = 30;
    public boolean forceRenew = false;
    public boolean checkOnly = false;

    /** "dns-01" (default, needs no inbound ports, allows wildcards) or "http-01". */
    public String challengeType = "dns-01";
    /** "cloudflare" or "hook". */
    public String dnsProvider = "cloudflare";
    public String cloudflareApiToken;
    /** Optional; auto-detected from the domain when empty. */
    public String cloudflareZoneId;
    public String cloudflareApiBase = CloudflareDnsProvider.DEFAULT_API;
    /** Script called as: script add|remove <fqdn> <value>. */
    public String dnsHookScript;
    /** Public DoH JSON endpoint used to see the TXT record before validation; null disables the check. */
    public String dnsCheckUrl = DnsPropagation.DEFAULT_URL;
    public int dnsPropagationTimeoutSeconds = 120;

    /** If set, HTTP-01 challenge files are written here (webroot mode). Otherwise standalone mode is used. */
    public String webrootPath;
    /** Port the standalone challenge responder binds to. */
    public int httpPort = 80;

    public String certPath = "/etc/morpheus/ssl/cert.pem";
    public String keyPath = "/etc/morpheus/ssl/key.pem";
    public String accountKeyPath = "/etc/morpheus/ssl/acme-account.pem";

    /** Per the Morpheus SSL docs these are nginx['ssl_certificate'] and nginx['ssl_server_key']. */

    /** Previous cert/key pairs are copied to backupDir/<timestamp>/ before each install; only the newest keepBackups stay. */
    public String backupDir = "/etc/morpheus/ssl/backup";
    public int keepBackups = 5;
    /** Rendered nginx site config, read (without sudo) to confirm nginx uses certPath/keyPath; "none" disables the check. */
    public String nginxConfPath = "/opt/morpheus/embedded/nginx/conf/sites-available/morpheus-ssl.conf";
    public boolean useSudo = true;
    /** Root-owned helper script used with sudo (see deploy/morpheus-tls-helper). */
    public String helperPath = HostFiles.DEFAULT_HELPER;
    /** Run when morpheus.rb was changed (or alwaysReconfigure is set). May restart more than nginx. */
    /** Always run after the new files are installed so nginx picks up the new certificate. */
    public String restartCommand = "sudo -n /opt/morpheus/bin/morpheus-ctl restart nginx";

    public boolean verifyAfterInstall = true;
    public String verifyHost = "localhost";
    public int verifyPort = 443;
    public int verifyTimeoutSeconds = 180;

    public boolean isDns01() {
        return "dns-01".equals(challengeType);
    }

    public String primaryDomain() {
        return domains.isEmpty() ? null : domains.get(0);
    }

    /** Throws IllegalArgumentException with a user-facing message if settings are unusable. */
    public void validate() {
        if (domains.isEmpty()) {
            throw new IllegalArgumentException("At least one domain is required");
        }
        for (String d : domains) {
            if (d.startsWith("*.") && !isDns01()) {
                throw new IllegalArgumentException("Wildcard domains need the dns-01 challenge: " + d);
            }
            if (!d.replaceFirst("^\\*\\.", "").matches("^[A-Za-z0-9]([A-Za-z0-9\\-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9\\-]*[A-Za-z0-9])?)+$")) {
                throw new IllegalArgumentException("Not a valid fully-qualified domain name: " + d);
            }
        }
        if (!checkOnly && (contactEmail == null || !contactEmail.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$"))) {
            throw new IllegalArgumentException("A valid contact e-mail address is required");
        }
        if (!isDns01() && !"http-01".equals(challengeType)) {
            throw new IllegalArgumentException("Challenge type must be dns-01 or http-01, got: " + challengeType);
        }
        if (isDns01() && !checkOnly) {
            if ("cloudflare".equals(dnsProvider)) {
                if (cloudflareApiToken == null) {
                    throw new IllegalArgumentException("A Cloudflare API token is required for dns-01");
                }
                if (cloudflareZoneId != null && !cloudflareZoneId.matches("^[0-9a-f]{32}$")) {
                    throw new IllegalArgumentException("Cloudflare zone id must be 32 hex characters");
                }
            } else if ("hook".equals(dnsProvider)) {
                if (dnsHookScript == null || !dnsHookScript.startsWith("/") || dnsHookScript.contains("..")) {
                    throw new IllegalArgumentException("DNS hook script must be an absolute path");
                }
            } else {
                throw new IllegalArgumentException("DNS provider must be cloudflare or hook, got: " + dnsProvider);
            }
        }
        if (renewBeforeDays < 1 || renewBeforeDays > 89) {
            throw new IllegalArgumentException("Renew-before days must be between 1 and 89");
        }
        if (httpPort < 1 || httpPort > 65535) {
            throw new IllegalArgumentException("HTTP port out of range");
        }
        for (String p : Arrays.asList(certPath, keyPath, accountKeyPath, backupDir, helperPath)) {
            if (p == null || !p.startsWith("/") || p.contains("..") || p.contains("'") || p.contains("\n")) {
                throw new IllegalArgumentException("Paths must be absolute and must not contain '..' or quotes: " + p);
            }
        }
        if (webrootPath != null && (!webrootPath.startsWith("/") || webrootPath.contains(".."))) {
            throw new IllegalArgumentException("Webroot path must be absolute and must not contain '..'");
        }
    }

    // ---- parsing helpers -------------------------------------------------------------------

    /** Builds settings from raw string option values (null / blank values keep the defaults). */
    public static RenewalSettings fromOptions(Map<String, String> o) {
        RenewalSettings s = new RenewalSettings();
        String domains = str(o, "domains");
        if (domains != null) {
            for (String d : domains.split("[,;\\s]+")) {
                if (!d.trim().isEmpty()) {
                    s.domains.add(d.trim().toLowerCase());
                }
            }
        }
        s.contactEmail = str(o, "contactEmail");
        s.useStaging = bool(o, "useStaging", s.useStaging);
        s.acmeDirectoryOverride = str(o, "acmeDirectoryOverride");
        s.renewBeforeDays = integer(o, "renewBeforeDays", s.renewBeforeDays);
        s.forceRenew = bool(o, "forceRenew", s.forceRenew);
        s.checkOnly = bool(o, "checkOnly", s.checkOnly);
        s.challengeType = orDefault(str(o, "challengeType"), s.challengeType).toLowerCase();
        s.dnsProvider = orDefault(str(o, "dnsProvider"), s.dnsProvider).toLowerCase();
        s.cloudflareApiToken = str(o, "cloudflareApiToken");
        s.cloudflareZoneId = str(o, "cloudflareZoneId");
        s.cloudflareApiBase = orDefault(str(o, "cloudflareApiBase"), s.cloudflareApiBase);
        s.dnsHookScript = str(o, "dnsHookScript");
        String check = orDefault(str(o, "dnsCheckUrl"), s.dnsCheckUrl);
        s.dnsCheckUrl = "none".equalsIgnoreCase(check) ? null : check;
        s.dnsPropagationTimeoutSeconds = integer(o, "dnsPropagationTimeoutSeconds", s.dnsPropagationTimeoutSeconds);
        s.webrootPath = str(o, "webrootPath");
        s.httpPort = integer(o, "httpPort", s.httpPort);
        s.certPath = orDefault(str(o, "certPath"), s.certPath);
        s.keyPath = orDefault(str(o, "keyPath"), s.keyPath);
        s.accountKeyPath = orDefault(str(o, "accountKeyPath"), s.accountKeyPath);
        s.backupDir = orDefault(str(o, "backupDir"), s.backupDir);
        s.keepBackups = Math.max(1, Math.min(50, integer(o, "keepBackups", s.keepBackups)));
        String conf = orDefault(str(o, "nginxConfPath"), s.nginxConfPath);
        s.nginxConfPath = "none".equalsIgnoreCase(conf) ? null : conf;
        s.useSudo = bool(o, "useSudo", s.useSudo);
        s.helperPath = orDefault(str(o, "helperPath"), s.helperPath);
        s.restartCommand = orDefault(str(o, "restartCommand"), s.restartCommand);
        s.verifyAfterInstall = bool(o, "verifyAfterInstall", s.verifyAfterInstall);
        s.verifyHost = orDefault(str(o, "verifyHost"), s.verifyHost);
        s.verifyPort = integer(o, "verifyPort", s.verifyPort);
        s.verifyTimeoutSeconds = integer(o, "verifyTimeoutSeconds", s.verifyTimeoutSeconds);
        return s;
    }

    public String acmeDirectory() {
        if (acmeDirectoryOverride != null) {
            return acmeDirectoryOverride;
        }
        return useStaging ? LE_STAGING : LE_PRODUCTION;
    }

    private static String str(Map<String, String> o, String k) {
        String v = o == null ? null : o.get(k);
        return (v == null || v.trim().isEmpty()) ? null : v.trim();
    }

    private static String orDefault(String v, String d) {
        return v == null ? d : v;
    }

    private static boolean bool(Map<String, String> o, String k, boolean d) {
        String v = str(o, k);
        if (v == null) {
            return d;
        }
        return v.equalsIgnoreCase("true") || v.equals("on") || v.equals("1") || v.equalsIgnoreCase("yes");
    }

    private static int integer(Map<String, String> o, String k, int d) {
        String v = str(o, k);
        if (v == null) {
            return d;
        }
        try {
            return (int) Double.parseDouble(v);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Option '" + k + "' must be a number, got: " + v);
        }
    }

    public List<String> domainsView() {
        return Collections.unmodifiableList(domains);
    }
}
