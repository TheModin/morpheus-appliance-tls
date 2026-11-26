package io.github.themodin.morpheus.tls.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

/** Orchestrates: inspect current cert -> decide -> issue -> install -> reload -> verify (with rollback). */
public class RenewalService {

    /** Creates the challenge responder for a run; replaceable in tests. */
    public interface ResponderFactory {
        ChallengeResponder create(RenewalSettings s, HostFiles files) throws IOException;
    }

    /** Issues the certificate; replaceable in tests so the file/reload logic can run without a CA. */
    public interface Issuer {
        AcmeIssuer.Issued issue(RenewalSettings s, ChallengeResponder r) throws Exception;
    }

    /** Fetches the cert served by nginx after reload. */
    public interface Prober {
        X509Certificate fetch(RenewalSettings s) throws IOException;
    }

    private final CommandRunner runner;
    private final Supplier<Instant> clock;
    private ResponderFactory responderFactory; // null = build from settings (see defaultResponder)
    private Prober prober = s -> TlsProbe.fetchLeaf(s.verifyHost, s.verifyPort, s.primaryDomain(), 10_000);
    private Issuer issuerOverride;

    public RenewalService(CommandRunner runner, Supplier<Instant> clock) {
        this.runner = runner;
        this.clock = clock;
    }

    static DnsProvider dnsProviderFor(RenewalSettings s) {
        return new CloudflareDnsProvider(s.cloudflareApiToken, s.cloudflareZoneId, s.cloudflareApiBase);
    }

    /** Check-only runs also prove the DNS credentials work, without creating any record. */
    private void checkDnsAccess(RenewalSettings s, RenewalResult res) {
        if (s.cloudflareApiToken == null) {
            res.log("DNS provider check: no Cloudflare API token configured");
            return;
        }
        try {
            String name = "_acme-challenge." + s.primaryDomain().replaceFirst("^\\*\\.", "");
            java.util.List<String> ns = dnsProviderFor(s).authoritativeServers(name);
            res.log(ns.isEmpty() ? "DNS provider check: Cloudflare configured (no zone lookup available)"
                    : "DNS provider check OK: zone found, authoritative servers " + ns);
        } catch (Exception e) {
            res.log("DNS provider check FAILED: " + e.getMessage());
        }
    }

    static ChallengeResponder defaultResponder(RenewalSettings s, HostFiles files, java.util.function.Consumer<String> log)
            throws IOException {
        if (s.isDns01()) {
            DnsProvider provider = dnsProviderFor(s);
            DnsPropagation prop = s.dnsCheckUrl == null ? null : new DnsPropagation(s.dnsCheckUrl, 5000);
            return new DnsResponder(provider, prop, s.dnsPropagationTimeoutSeconds, log);
        }
        return s.webrootPath != null ? new WebrootResponder(s.webrootPath, files) : new StandaloneResponder(s.httpPort);
    }

    public RenewalService withResponderFactory(ResponderFactory f) {
        this.responderFactory = f;
        return this;
    }

    public RenewalService withProber(Prober p) {
        this.prober = p;
        return this;
    }

    public RenewalService withIssuer(Issuer i) {
        this.issuerOverride = i;
        return this;
    }

    public RenewalResult run(RenewalSettings s) {
        RenewalResult res = new RenewalResult();
        try {
            s.validate();
            doRun(s, res);
        } catch (IllegalArgumentException e) {
            res.status = RenewalResult.Status.FAILED;
            res.message = "Invalid settings: " + e.getMessage();
            res.log(res.message);
        } catch (Exception e) {
            res.status = RenewalResult.Status.FAILED;
            res.message = describe(e);
            res.log("ERROR " + res.message);
        }
        return res;
    }

    /**
     * The configured threshold, capped at one third of the certificate's lifetime. Let's Encrypt is moving to
     * shorter certificates (45 days; short-lived profiles are 6 days), where a fixed 30 day threshold would
     * renew far too early or on every run.
     */
    static long effectiveThresholdDays(X509Certificate c, int configured) {
        long lifetimeDays = java.time.Duration.between(c.getNotBefore().toInstant(), c.getNotAfter().toInstant())
                .toDays();
        return Math.max(1, Math.min(configured, lifetimeDays / 3));
    }

    /** Exception message including the cause chain (acme4j hides the useful part in the cause). */
    static String describe(Throwable e) {
        StringBuilder sb = new StringBuilder();
        Throwable t = e;
        int depth = 0;
        while (t != null && depth++ < 5) {
            if (sb.length() > 0) {
                sb.append(" <- ");
            }
            sb.append(t.getClass().getSimpleName());
            if (t.getMessage() != null) {
                sb.append(": ").append(t.getMessage());
            }
            t = t.getCause() == t ? null : t.getCause();
        }
        return sb.toString();
    }

    private void doRun(RenewalSettings s, RenewalResult res) throws Exception {
        HostFiles files = new HostFiles(s.useSudo, runner, s.helperPath);
        Instant now = clock.get();

        // 1. look at what is installed now
        X509Certificate current = null;
        byte[] currentPem = files.read(s.certPath);
        if (currentPem == null) {
            res.log("No certificate at " + s.certPath);
        } else {
            current = CertInspector.parseChain(currentPem).get(0);
            res.log("Installed certificate: " + CertInspector.describe(current));
            res.notAfterBefore = CertInspector.notAfter(current);
            res.log("Days remaining: " + CertInspector.daysRemaining(current, now));
        }

        if (s.checkOnly && s.isDns01()) {
            checkDnsAccess(s, res);
        }
        if (s.checkOnly) {
            String warn = nginxPathProblem(s);
            if (warn != null) {
                res.log("WARNING: " + warn);
            }
        }

        // 2. decide
        String reason = null;
        if (s.forceRenew) {
            reason = "renewal forced";
        } else if (current == null) {
            reason = "no certificate installed";
        } else if (CertInspector.isSelfSigned(current)) {
            reason = "installed certificate is self-signed";
        } else if (!CertInspector.covers(current, s.domains)) {
            reason = "installed certificate does not cover " + s.domains;
        } else if (CertInspector.daysRemaining(current, now) < effectiveThresholdDays(current, s.renewBeforeDays)) {
            reason = "expires in " + CertInspector.daysRemaining(current, now) + " days (threshold "
                    + effectiveThresholdDays(current, s.renewBeforeDays) + ")";
        }
        if (reason == null) {
            res.status = RenewalResult.Status.UP_TO_DATE;
            res.message = "Certificate is valid for " + CertInspector.daysRemaining(current, now)
                    + " more days; no renewal needed";
            res.log(res.message);
            return;
        }
        res.log("Renewal needed: " + reason);
        if (s.checkOnly) {
            res.status = RenewalResult.Status.RENEWAL_DUE;
            res.message = "Renewal due (" + reason + "); check-only run, nothing changed";
            res.log(res.message);
            return;
        }

        // 3. issue (after making sure nginx will actually read the files we install: do not waste CA rate limits)
        String problem = nginxPathProblem(s);
        if (problem != null) {
            throw new IllegalStateException(problem);
        }
        AcmeIssuer.Issued issued;
        try (ChallengeResponder responder = responderFactory != null ? responderFactory.create(s, files)
                : defaultResponder(s, files, res::log)) {
            issued = issuerOverride != null
                    ? issuerOverride.issue(s, responder)
                    : new AcmeIssuer(files, res::log).issue(s, responder);
        }
        X509Certificate fresh = CertInspector.parseChain(issued.fullChainPem.getBytes(StandardCharsets.US_ASCII)).get(0);
        res.notAfterAfter = CertInspector.notAfter(fresh);
        res.log("Issued: " + CertInspector.describe(fresh));

        // 4. back up and install
        String stamp = DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(ZoneOffset.UTC).format(now);
        String bakDir = s.backupDir + "/" + stamp;
        String certBak = backup(files, s.certPath, bakDir, res);
        String keyBak = backup(files, s.keyPath, bakDir, res);

        try {
            files.write(s.keyPath, issued.privateKeyPem.getBytes(StandardCharsets.US_ASCII), "0600");
            files.write(s.certPath, issued.fullChainPem.getBytes(StandardCharsets.US_ASCII), "0644");
            res.log("Installed new certificate and key");
            // nginx re-reads the files on restart; no reconfigure is needed because the paths do not change
            runShell(s.restartCommand, res, 300);
        } catch (Exception e) {
            res.log("Install/reload failed: " + e.getMessage() + " - rolling back");
            rollback(files, s, certBak, keyBak, res);
            throw e;
        }

        // 5. verify nginx really serves the new certificate
        if (s.verifyAfterInstall) {
            String want = CertInspector.sha256(fresh);
            Served served = waitForServed(s, want, res);
            if (served == Served.NO_ANSWER) {
                // nothing answers on the HTTPS port: do not leave the appliance without a working web server
                res.log("nginx is not answering after the restart - rolling back");
                rollback(files, s, certBak, keyBak, res);
                res.status = RenewalResult.Status.FAILED;
                res.message = "New certificate installed, but nginx did not answer afterwards (waited "
                        + s.verifyTimeoutSeconds + "s). The previous certificate was restored. Backups: "
                        + certBak + ", " + keyBak;
                res.log(res.message);
                return;
            }
            if (served == Served.OTHER_CERT) {
                res.status = RenewalResult.Status.FAILED;
                res.message = "New certificate installed and nginx restarted, but nginx is not serving it "
                        + "(waited " + s.verifyTimeoutSeconds + "s). Backups: " + certBak + ", " + keyBak;
                res.log(res.message);
                return;
            }
            res.log("Verified: " + s.verifyHost + ":" + s.verifyPort + " serves the new certificate");
        }
        try {
            files.pruneBackups(s.backupDir, s.keepBackups);
        } catch (Exception e) {
            res.log("Could not prune old backups: " + e.getMessage());
        }
        res.status = RenewalResult.Status.RENEWED;
        res.message = "Certificate renewed; valid until " + res.notAfterAfter;
        res.log(res.message);
    }

    /** What the HTTPS port returned while waiting for the new certificate. */
    enum Served { NEW_CERT, OTHER_CERT, NO_ANSWER }

    private Served waitForServed(RenewalSettings s, String wantFingerprint, RenewalResult res) {
        long deadline = System.currentTimeMillis() + s.verifyTimeoutSeconds * 1000L;
        String last = "no connection yet";
        boolean answered = false;
        while (true) {
            try {
                X509Certificate served = prober.fetch(s);
                answered = true;
                String got = CertInspector.sha256(served);
                if (got.equals(wantFingerprint)) {
                    return Served.NEW_CERT;
                }
                last = "serving fingerprint " + got;
            } catch (Exception e) {
                last = e.getMessage();
            }
            if (System.currentTimeMillis() >= deadline) {
                res.log("Last probe result: " + last);
                return answered ? Served.OTHER_CERT : Served.NO_ANSWER;
            }
            try {
                Thread.sleep(3000);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return answered ? Served.OTHER_CERT : Served.NO_ANSWER;
            }
        }
    }

    private String backup(HostFiles files, String path, String dir, RenewalResult res) throws IOException {
        if (!files.exists(path)) {
            return null;
        }
        String dst = dir + "/" + path.substring(path.lastIndexOf('/') + 1);
        files.copy(path, dst);
        res.log("Backed up " + path + " -> " + dst);
        return dst;
    }

    private void rollback(HostFiles files, RenewalSettings s, String certBak, String keyBak, RenewalResult res) {
        try {
            // restore the previous state exactly: copy backups back, or remove files that did not exist before
            if (certBak != null) {
                files.copy(certBak, s.certPath);
            } else {
                files.delete(s.certPath);
            }
            if (keyBak != null) {
                files.copy(keyBak, s.keyPath);
            } else {
                files.delete(s.keyPath);
            }
            res.log("Restored previous files");
            runShell(s.restartCommand, res, 300);
            res.log("Reloaded with previous certificate");
        } catch (Exception e) {
            res.log("ROLLBACK FAILED: " + e.getMessage() + " - restore the files from " + s.backupDir + " manually");
        }
    }

    /**
     * nginx is configured by Morpheus (Chef renders it from morpheus.rb). Writing new files only helps if nginx is
     * already pointed at them, so compare the rendered config with the configured paths before issuing anything.
     * @return a human readable problem, or null when fine / not verifiable
     */
    String nginxPathProblem(RenewalSettings s) {
        if (s.nginxConfPath == null) {
            return null;
        }
        String conf;
        try {
            conf = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(s.nginxConfPath)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null; // cannot verify (other layout / no read access): do not block
        }
        String cert = firstDirective(conf, "ssl_certificate");
        String key = firstDirective(conf, "ssl_certificate_key");
        if (cert == null || key == null || (cert.equals(s.certPath) && key.equals(s.keyPath))) {
            return null;
        }
        return "nginx is configured to use " + cert + " and " + key + ", not " + s.certPath + " and " + s.keyPath
                + ". One-time setup: add nginx['ssl_certificate'] = '" + s.certPath + "' and nginx['ssl_server_key'] = '"
                + s.keyPath + "' to /etc/morpheus/morpheus.rb and run 'sudo morpheus-ctl reconfigure' (or change the paths "
                + "in this plugin to the ones nginx uses).";
    }

    private static String firstDirective(String conf, String name) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?m)^\\s*" + name + "\\s+([^;\\s]+)\\s*;").matcher(conf);
        return m.find() ? m.group(1) : null;
    }

    private void runShell(String command, RenewalResult res, int timeoutSeconds) throws IOException {
        if (command == null || command.trim().isEmpty()) {
            return;
        }
        res.log("$ " + command);
        List<String> argv = Arrays.asList("/bin/sh", "-c", command);
        CommandRunner.Result r = runner.run(argv, null, timeoutSeconds);
        if (!r.output.isEmpty()) {
            res.log(r.output.length() > 2000 ? r.output.substring(r.output.length() - 2000) : r.output);
        }
        if (!r.ok()) {
            throw new IOException("Command failed with exit code " + r.exitCode + ": " + command);
        }
    }
}
