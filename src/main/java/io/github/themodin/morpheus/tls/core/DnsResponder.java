package io.github.themodin.morpheus.tls.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/** Answers DNS-01 by creating _acme-challenge TXT records through a DnsProvider. */
public class DnsResponder implements ChallengeResponder {

    private static final class Rec {
        final String fqdn, value, handle;

        Rec(String fqdn, String value, String handle) {
            this.fqdn = fqdn;
            this.value = value;
            this.handle = handle;
        }
    }

    private final DnsProvider provider;
    private final DnsPropagation propagation; // may be null = just wait settleSeconds
    private final int timeoutSeconds;
    private final Consumer<String> log;
    private final Map<String, Rec> records = new ConcurrentHashMap<>();

    public DnsResponder(DnsProvider provider, DnsPropagation propagation, int timeoutSeconds, Consumer<String> log) {
        this.provider = provider;
        this.propagation = propagation;
        this.timeoutSeconds = timeoutSeconds;
        this.log = log;
    }

    @Override
    public String challengeType() {
        return "dns-01";
    }

    static String txtValue(String keyAuthorization) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(keyAuthorization.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(d);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void publish(String domain, String token, String keyAuthorization) throws IOException {
        ChallengeResponder.checkToken(token);
        String fqdn = "_acme-challenge." + domain.replaceFirst("^\\*\\.", "");
        String value = txtValue(keyAuthorization);
        String handle = provider.addTxt(fqdn, value);
        records.put(domain + "|" + token, new Rec(fqdn, value, handle));
        log.accept("Created TXT " + fqdn);
        java.util.List<String> auth = java.util.Collections.emptyList();
        try {
            auth = provider.authoritativeServers(fqdn);
        } catch (IOException e) {
            log.accept("Could not look up authoritative servers (" + e.getMessage() + ")");
        }
        if (!auth.isEmpty()) {
            DnsPropagation.awaitAuthoritative(auth, 53, fqdn, value, timeoutSeconds, 3000, log);
        } else if (propagation != null) {
            propagation.await(fqdn, value, timeoutSeconds, log);
        }
    }

    @Override
    public void cleanup(String domain, String token) {
        Rec r = records.remove(domain + "|" + token);
        if (r == null) {
            return;
        }
        try {
            provider.removeTxt(r.fqdn, r.value, r.handle);
            log.accept("Removed TXT " + r.fqdn);
        } catch (IOException e) {
            log.accept("WARNING: could not remove TXT " + r.fqdn + ": " + e.getMessage());
        }
    }

    @Override
    public void publish(String token, String keyAuthorization) {
        throw new UnsupportedOperationException("DNS-01 needs the domain");
    }

    @Override
    public void cleanup(String token) {
        // handled by cleanup(domain, token)
    }

    @Override
    public void close() {
        // leftover records (failed before cleanup) are removed here
        for (String k : records.keySet()) {
            String[] p = k.split("\\|", 2);
            cleanup(p[0], p[1]);
        }
    }
}
