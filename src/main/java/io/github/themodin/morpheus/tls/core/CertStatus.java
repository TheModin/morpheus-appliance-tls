package io.github.themodin.morpheus.tls.core;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** Builds the data shown by the status report: what nginx serves right now plus the effective configuration. */
public final class CertStatus {

    private CertStatus() {
    }

    public interface Prober {
        X509Certificate fetch(RenewalSettings s) throws Exception;
    }

    /** Health of the served certificate. */
    public static String classify(X509Certificate c, RenewalSettings s, Instant now) {
        if (CertInspector.isSelfSigned(c)) {
            return "SELF_SIGNED";
        }
        if (c.getIssuerX500Principal().getName().toUpperCase().contains("(STAGING)")) {
            return "STAGING";
        }
        long days = CertInspector.daysRemaining(c, now);
        if (days < 0) {
            return "EXPIRED";
        }
        if (!CertInspector.covers(c, s.domains)) {
            return "DOES_NOT_COVER_DOMAINS";
        }
        return days <= s.renewBeforeDays ? "RENEWAL_DUE" : "OK";
    }

    /** Never contains secret values (only whether a token is set). */
    public static Map<String, Object> collect(RenewalSettings s, Instant now, Prober prober) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("domains", String.join(", ", s.domains));
        m.put("environment", s.useStaging ? "Let's Encrypt STAGING" : "Let's Encrypt production");
        m.put("challenge", s.challengeType + ("dns-01".equals(s.challengeType) ? " (" + s.dnsProvider + ")" : ""));
        m.put("tokenConfigured", s.cloudflareApiToken != null ? "yes" : "no");
        m.put("renewBeforeDays", s.renewBeforeDays);
        m.put("checkedAt", now.toString());
        try {
            X509Certificate c = prober.fetch(s);
            m.put("state", classify(c, s, now));
            m.put("subject", c.getSubjectX500Principal().getName());
            m.put("issuer", c.getIssuerX500Principal().getName());
            m.put("notAfter", CertInspector.notAfter(c).toString());
            m.put("daysRemaining", CertInspector.daysRemaining(c, now));
            m.put("sans", String.join(", ", CertInspector.dnsNames(c)));
            m.put("fingerprint", CertInspector.sha256(c));
        } catch (Exception e) {
            m.put("state", "UNREACHABLE");
            m.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return m;
    }

    public static Prober tlsProber() {
        return s -> TlsProbe.fetchLeaf(s.verifyHost, s.verifyPort, s.primaryDomain(), 10_000);
    }
}
