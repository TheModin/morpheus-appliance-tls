package io.github.themodin.morpheus.tls.core;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/** Read-only helpers for looking at PEM certificates. */
public final class CertInspector {

    private CertInspector() {
    }

    /** Parses all certificates from PEM (or DER) bytes. */
    public static List<X509Certificate> parseChain(byte[] pem) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<?> certs = cf.generateCertificates(new ByteArrayInputStream(pem));
        List<X509Certificate> out = new ArrayList<>();
        for (Object o : certs) {
            out.add((X509Certificate) o);
        }
        if (out.isEmpty()) {
            throw new CertificateException("No certificate found in file");
        }
        return out;
    }

    public static Instant notAfter(X509Certificate c) {
        return c.getNotAfter().toInstant();
    }

    public static long daysRemaining(X509Certificate c, Instant now) {
        return Duration.between(now, notAfter(c)).toDays();
    }

    /** Lower-case DNS SANs. */
    public static List<String> dnsNames(X509Certificate c) {
        List<String> names = new ArrayList<>();
        try {
            Collection<List<?>> sans = c.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    if (((Integer) san.get(0)) == 2) {
                        names.add(((String) san.get(1)).toLowerCase(Locale.ROOT));
                    }
                }
            }
        } catch (CertificateException ignored) {
            // treated as no SANs
        }
        return names;
    }

    /** True if every wanted domain is matched by a SAN (exact, or single-label wildcard). */
    public static boolean covers(X509Certificate c, List<String> wanted) {
        List<String> names = dnsNames(c);
        for (String w : wanted) {
            boolean hit = false;
            for (String n : names) {
                if (n.equals(w) || (n.startsWith("*.") && w.indexOf('.') > 0
                        && w.substring(w.indexOf('.')).equals(n.substring(1)))) {
                    hit = true;
                    break;
                }
            }
            if (!hit) {
                return false;
            }
        }
        return true;
    }

    public static boolean isSelfSigned(X509Certificate c) {
        return c.getSubjectX500Principal().equals(c.getIssuerX500Principal());
    }

    public static String sha256(X509Certificate c) throws CertificateException {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(c.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : d) {
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new CertificateException(e);
        }
    }

    public static String describe(X509Certificate c) {
        return "subject=" + c.getSubjectX500Principal().getName()
                + ", issuer=" + c.getIssuerX500Principal().getName()
                + ", notAfter=" + notAfter(c)
                + ", SANs=" + dnsNames(c);
    }
}
