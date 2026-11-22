package io.github.themodin.morpheus.tls.core;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Collections;

/** Fetches the certificate a TLS endpoint actually serves (no trust decisions are made from it). */
public final class TlsProbe {

    private TlsProbe() {
    }

    public static X509Certificate fetchLeaf(String host, int port, String sni, int timeoutMs) throws IOException {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] c, String a) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] c, String a) {
                    // inspection only: we compare fingerprints, we do not trust the result
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }}, null);
            try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
                s.connect(new InetSocketAddress(host, port), timeoutMs);
                s.setSoTimeout(timeoutMs);
                SSLParameters p = s.getSSLParameters();
                if (sni != null && sni.matches("^[A-Za-z0-9.-]+$")) {
                    p.setServerNames(Collections.singletonList(new SNIHostName(sni)));
                }
                s.setSSLParameters(p);
                s.startHandshake();
                return (X509Certificate) s.getSession().getPeerCertificates()[0];
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("TLS probe failed: " + e.getMessage(), e);
        }
    }
}
