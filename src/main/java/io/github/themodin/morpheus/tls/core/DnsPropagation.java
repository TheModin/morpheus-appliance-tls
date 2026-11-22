package io.github.themodin.morpheus.tls.core;

import org.shredzone.acme4j.toolbox.JSON;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.function.Consumer;

/** Polls a public DNS-over-HTTPS (JSON) resolver until the TXT record is visible, so the CA does not race it. */
public class DnsPropagation {

    public static final String DEFAULT_URL = "https://cloudflare-dns.com/dns-query";

    private final String dohUrl;
    private final long pollMillis;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public DnsPropagation(String dohUrl, long pollMillis) {
        this.dohUrl = dohUrl;
        this.pollMillis = pollMillis;
    }

    boolean visible(String fqdn, String value) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(dohUrl + "?type=TXT&name="
                    + URLEncoder.encode(fqdn, StandardCharsets.UTF_8))).timeout(Duration.ofSeconds(10))
                    .header("Accept", "application/dns-json").GET().build();
            HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
            JSON.Array answers = JSON.parse(r.body()).get("Answer").asArray();
            if (answers == null) {
                return false;
            }
            for (JSON.Value v : answers) {
                String data = v.asObject().get("data").asString();
                if (data != null && data.replace("\"", "").equals(value)) {
                    return true;
                }
            }
            return false;
        } catch (IOException | RuntimeException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** True when every given server answers with the value (authoritative servers are not cached). */
    static boolean visibleOnAll(java.util.List<String> servers, int port, String fqdn, String value) {
        for (String srv : servers) {
            try {
                if (!UdpDns.queryTxt(srv, port, fqdn, 3000).contains(value)) {
                    return false;
                }
            } catch (IOException | RuntimeException e) {
                return false;
            }
        }
        return !servers.isEmpty();
    }

    /** Polls the authoritative servers directly. @return true if all of them serve the record in time. */
    public static boolean awaitAuthoritative(java.util.List<String> servers, int port, String fqdn, String value,
                                             int timeoutSeconds, long pollMillis, Consumer<String> log) {
        long end = System.currentTimeMillis() + timeoutSeconds * 1000L;
        while (true) {
            if (visibleOnAll(servers, port, fqdn, value)) {
                log.accept("TXT record served by authoritative servers " + servers + ": " + fqdn);
                return true;
            }
            if (System.currentTimeMillis() >= end) {
                log.accept("WARNING: TXT record not served by " + servers + " after " + timeoutSeconds
                        + "s; validating anyway");
                return false;
            }
            try {
                Thread.sleep(pollMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    /** @return true if the record became visible within the timeout. */
    public boolean await(String fqdn, String value, int timeoutSeconds, Consumer<String> log) {
        long end = System.currentTimeMillis() + timeoutSeconds * 1000L;
        while (true) {
            if (visible(fqdn, value)) {
                log.accept("TXT record visible in public DNS: " + fqdn);
                return true;
            }
            if (System.currentTimeMillis() >= end) {
                log.accept("WARNING: TXT record not visible via " + dohUrl + " after " + timeoutSeconds
                        + "s; validating anyway");
                return false;
            }
            try {
                Thread.sleep(pollMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }
}
