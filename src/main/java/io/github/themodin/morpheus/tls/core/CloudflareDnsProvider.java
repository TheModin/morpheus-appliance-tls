package io.github.themodin.morpheus.tls.core;

import org.shredzone.acme4j.toolbox.JSON;
import org.shredzone.acme4j.toolbox.JSONBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/** DNS-01 records through the Cloudflare v4 API. The token only needs Zone:Read and DNS:Edit on the zone. */
public class CloudflareDnsProvider implements DnsProvider {

    public static final String DEFAULT_API = "https://api.cloudflare.com/client/v4";

    private final String token;
    private final String apiBase;
    private final String fixedZoneId;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();

    public CloudflareDnsProvider(String token, String zoneId, String apiBase) {
        this.token = token;
        this.fixedZoneId = zoneId;
        this.apiBase = apiBase == null ? DEFAULT_API : apiBase.replaceAll("/+$", "");
    }

    private JSON call(String method, String path, String body) throws IOException {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(apiBase + path)).timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + token).header("Content-Type", "application/json");
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        HttpResponse<String> r;
        try {
            r = http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while calling Cloudflare", e);
        }
        JSON json;
        try {
            json = JSON.parse(r.body());
        } catch (RuntimeException e) {
            throw new IOException("Cloudflare returned HTTP " + r.statusCode() + " with a non-JSON body", e);
        }
        if (r.statusCode() / 100 != 2 || !json.get("success").asBoolean()) {
            String err = r.body().length() > 500 ? r.body().substring(0, 500) : r.body();
            throw new IOException("Cloudflare " + method + " " + path.replaceAll("\\?.*", "") + " failed (HTTP "
                    + r.statusCode() + "): " + err);
        }
        return json;
    }

    /** Finds the zone that contains fqdn by trying the name and then its parents (longest match first). */
    String zoneIdFor(String fqdn) throws IOException {
        if (fixedZoneId != null) {
            return fixedZoneId;
        }
        String[] labels = fqdn.split("\\.");
        for (int i = 0; i < labels.length - 1; i++) {
            String candidate = String.join(".", java.util.Arrays.copyOfRange(labels, i, labels.length));
            JSON res = call("GET", "/zones?name=" + URLEncoder.encode(candidate, StandardCharsets.UTF_8), null);
            JSON.Array arr = res.get("result").asArray();
            if (arr != null && arr.size() > 0) {
                return arr.get(0).asObject().get("id").asString();
            }
        }
        throw new IOException("No Cloudflare zone found for " + fqdn + " (does the API token have access to it?)");
    }

    @Override
    public java.util.List<String> authoritativeServers(String fqdn) throws IOException {
        JSON.Array ns = call("GET", "/zones/" + zoneIdFor(fqdn), null).get("result").asObject().get("name_servers")
                .asArray();
        java.util.List<String> out = new java.util.ArrayList<>();
        if (ns != null) {
            for (JSON.Value v : ns) {
                out.add(v.asString());
            }
        }
        return out;
    }

    @Override
    public String addTxt(String fqdn, String value) throws IOException {
        String zone = zoneIdFor(fqdn);
        String body = new JSONBuilder().put("type", "TXT").put("name", fqdn).put("content", value).put("ttl", 60)
                .toString();
        JSON res = call("POST", "/zones/" + zone + "/dns_records", body);
        return zone + "/" + res.get("result").asObject().get("id").asString();
    }

    @Override
    public void removeTxt(String fqdn, String value, String handle) throws IOException {
        if (handle == null || !handle.matches("^[0-9a-f]{32}/[0-9a-f]{32}$")) {
            throw new IOException("Unexpected Cloudflare record handle");
        }
        String[] p = handle.split("/");
        call("DELETE", "/zones/" + p[0] + "/dns_records/" + p[1], null);
    }
}
