package io.github.themodin.morpheus.tls.core;

import java.io.IOException;

/** Creates and removes the TXT records used by the ACME DNS-01 challenge. */
public interface DnsProvider {

    /** Adds a TXT record and returns an opaque handle that removeTxt() understands. */
    /**
     * Authoritative name servers for the zone holding fqdn, so propagation can be checked without any resolver
     * cache. Empty = unknown (the caller falls back to a public DoH resolver).
     */
    default java.util.List<String> authoritativeServers(String fqdn) throws IOException {
        return java.util.Collections.emptyList();
    }

    String addTxt(String fqdn, String value) throws IOException;

    void removeTxt(String fqdn, String value, String handle) throws IOException;
}
