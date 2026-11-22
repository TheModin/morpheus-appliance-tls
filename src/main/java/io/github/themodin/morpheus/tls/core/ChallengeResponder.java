package io.github.themodin.morpheus.tls.core;

import java.io.IOException;

/** Publishes ACME challenge answers (HTTP-01 files or DNS-01 TXT records) so the CA can validate them. */
public interface ChallengeResponder extends AutoCloseable {

    /** Makes http://domain/.well-known/acme-challenge/{token} return keyAuthorization. */
    void publish(String token, String keyAuthorization) throws IOException;

    void cleanup(String token);

    /** ACME challenge type this responder answers. */
    default String challengeType() {
        return "http-01";
    }

    /** Domain-aware variants used by AcmeIssuer; HTTP responders ignore the domain. */
    default void publish(String domain, String token, String keyAuthorization) throws IOException {
        publish(token, keyAuthorization);
    }

    default void cleanup(String domain, String token) {
        cleanup(token);
    }

    @Override
    void close();

    /** Tokens are base64url; reject anything else so they can never become a path traversal. */
    static void checkToken(String token) {
        if (token == null || !token.matches("^[A-Za-z0-9_-]{8,256}$")) {
            throw new IllegalArgumentException("Unexpected ACME token format");
        }
    }
}
