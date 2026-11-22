package io.github.themodin.morpheus.tls.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** Writes challenge files below a webroot that the front-end web server already serves. */
public class WebrootResponder implements ChallengeResponder {

    private final String webroot;
    private final HostFiles files;

    public WebrootResponder(String webroot, HostFiles files) {
        this.webroot = webroot.endsWith("/") ? webroot.substring(0, webroot.length() - 1) : webroot;
        this.files = files;
    }

    private String pathFor(String token) {
        return webroot + "/.well-known/acme-challenge/" + token;
    }

    @Override
    public void publish(String token, String keyAuthorization) throws IOException {
        ChallengeResponder.checkToken(token);
        files.write(pathFor(token), keyAuthorization.getBytes(StandardCharsets.US_ASCII), "0644");
    }

    @Override
    public void cleanup(String token) {
        try {
            ChallengeResponder.checkToken(token);
            files.delete(pathFor(token));
        } catch (IOException | IllegalArgumentException ignored) {
            // leftover challenge files are harmless
        }
    }

    @Override
    public void close() {
        // nothing to release
    }
}
