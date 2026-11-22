package io.github.themodin.morpheus.tls.core;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Tiny embedded HTTP server answering only /.well-known/acme-challenge/{token}. */
public class StandaloneResponder implements ChallengeResponder {

    private static final String PREFIX = "/.well-known/acme-challenge/";

    private final Map<String, String> tokens = new ConcurrentHashMap<>();
    private final HttpServer server;

    public StandaloneResponder(int port) throws IOException {
        try {
            server = HttpServer.create(new InetSocketAddress(port), 8);
        } catch (BindException e) {
            throw new IOException("Cannot listen on port " + port + " for the HTTP-01 challenge ("
                    + e.getMessage() + "). Port 80 is normally held by nginx and needs privileges; use webroot "
                    + "mode or forward the port.", e);
        }
        server.createContext(PREFIX, ex -> {
            String path = ex.getRequestURI().getPath();
            String token = path.length() > PREFIX.length() ? path.substring(PREFIX.length()) : "";
            String body = tokens.get(token);
            byte[] out = (body == null ? "not found" : body).getBytes(StandardCharsets.US_ASCII);
            ex.getResponseHeaders().add("Content-Type", "text/plain");
            ex.sendResponseHeaders(body == null ? 404 : 200, out.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(out);
            }
        });
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void publish(String token, String keyAuthorization) {
        ChallengeResponder.checkToken(token);
        tokens.put(token, keyAuthorization);
    }

    @Override
    public void cleanup(String token) {
        tokens.remove(token);
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
