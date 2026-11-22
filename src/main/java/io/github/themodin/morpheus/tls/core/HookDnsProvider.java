package io.github.themodin.morpheus.tls.core;

import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * Delegates to a customer script: {@code script add <fqdn> <value>} and {@code script remove <fqdn> <value>}.
 * No shell is involved; the script path is passed as argv[0]. Exit code != 0 fails the renewal.
 */
public class HookDnsProvider implements DnsProvider {

    private final String script;

    public HookDnsProvider(String script) {
        this.script = script;
    }

    private void run(String action, String fqdn, String value) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(Arrays.asList(script, action, fqdn, value)).redirectErrorStream(true);
        Process p = pb.start();
        byte[] out = p.getInputStream().readAllBytes();
        try {
            if (!p.waitFor(120, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                throw new IOException("DNS hook timed out: " + action);
            }
        } catch (InterruptedException e) {
            p.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted", e);
        }
        if (p.exitValue() != 0) {
            throw new IOException("DNS hook '" + action + "' exited " + p.exitValue() + ": "
                    + new String(out).trim());
        }
    }

    @Override
    public String addTxt(String fqdn, String value) throws IOException {
        run("add", fqdn, value);
        return "hook";
    }

    @Override
    public void removeTxt(String fqdn, String value, String handle) throws IOException {
        run("remove", fqdn, value);
    }
}
