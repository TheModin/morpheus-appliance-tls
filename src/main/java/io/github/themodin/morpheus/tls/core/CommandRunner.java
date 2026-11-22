package io.github.themodin.morpheus.tls.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Runs OS commands. An interface so tests can substitute a fake. */
public interface CommandRunner {

    class Result {
        public final int exitCode;
        public final byte[] stdout;
        public final String output;

        public Result(int exitCode, byte[] stdout, String output) {
            this.exitCode = exitCode;
            this.stdout = stdout;
            this.output = output;
        }

        public boolean ok() {
            return exitCode == 0;
        }
    }

    /** Runs argv directly (no shell). stdin may be null. */
    Result run(List<String> argv, byte[] stdin, int timeoutSeconds) throws IOException;

    /** Default implementation backed by ProcessBuilder. */
    class Local implements CommandRunner {
        private final java.util.Map<String, String> extraEnv;

        public Local() {
            this(java.util.Collections.emptyMap());
        }

        public Local(java.util.Map<String, String> extraEnv) {
            this.extraEnv = extraEnv;
        }

        @Override
        public Result run(List<String> argv, byte[] stdin, int timeoutSeconds) throws IOException {
            ProcessBuilder pb = new ProcessBuilder(resolve(argv));
            pb.environment().putAll(extraEnv);
            Process p = pb.start();
            Thread feeder = null;
            if (stdin != null) {
                feeder = new Thread(() -> {
                    try (OutputStream os = p.getOutputStream()) {
                        os.write(stdin);
                    } catch (IOException ignored) {
                        // process may exit before reading stdin
                    }
                });
                feeder.start();
            } else {
                p.getOutputStream().close();
            }
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            Thread errDrain = drain(p.getErrorStream(), err);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Thread outDrain = drain(p.getInputStream(), out);
            try {
                if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                    throw new IOException("Command timed out after " + timeoutSeconds + "s: " + String.join(" ", argv));
                }
                outDrain.join(2000);
                errDrain.join(2000);
                if (feeder != null) {
                    feeder.join(2000);
                }
            } catch (InterruptedException e) {
                p.destroyForcibly();
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted running: " + String.join(" ", argv), e);
            }
            String combined = (out.toString(StandardCharsets.UTF_8) + err.toString(StandardCharsets.UTF_8)).trim();
            return new Result(p.exitValue(), out.toByteArray(), combined);
        }

        /** The JVM looks programs up in ITS OWN PATH; honour a PATH override so tests can shadow e.g. sudo. */
        private List<String> resolve(List<String> argv) {
            String path = extraEnv.get("PATH");
            String prog = argv.get(0);
            if (path == null || prog.contains("/")) {
                return argv;
            }
            for (String dir : path.split(":")) {
                java.io.File f = new java.io.File(dir, prog);
                if (f.isFile() && f.canExecute()) {
                    List<String> out = new java.util.ArrayList<>(argv);
                    out.set(0, f.getAbsolutePath());
                    return out;
                }
            }
            return argv;
        }

        private static Thread drain(InputStream in, ByteArrayOutputStream sink) {
            Thread t = new Thread(() -> {
                try {
                    in.transferTo(sink);
                } catch (IOException ignored) {
                    // stream closed
                }
            });
            t.setDaemon(true);
            t.start();
            return t;
        }
    }
}
