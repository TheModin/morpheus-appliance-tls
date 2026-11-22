package io.github.themodin.morpheus.tls.core;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * File access for root-owned files under /etc/morpheus.
 * <p>
 * Without sudo the files are accessed directly. With sudo every privileged operation goes through ONE root-owned
 * helper script ({@code deploy/morpheus-tls-helper}) that is confined to /etc/morpheus, instead of granting the
 * Morpheus app user passwordless {@code sudo install/cp/rm/cat} (which would be a general root shell). File
 * content, including the private key, is passed over the helper's stdin and never staged in a temp directory.
 */
public class HostFiles {

    public static final String DEFAULT_HELPER = "/usr/local/sbin/morpheus-tls-helper";
    private static final int TIMEOUT = 60;
    private static final int EXIT_NOT_FOUND = 3;

    private final boolean useSudo;
    private final CommandRunner runner;
    private final String helper;

    public HostFiles(boolean useSudo, CommandRunner runner) {
        this(useSudo, runner, DEFAULT_HELPER);
    }

    public HostFiles(boolean useSudo, CommandRunner runner, String helper) {
        this.useSudo = useSudo;
        this.runner = runner;
        this.helper = helper == null ? DEFAULT_HELPER : helper;
    }

    /** Reads a file; returns null when it does not exist. */
    public byte[] read(String path) throws IOException {
        try {
            return Files.readAllBytes(Paths.get(path));
        } catch (NoSuchFileException e) {
            return null;
        } catch (AccessDeniedException e) {
            if (!useSudo) {
                throw e;
            }
        }
        CommandRunner.Result r = helper(null, "read", path);
        if (r.exitCode == EXIT_NOT_FOUND) {
            return null;
        }
        if (!r.ok()) {
            throw helperError("read", r);
        }
        return r.stdout;
    }

    /** Writes content to path with the given octal mode (0600, 0640 or 0644). */
    public void write(String path, byte[] content, String mode) throws IOException {
        if (useSudo) {
            CommandRunner.Result r = helper(content, "write", path, mode);
            if (!r.ok()) {
                throw helperError("write", r);
            }
            return;
        }
        Path target = Paths.get(path);
        Path parent = target.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path tmp = Files.createTempFile(parent, ".lewrite", ".tmp");
        try {
            Files.write(tmp, content);
            Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString(toRwx(mode)));
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /** Copies src to dst preserving mode (backups and rollback). */
    public void copy(String src, String dst) throws IOException {
        if (useSudo) {
            CommandRunner.Result r = helper(null, "copy", src, dst);
            if (!r.ok()) {
                throw helperError("copy", r);
            }
        } else {
            Path parent = Paths.get(dst).getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.copy(Paths.get(src), Paths.get(dst), StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.COPY_ATTRIBUTES);
        }
    }

    /** Keeps the newest {@code keep} timestamped backup directories below the backup directory and removes the rest. */
    public void pruneBackups(String dir, int keep) throws IOException {
        if (useSudo) {
            CommandRunner.Result r = helper(null, "prune", String.valueOf(keep));
            if (!r.ok()) {
                throw helperError("prune", r);
            }
            return;
        }
        Path root = Paths.get(dir);
        if (!Files.isDirectory(root)) {
            return;
        }
        List<Path> dirs = new ArrayList<>();
        try (java.util.stream.Stream<Path> st = Files.list(root)) {
            st.filter(Files::isDirectory).filter(x -> x.getFileName().toString().matches("^[0-9]{14}$")).forEach(dirs::add);
        }
        dirs.sort(java.util.Comparator.comparing(x -> x.getFileName().toString()));
        for (int i = 0; i < dirs.size() - keep; i++) {
            try (java.util.stream.Stream<Path> st = Files.walk(dirs.get(i))) {
                st.sorted(java.util.Comparator.reverseOrder()).forEach(x -> x.toFile().delete());
            }
        }
    }

    public void delete(String path) throws IOException {
        if (useSudo) {
            CommandRunner.Result r = helper(null, "delete", path);
            if (!r.ok()) {
                throw helperError("delete", r);
            }
        } else {
            Files.deleteIfExists(Paths.get(path));
        }
    }

    public boolean exists(String path) throws IOException {
        if (Files.exists(Paths.get(path))) {
            return true;
        }
        return useSudo && helper(null, "exists", path).ok();
    }

    private CommandRunner.Result helper(byte[] stdin, String... args) throws IOException {
        List<String> argv = new ArrayList<>(Arrays.asList("sudo", "-n", helper));
        argv.addAll(Arrays.asList(args));
        return runner.run(argv, stdin, TIMEOUT);
    }

    private IOException helperError(String op, CommandRunner.Result r) {
        return new IOException("Privileged " + op + " failed (exit " + r.exitCode + "): " + r.output
                + " - is " + helper + " installed and allowed by sudoers for the Morpheus app user?");
    }

    static String toRwx(String octal) {
        int m = Integer.parseInt(octal, 8);
        StringBuilder sb = new StringBuilder();
        String rwx = "rwxrwxrwx";
        for (int i = 0; i < 9; i++) {
            sb.append((m & (1 << (8 - i))) != 0 ? rwx.charAt(i) : '-');
        }
        return sb.toString();
    }
}
