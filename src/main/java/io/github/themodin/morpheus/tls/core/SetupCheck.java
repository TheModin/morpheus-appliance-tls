package io.github.themodin.morpheus.tls.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks, from inside the plugin (so as the unprivileged Morpheus app user), that the one-time root-side setup is in
 * place: helper, sudoers rule, nginx pointing at the plugin's certificate files, and those files existing.
 * Nothing here changes anything.
 */
public final class SetupCheck {

    public static final String CTL = "/opt/morpheus/bin/morpheus-ctl";

    private SetupCheck() {
    }

    public static List<Map<String, Object>> run(CommandRunner runner, String helper, String nginxConfPath,
                                                String certPath, String keyPath) {
        List<Map<String, Object>> out = new ArrayList<>();

        Path hp = Paths.get(helper);
        boolean helperThere = Files.isRegularFile(hp) && Files.isExecutable(hp);
        out.add(item("helper", "Privileged helper installed", helperThere,
                helperThere ? helper : helper + " not found"));

        boolean sudoOk = false;
        String sudoDetail;
        if (!helperThere) {
            sudoDetail = "needs the helper";
        } else {
            CommandRunner.Result r = quiet(runner, Arrays.asList("sudo", "-n", helper, "version"));
            sudoOk = r != null && r.ok() && r.output.startsWith("morpheus-tls-helper");
            sudoDetail = sudoOk ? r.output
                    : r == null ? "could not run sudo"
                    : r.output.contains("unknown operation") ? "helper is outdated - re-run the setup command"
                    : "sudo is not allowed to run the helper (sudoers rule missing?)";
        }
        out.add(item("sudoers", "sudo may run the helper", sudoOk, sudoDetail));

        CommandRunner.Result rr = quiet(runner, Arrays.asList("sudo", "-n", "-l", CTL, "restart", "nginx"));
        boolean restartOk = rr != null && rr.ok();
        out.add(item("restart", "sudo may restart nginx", restartOk,
                restartOk ? CTL + " restart nginx" : "not allowed (sudoers rule missing?)"));

        out.add(nginxPaths(nginxConfPath, certPath, keyPath));

        boolean certThere = false, keyThere = false;
        if (sudoOk) {
            certThere = exists(runner, helper, certPath);
            keyThere = exists(runner, helper, keyPath);
        }
        out.add(item("files", "Certificate and key files exist", sudoOk ? certThere && keyThere : Boolean.FALSE,
                !sudoOk ? "needs the helper and sudoers rule"
                        : certThere && keyThere ? certPath + ", " + keyPath
                        : "missing: " + (certThere ? "" : certPath + " ") + (keyThere ? "" : keyPath)));
        return out;
    }

    public static boolean ready(List<Map<String, Object>> checks) {
        for (Map<String, Object> c : checks) {
            if (!Boolean.TRUE.equals(c.get("ok"))) {
                return false;
            }
        }
        return true;
    }

    static Map<String, Object> nginxPaths(String confPath, String certPath, String keyPath) {
        if (confPath == null || "none".equals(confPath)) {
            return item("nginx", "nginx uses the plugin's certificate files", Boolean.TRUE, "check disabled");
        }
        String conf;
        try {
            conf = new String(Files.readAllBytes(Paths.get(confPath)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            // cannot verify (other layout, no read access): do not block, but say so
            return item("nginx", "nginx uses the plugin's certificate files", Boolean.TRUE,
                    "could not read " + confPath + " - not verified");
        }
        String cert = directive(conf, "ssl_certificate");
        String key = directive(conf, "ssl_certificate_key");
        boolean ok = certPath.equals(cert) && keyPath.equals(key);
        return item("nginx", "nginx uses the plugin's certificate files", ok,
                ok ? certPath + ", " + keyPath : "nginx uses " + cert + " and " + key);
    }

    static String directive(String conf, String name) {
        Matcher m = Pattern.compile("(?m)^\\s*" + name + "\\s+([^;\\s]+)\\s*;").matcher(conf);
        return m.find() ? m.group(1) : null;
    }

    private static boolean exists(CommandRunner runner, String helper, String path) {
        CommandRunner.Result r = quiet(runner, Arrays.asList("sudo", "-n", helper, "exists", path));
        return r != null && r.ok();
    }

    private static CommandRunner.Result quiet(CommandRunner runner, List<String> argv) {
        try {
            return runner.run(argv, null, 10);
        } catch (Exception e) {
            return null;
        }
    }

    private static Map<String, Object> item(String id, String label, Boolean ok, String detail) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("label", label);
        m.put("ok", ok);
        m.put("detail", detail);
        return m;
    }
}
