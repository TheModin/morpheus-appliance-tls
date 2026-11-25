package io.github.themodin.morpheus.tls.core;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Works out which Morpheus-managed server is the appliance itself, by comparing each server's addresses with the
 * addresses of the machine the plugin runs on. Pure logic, no Morpheus dependency.
 */
public final class ApplianceMatcher {

    private ApplianceMatcher() {
    }

    /** A managed server as far as matching is concerned. */
    public static final class Candidate {
        public final long id;
        public final String name;
        public final String hostname;
        public final List<String> ips;
        public final boolean agent;
        public final String os;
        public final String status;
        public int score;
        public String reason = "";

        public Candidate(long id, String name, String hostname, List<String> ips, boolean agent, String os, String status) {
            this.id = id;
            this.name = name;
            this.hostname = hostname;
            this.ips = ips == null ? Collections.<String>emptyList() : ips;
            this.agent = agent;
            this.os = os;
            this.status = status;
        }
    }

    /** Scores the candidates (IP match 100, host name match 40) and returns them best first. Never returns null. */
    public static List<Candidate> rank(List<Candidate> in, Set<String> localIps, String localHostName) {
        List<Candidate> out = new ArrayList<>(in);
        String host = localHostName == null ? "" : localHostName.toLowerCase(Locale.ROOT);
        for (Candidate c : out) {
            c.score = 0;
            c.reason = "";
            for (String ip : c.ips) {
                if (ip != null && localIps.contains(ip.trim())) {
                    c.score += 100;
                    c.reason = "same IP address as this appliance (" + ip.trim() + ")";
                    break;
                }
            }
            if (!host.isEmpty() && (host.equals(lower(c.name)) || host.equals(lower(c.hostname)))) {
                c.score += 40;
                c.reason = c.reason.isEmpty() ? "same host name as this appliance" : c.reason + ", same host name";
            }
        }
        out.sort(Comparator.<Candidate>comparingInt(c -> -c.score).thenComparing(c -> lower(c.name)));
        return out;
    }

    /** The server to preselect, or null when nothing matches by address (a name match alone is not enough). */
    public static Candidate recommended(List<Candidate> ranked) {
        for (Candidate c : ranked) {
            if (c.score >= 100 && c.agent) {
                return c;
            }
        }
        return null;
    }

    /** Non-loopback, non-link-local addresses of this machine. */
    public static Set<String> localAddresses() {
        Set<String> out = new LinkedHashSet<>();
        try {
            Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
            while (nics != null && nics.hasMoreElements()) {
                NetworkInterface nic = nics.nextElement();
                if (!nic.isUp() || nic.isLoopback()) {
                    continue;
                }
                Enumeration<InetAddress> addrs = nic.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress a = addrs.nextElement();
                    if (a.isLoopbackAddress() || a.isLinkLocalAddress() || !(a instanceof Inet4Address)) {
                        continue;
                    }
                    out.add(a.getHostAddress());
                }
            }
        } catch (Exception e) {
            // no network information: nothing to match against
        }
        return out;
    }

    /** The OS host name, read without any DNS lookup (InetAddress.getLocalHost() can block for many seconds). */
    public static String localHostName() {
        try {
            String h = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/proc/sys/kernel/hostname")),
                    java.nio.charset.StandardCharsets.UTF_8).trim();
            if (!h.isEmpty()) {
                return h;
            }
        } catch (Exception e) {
            // not Linux or not readable: try the environment
        }
        String env = System.getenv("HOSTNAME");
        return env == null ? "" : env.trim();
    }

    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }
}
