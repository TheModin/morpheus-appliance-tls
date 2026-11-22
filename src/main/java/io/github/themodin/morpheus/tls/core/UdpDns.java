package io.github.themodin.morpheus.tls.core;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/** Minimal DNS-over-UDP TXT client, used to ask authoritative servers directly (no resolver caching). */
public final class UdpDns {

    private UdpDns() {
    }

    static byte[] buildQuery(String name, int id) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        o.write(id >> 8);
        o.write(id & 0xff);
        o.write(0x00); // flags: standard query, no recursion desired
        o.write(0x00);
        o.write(0);
        o.write(1); // QDCOUNT
        for (int i = 0; i < 6; i++) {
            o.write(0);
        }
        for (String label : name.replaceAll("\\.$", "").split("\\.")) {
            byte[] l = label.getBytes(StandardCharsets.US_ASCII);
            o.write(l.length);
            o.write(l, 0, l.length);
        }
        o.write(0);
        o.write(0);
        o.write(16); // TYPE TXT
        o.write(0);
        o.write(1); // CLASS IN
        return o.toByteArray();
    }

    private static int skipName(byte[] m, int p) {
        while (true) {
            int len = m[p] & 0xff;
            if (len == 0) {
                return p + 1;
            }
            if ((len & 0xc0) == 0xc0) {
                return p + 2;
            }
            p += len + 1;
        }
    }

    /** TXT strings (each record's character-strings concatenated) found in the answer section. */
    static List<String> parseTxt(byte[] m, int len) {
        List<String> out = new ArrayList<>();
        if (len < 12) {
            return out;
        }
        int qd = ((m[4] & 0xff) << 8) | (m[5] & 0xff);
        int an = ((m[6] & 0xff) << 8) | (m[7] & 0xff);
        int p = 12;
        for (int i = 0; i < qd; i++) {
            p = skipName(m, p) + 4;
        }
        for (int i = 0; i < an && p < len; i++) {
            p = skipName(m, p);
            int type = ((m[p] & 0xff) << 8) | (m[p + 1] & 0xff);
            int rdlen = ((m[p + 8] & 0xff) << 8) | (m[p + 9] & 0xff);
            p += 10;
            if (type == 16) {
                StringBuilder sb = new StringBuilder();
                int q = p;
                while (q < p + rdlen) {
                    int l = m[q] & 0xff;
                    sb.append(new String(m, q + 1, l, StandardCharsets.UTF_8));
                    q += l + 1;
                }
                out.add(sb.toString());
            }
            p += rdlen;
        }
        return out;
    }

    public static List<String> queryTxt(String server, int port, String name, int timeoutMs) throws IOException {
        int id = new SecureRandom().nextInt(0x10000);
        byte[] q = buildQuery(name, id);
        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(timeoutMs);
            s.send(new DatagramPacket(q, q.length, new InetSocketAddress(InetAddress.getByName(server), port)));
            byte[] buf = new byte[4096];
            DatagramPacket r = new DatagramPacket(buf, buf.length);
            s.receive(r);
            if ((((buf[0] & 0xff) << 8) | (buf[1] & 0xff)) != id) {
                throw new IOException("DNS response id mismatch");
            }
            return parseTxt(buf, r.getLength());
        }
    }
}
