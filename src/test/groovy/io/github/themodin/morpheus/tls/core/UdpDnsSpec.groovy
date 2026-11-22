package io.github.themodin.morpheus.tls.core

import spock.lang.Specification

class UdpDnsSpec extends Specification {

    /** A one-record fake authoritative server on a random UDP port. */
    static Thread serve(DatagramSocket sock, List<String> answers, Closure onQuery = null) {
        Thread.start {
            byte[] buf = new byte[512]
            while (!sock.closed) {
                def pkt = new DatagramPacket(buf, buf.length)
                try { sock.receive(pkt) } catch (IOException e) { return }
                onQuery?.call()
                byte[] q = Arrays.copyOf(buf, pkt.length)
                def o = new ByteArrayOutputStream()
                o.write(q, 0, 2)                         // id
                o.write([0x84, 0x00] as byte[], 0, 2)    // response, authoritative
                o.write([0, 1, 0, answers.size(), 0, 0, 0, 0] as byte[], 0, 8)
                o.write(q, 12, q.length - 12)            // question section
                answers.each { String a ->
                    o.write([0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60] as byte[], 0, 10)   // pointer, TXT, IN, ttl 60
                    byte[] d = a.getBytes('UTF-8')
                    // split into <=255 char strings like real servers do for long values
                    def chunks = d.toList().collate(255)
                    int rdlen = chunks.sum { it.size() + 1 }
                    o.write([rdlen >> 8, rdlen & 0xff] as byte[], 0, 2)
                    chunks.each { c -> o.write(c.size()); o.write(c as byte[], 0, c.size()) }
                }
                byte[] resp = o.toByteArray()
                sock.send(new DatagramPacket(resp, resp.length, pkt.socketAddress))
            }
        }
    }

    def "queries a TXT record from an authoritative server"() {
        given:
        def sock = new DatagramSocket(0, InetAddress.getByName('127.0.0.1'))
        serve(sock, ['other', 'wanted-value'])
        expect:
        UdpDns.queryTxt('127.0.0.1', sock.localPort, '_acme-challenge.x.example.com', 2000) == ['other', 'wanted-value']
        cleanup:
        sock.close()
    }

    def "joins multi-string TXT data"() {
        given:
        def sock = new DatagramSocket(0, InetAddress.getByName('127.0.0.1'))
        String longValue = 'a' * 300
        serve(sock, [longValue])
        expect:
        UdpDns.queryTxt('127.0.0.1', sock.localPort, 'x.example.com', 2000) == [longValue]
        cleanup:
        sock.close()
    }

    def "awaitAuthoritative waits until every server serves the value"() {
        given:
        def s1 = new DatagramSocket(0, InetAddress.getByName('127.0.0.1'))
        def s2 = new DatagramSocket(0, InetAddress.getByName('127.0.0.1'))
        int n = 0
        serve(s1, ['v'])
        serve(s2, ['v'], { n++ })     // second server is queried too
        List<String> log = []
        when:
        boolean ok = DnsPropagation.visibleOnAll(['127.0.0.1'], s1.localPort, 'x.example.com', 'v')
        boolean wrong = DnsPropagation.visibleOnAll(['127.0.0.1'], s1.localPort, 'x.example.com', 'nope')
        boolean none = DnsPropagation.awaitAuthoritative(['127.0.0.1'], s1.localPort, 'x.example.com', 'nope', 1, 100, { log << it })
        then:
        ok
        !wrong
        !none
        log.any { it.contains('validating anyway') }
        cleanup:
        s1.close(); s2.close()
    }

    def "an unreachable server counts as not visible, not as an exception"() {
        expect:
        !DnsPropagation.visibleOnAll(['127.0.0.1'], 9, 'x.example.com', 'v')
    }
}
