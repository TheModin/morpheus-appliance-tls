package io.github.themodin.morpheus.tls.core

import com.sun.net.httpserver.HttpServer
import spock.lang.Shared
import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

class DnsProvidersSpec extends Specification {

    static final String ZONE = 'a' * 32
    static final String REC = 'b' * 32

    @Shared HttpServer server
    @Shared List<String> calls = []
    @Shared List<String> auth = []
    @Shared String lastBody

    def setupSpec() {
        server = HttpServer.create(new InetSocketAddress('127.0.0.1', 0), 0)
        server.createContext('/', { ex ->
            String key = ex.requestMethod + ' ' + ex.requestURI.toString()
            calls << key
            auth << ex.requestHeaders.getFirst('Authorization')
            lastBody = ex.requestBody.text
            String out
            int code = 200
            if (key == "GET /zones?name=sub.example.com") {
                out = '{"success":true,"result":[]}'
            } else if (key == "GET /zones?name=example.com") {
                out = '{"success":true,"result":[{"id":"' + ZONE + '"}]}'
            } else if (key == "GET /zones/$ZONE".toString()) {
                out = '{"success":true,"result":{"id":"' + ZONE + '","name_servers":["ns1.example.net","ns2.example.net"]}}'
            } else if (key == "POST /zones/$ZONE/dns_records".toString()) {
                out = '{"success":true,"result":{"id":"' + REC + '"}}'
            } else if (key == "DELETE /zones/$ZONE/dns_records/$REC".toString()) {
                out = '{"success":true,"result":{"id":"' + REC + '"}}'
            } else if (key.startsWith('GET /zones?name=') && !key.contains('bad')) {
                out = '{"success":true,"result":[]}'
            } else {
                code = 403
                out = '{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}'
            }
            byte[] b = out.bytes
            ex.sendResponseHeaders(code, b.length)
            ex.responseBody.write(b)
            ex.close()
        })
        server.start()
    }

    def cleanupSpec() { server.stop(0) }

    String base() { "http://127.0.0.1:${server.address.port}" }

    def "cloudflare: finds the parent zone, creates and deletes the TXT record"() {
        given:
        calls.clear(); auth.clear()
        def cf = new CloudflareDnsProvider('secret-token', null, base())
        when:
        String h = cf.addTxt('_acme-challenge.sub.example.com', 'val123')
        then:
        h == "$ZONE/$REC".toString()
        calls == ['GET /zones?name=_acme-challenge.sub.example.com', 'GET /zones?name=sub.example.com',
                  'GET /zones?name=example.com', "POST /zones/$ZONE/dns_records".toString()]
        auth.every { it == 'Bearer secret-token' }
        lastBody.contains('"type":"TXT"')
        lastBody.contains('"content":"val123"')
        lastBody.contains('"name":"_acme-challenge.sub.example.com"')
        when:
        calls.clear()
        cf.removeTxt('x', 'val123', h)
        then:
        calls == ["DELETE /zones/$ZONE/dns_records/$REC".toString()]
    }

    def "cloudflare: reports the zone's authoritative name servers"() {
        expect:
        new CloudflareDnsProvider('t', ZONE, base()).authoritativeServers('_acme-challenge.example.com') ==
                ['ns1.example.net', 'ns2.example.net']
    }

    def "cloudflare: a fixed zone id skips the lookup"() {
        given:
        calls.clear()
        when:
        new CloudflareDnsProvider('t', ZONE, base()).addTxt('_acme-challenge.example.com', 'v')
        then:
        calls == ["POST /zones/$ZONE/dns_records".toString()]
    }

    def "cloudflare: API errors and unknown zones become readable IOExceptions"() {
        when:
        new CloudflareDnsProvider('tok-secret', null, base()).addTxt('_acme-challenge.nozone.test', 'v')
        then:
        thrown(IOException)
        when:
        new CloudflareDnsProvider('tok-secret', null, base()).addTxt('_acme-challenge.bad.test', 'v')
        then:
        def e = thrown(IOException)
        e.message.contains('Invalid access token')
        !e.message.contains('tok-secret')  // token never leaks into messages
    }

    def "cloudflare: refuses a tampered record handle"() {
        when:
        new CloudflareDnsProvider('t', null, base()).removeTxt('x', 'v', '../../zones')
        then:
        thrown(IOException)
    }

    def "txt value is base64url(sha256(keyAuthorization))"() {
        expect:
        // RFC 8555 style check with a known SHA-256: sha256("abc")
        DnsResponder.txtValue('abc') == 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0'
    }

    def "responder publishes to _acme-challenge (wildcard stripped) and cleans up"() {
        given:
        List ops = []
        def provider = new FakeDns(add: { n, v -> ops << "add $n $v".toString(); 'h1' },
                                   remove: { n, v, h -> ops << "rm $n $h".toString() })
        def r = new DnsResponder(provider, null, 1, { })
        when:
        r.publish('*.example.com', 'tokentoken1', 'keyauth')
        r.cleanup('*.example.com', 'tokentoken1')
        then:
        ops == ["add _acme-challenge.example.com ${DnsResponder.txtValue('keyauth')}".toString(),
                'rm _acme-challenge.example.com h1']
        r.challengeType() == 'dns-01'
    }

    def "close() removes records left behind by a failed run"() {
        given:
        List ops = []
        def provider = new FakeDns(remove: { n, v, h -> ops << n })
        def r = new DnsResponder(provider, null, 1, { })
        r.publish('a.example.com', 'tokentoken1', 'k')
        when:
        r.close()
        then:
        ops == ['_acme-challenge.a.example.com']
    }

    def "responder rejects a malformed token"() {
        when:
        new DnsResponder(new FakeDns(), null, 1, { }).publish('a.example.com', '../x', 'k')
        then:
        thrown(IllegalArgumentException)
    }

    def "propagation check polls a DoH endpoint until the record shows up"() {
        given:
        int n = 0
        def doh = HttpServer.create(new InetSocketAddress('127.0.0.1', 0), 0)
        doh.createContext('/dns-query', { ex ->
            n++
            String body = n < 3 ? '{"Status":0}' : '{"Status":0,"Answer":[{"name":"x","type":16,"data":"\\"wanted\\""}]}'
            ex.sendResponseHeaders(200, body.bytes.length)
            ex.responseBody.write(body.bytes)
            ex.close()
        })
        doh.start()
        def prop = new DnsPropagation("http://127.0.0.1:${doh.address.port}/dns-query", 50)
        List msgs = []
        when:
        boolean ok = prop.await('_acme-challenge.x.test', 'wanted', 10, { msgs << it })
        then:
        ok
        n == 3
        cleanup:
        doh.stop(0)
    }

    def "propagation check times out softly"() {
        given:
        def prop = new DnsPropagation('http://127.0.0.1:1/dns-query', 50)
        expect:
        !prop.await('x', 'y', 1, { })
    }
}
