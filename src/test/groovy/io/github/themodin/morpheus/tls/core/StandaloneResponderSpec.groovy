package io.github.themodin.morpheus.tls.core

import spock.lang.Specification

class StandaloneResponderSpec extends Specification {

    def "serves published tokens and 404s everything else"() {
        given:
        def r = new StandaloneResponder(0)
        def base = "http://127.0.0.1:${r.port()}/.well-known/acme-challenge/"
        r.publish('abcdefgh_-12345', 'abcdefgh_-12345.thumbprint')
        when:
        def ok = new URL(base + 'abcdefgh_-12345').openConnection()
        def missing = new URL(base + 'unknowntoken1').openConnection()
        then:
        ok.responseCode == 200
        ok.inputStream.text == 'abcdefgh_-12345.thumbprint'
        missing.responseCode == 404
        cleanup:
        r?.close()
    }

    def "cleanup removes the token"() {
        given:
        def r = new StandaloneResponder(0)
        r.publish('abcdefgh12345', 'x')
        when:
        r.cleanup('abcdefgh12345')
        then:
        new URL("http://127.0.0.1:${r.port()}/.well-known/acme-challenge/abcdefgh12345").openConnection().responseCode == 404
        cleanup:
        r?.close()
    }

    def "path-traversal style tokens are rejected"() {
        given:
        def r = new StandaloneResponder(0)
        when:
        r.publish('../../etc/passwd', 'x')
        then:
        thrown(IllegalArgumentException)
        cleanup:
        r?.close()
    }

    def "reports a helpful error when the port is taken"() {
        given:
        def first = new StandaloneResponder(0)
        when:
        new StandaloneResponder(first.port())
        then:
        def e = thrown(IOException)
        e.message.contains('webroot')
        cleanup:
        first?.close()
    }
}
