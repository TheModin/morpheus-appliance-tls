package io.github.themodin.morpheus.tls.core

import spock.lang.Shared
import spock.lang.Specification

import java.time.Instant

class CertInspectorSpec extends Specification {

    @Shared String pem = TestCerts.leafPem(['morpheus.example.com', 'alt.example.com'], 45)
    @Shared String selfSigned = TestCerts.selfSignedPem('self.example.com', 30)

    def "reads SANs, expiry and fingerprint"() {
        when:
        def c = CertInspector.parseChain(pem.bytes)[0]
        then:
        CertInspector.dnsNames(c) == ['morpheus.example.com', 'alt.example.com']
        CertInspector.daysRemaining(c, Instant.now()) >= 43L && CertInspector.daysRemaining(c, Instant.now()) <= 45L
        CertInspector.sha256(c) ==~ /[0-9A-F]{64}/
        !CertInspector.isSelfSigned(c)
    }

    def "covers checks every wanted name"() {
        given:
        def c = CertInspector.parseChain(pem.bytes)[0]
        expect:
        CertInspector.covers(c, ['morpheus.example.com'])
        CertInspector.covers(c, ['morpheus.example.com', 'alt.example.com'])
        !CertInspector.covers(c, ['other.example.com'])
    }

    def "detects self-signed certificates"() {
        expect:
        CertInspector.isSelfSigned(CertInspector.parseChain(selfSigned.bytes)[0])
    }

    def "garbage input is rejected"() {
        when:
        CertInspector.parseChain('not a cert'.bytes)
        then:
        thrown(java.security.cert.CertificateException)
    }
}
