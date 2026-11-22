package io.github.themodin.morpheus.tls.core

import spock.lang.Specification

import java.time.Instant

class CertStatusSpec extends Specification {

    RenewalSettings settings(Map extra = [:]) {
        RenewalSettings.fromOptions([domains: 'm.example.com', checkOnly: 'true', cloudflareApiToken: 'secret-tok'] + extra)
    }

    def "classifies a healthy, a due and an expired certificate"() {
        expect:
        CertStatus.classify(TestCerts.leafPem(['m.example.com'], 90, -10).with { CertInspector.parseChain(it.bytes)[0] }, settings(), Instant.now()) == 'OK'
        CertStatus.classify(TestCerts.leafPem(['m.example.com'], 90, -70).with { CertInspector.parseChain(it.bytes)[0] }, settings(), Instant.now()) == 'RENEWAL_DUE'
        CertStatus.classify(TestCerts.leafPem(['m.example.com'], 10, -20).with { CertInspector.parseChain(it.bytes)[0] }, settings(), Instant.now()) == 'EXPIRED'
        CertStatus.classify(TestCerts.leafPem(['other.example.com'], 90, -10).with { CertInspector.parseChain(it.bytes)[0] }, settings(), Instant.now()) == 'DOES_NOT_COVER_DOMAINS'
    }

    def "collect reports the served cert and never leaks the token"() {
        given:
        def cert = CertInspector.parseChain(TestCerts.leafPem(['m.example.com'], 90, -10).bytes)[0]
        when:
        def m = CertStatus.collect(settings(), Instant.now(), { s -> cert } as CertStatus.Prober)
        then:
        m.state == 'OK'
        m.daysRemaining.intValue() in [79, 80]
        m.sans == 'm.example.com'
        m.tokenConfigured == 'yes'
        !m.values().any { it.toString().contains('secret-tok') }
    }

    def "an unreachable endpoint becomes a state, not an exception"() {
        when:
        def m = CertStatus.collect(settings(), Instant.now(), { s -> throw new IOException('refused') } as CertStatus.Prober)
        then:
        m.state == 'UNREACHABLE'
        m.error.contains('refused')
    }
}
