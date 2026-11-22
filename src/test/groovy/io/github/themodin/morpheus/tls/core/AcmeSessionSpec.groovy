package io.github.themodin.morpheus.tls.core

import spock.lang.Specification

class AcmeSessionSpec extends Specification {
    def "directory URIs resolve without ServiceLoader"() {
        expect:
        AcmeIssuer.sessionFor(RenewalSettings.LE_STAGING).serverUri.toString() == 'acme://letsencrypt.org/staging'
        AcmeIssuer.sessionFor('https://localhost:14000/dir').serverUri.toString() == 'https://localhost:14000/dir'
    }

    def "works when the thread context class loader cannot see the providers (as in the appliance)"() {
        given:
        def old = Thread.currentThread().contextClassLoader
        Thread.currentThread().contextClassLoader = new URLClassLoader(new URL[0], null)
        when:
        def s = AcmeIssuer.sessionFor(RenewalSettings.LE_STAGING)
        then:
        s.serverUri.scheme == 'acme'
        cleanup:
        Thread.currentThread().contextClassLoader = old
    }
}
