package io.github.themodin.morpheus.tls.core

import spock.lang.Specification

class RenewalSettingsSpec extends Specification {

    def "parses options and applies defaults"() {
        when:
        def s = RenewalSettings.fromOptions([domains: 'Morpheus.Example.com, alt.example.com', contactEmail: 'a@b.se',
                                              useStaging: 'off', renewBeforeDays: '21.0', webrootPath: '/var/www'])
        then:
        s.domains == ['morpheus.example.com', 'alt.example.com']
        !s.useStaging
        s.renewBeforeDays == 21
        s.webrootPath == '/var/www'
        s.certPath == '/etc/morpheus/ssl/cert.pem'
        s.keepBackups == 5
        s.backupDir == '/etc/morpheus/ssl/backup'
        s.acmeDirectory() == RenewalSettings.LE_PRODUCTION
        notThrown(Exception)
    }

    def "staging is the default CA"() {
        expect:
        RenewalSettings.fromOptions([domains: 'a.example.com']).acmeDirectory() == RenewalSettings.LE_STAGING
    }

    def "validate rejects bad input: #why"() {
        when:
        def s = RenewalSettings.fromOptions(opts)
        s.validate()
        then:
        thrown(IllegalArgumentException)
        where:
        why                | opts
        'no domain'        | [contactEmail: 'a@b.se']
        'wildcard http-01' | [domains: '*.example.com', contactEmail: 'a@b.se', challengeType: 'http-01']
        'dns no token'     | [domains: 'a.example.com', contactEmail: 'a@b.se']
        'bad zone id'      | [domains: 'a.example.com', contactEmail: 'a@b.se', cloudflareApiToken: 't', cloudflareZoneId: 'xyz']
        'unknown challenge'| [domains: 'a.example.com', contactEmail: 'a@b.se', challengeType: 'tls-alpn-01']
        'not an fqdn'      | [domains: 'localhost', contactEmail: 'a@b.se']
        'bad email'        | [domains: 'a.example.com', contactEmail: 'nope']
        'threshold too big'| [domains: 'a.example.com', contactEmail: 'a@b.se', renewBeforeDays: '120']
        'path traversal'   | [domains: 'a.example.com', contactEmail: 'a@b.se', certPath: '/etc/../tmp/x']
        'quote in path'    | [domains: 'a.example.com', contactEmail: 'a@b.se', keyPath: "/etc/x'y"]
        'relative webroot' | [domains: 'a.example.com', contactEmail: 'a@b.se', webrootPath: 'www']
    }

    def "dns-01 is the default and allows wildcards"() {
        when:
        def s = RenewalSettings.fromOptions([domains: '*.Example.com, example.com', contactEmail: 'a@b.se',
                                              cloudflareApiToken: 'tok', dnsCheckUrl: 'none'])
        s.validate()
        then:
        s.isDns01()
        s.domains == ['*.example.com', 'example.com']
        s.dnsCheckUrl == null
    }

    def "check-only does not need an e-mail"() {
        when:
        RenewalSettings.fromOptions([domains: 'a.example.com', checkOnly: 'true']).validate()
        then:
        notThrown(Exception)
    }
}
