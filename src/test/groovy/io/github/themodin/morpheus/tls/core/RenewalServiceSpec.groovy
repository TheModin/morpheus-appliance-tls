package io.github.themodin.morpheus.tls.core

import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.Path
import java.security.cert.X509Certificate
import java.time.Instant

class RenewalServiceSpec extends Specification {

    /** Records commands; individual commands can be made to fail. */
    static class FakeRunner implements CommandRunner {
        List<String> commands = []
        Set<String> failing = [] as Set
        Result run(List<String> argv, byte[] stdin, int t) {
            String line = argv.size() == 3 && argv[0] == '/bin/sh' ? argv[2] : argv.join(' ')
            commands << line
            boolean fail = failing.any { line.contains(it) }
            return new Result(fail ? 1 : 0, new byte[0], fail ? 'boom' : '')
        }
    }

    Path dir
    String certPath, keyPath, acctPath
    FakeRunner runner
    String newChain
    X509Certificate newCert

    def setup() {
        dir = Files.createTempDirectory('renewal')
        certPath = "$dir/cert.pem"; keyPath = "$dir/key.pem"; acctPath = "$dir/acct.pem"
        runner = new FakeRunner()
        newChain = TestCerts.leafPem(['m.example.com'], 90)
        newCert = CertInspector.parseChain(newChain.bytes)[0]
    }

    RenewalSettings settings(Map extra = [:]) {
        Map o = [challengeType: 'http-01', domains: 'm.example.com', contactEmail: 'ops@example.com', useSudo: 'false', useStaging: 'true',
                 certPath: certPath, keyPath: keyPath, accountKeyPath: acctPath, backupDir: "$dir/backup", nginxConfPath: 'none',
                 verifyAfterInstall: 'true', verifyTimeoutSeconds: '1'] + extra
        return RenewalSettings.fromOptions(o.collectEntries { k, v -> [k, v.toString()] })
    }

    RenewalService service(boolean servesNew = true, boolean issuerFails = false) {
        return new RenewalService(runner, { Instant.now() })
            .withIssuer({ s, r ->
                if (issuerFails) { throw new IOException('CA says no') }
                return issued()
            } as RenewalService.Issuer)
            .withResponderFactory({ s, f -> new WebrootResponder(dir.toString(), f) } as RenewalService.ResponderFactory)
            .withProber({ s -> servesNew ? newCert : CertInspector.parseChain(TestCerts.leafPem(['m.example.com'], 5).bytes)[0] } as RenewalService.Prober)
    }

    AcmeIssuer.Issued issued() {
        def ctor = AcmeIssuer.Issued.getDeclaredConstructors()[0]
        ctor.accessible = true
        return ctor.newInstance(newChain, '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n')
    }

    void installCurrent(String pem) {
        new File(certPath).text = pem
        new File(keyPath).text = 'old-key'
    }

    def "healthy certificate -> UP_TO_DATE, nothing touched"() {
        given:
        installCurrent(TestCerts.leafPem(['m.example.com'], 90, -10))
        def before = new File(certPath).text
        when:
        def r = service().run(settings())
        then:
        r.status == RenewalResult.Status.UP_TO_DATE
        r.success
        new File(certPath).text == before
        runner.commands.isEmpty()
    }

    def "expiring certificate with checkOnly -> RENEWAL_DUE and no changes"() {
        given:
        installCurrent(TestCerts.leafPem(['m.example.com'], 90, -85))
        def before = new File(certPath).text
        when:
        def r = service().run(settings(checkOnly: true))
        then:
        r.status == RenewalResult.Status.RENEWAL_DUE
        new File(certPath).text == before
        runner.commands.isEmpty()
    }

    def "expiring certificate gets renewed, installed, nginx restarted, verified"() {
        given:
        installCurrent(TestCerts.leafPem(['m.example.com'], 90, -85))
        def oldCert = new File(certPath).text
        when:
        def r = service().run(settings())
        then:
        r.status == RenewalResult.Status.RENEWED
        new File(certPath).text == newChain
        new File(keyPath).text.contains('BEGIN PRIVATE KEY')
        new File("$dir/backup").listFiles().size() == 1
        new File("$dir/backup").listFiles()[0].listFiles().any { it.name == 'cert.pem' && it.text == oldCert }
        new File("$dir/backup").listFiles()[0].listFiles().any { it.name == 'key.pem' && it.text == 'old-key' }
        runner.commands == ['sudo -n /opt/morpheus/bin/morpheus-ctl restart nginx']   // restart only, never reconfigure
        r.notAfterAfter != null
    }

    def "only the newest 5 backups are kept"() {
        given:
        installCurrent(TestCerts.leafPem(['m.example.com'], 90, -85))
        (1..7).each { new File("$dir/backup/2026010${it}000000").mkdirs(); new File("$dir/backup/2026010${it}000000/cert.pem").text = 'old' }
        when:
        def r = service().run(settings())
        then:
        r.status == RenewalResult.Status.RENEWED
        new File("$dir/backup").list().length == 5
        !new File("$dir/backup/20260101000000").exists()
    }

    def "nginx using other paths than configured: refuse before issuing anything, with setup instructions"() {
        given:
        installCurrent(TestCerts.selfSignedPem('m.example.com', 3650))
        def conf = new File("$dir/site.conf")
        conf.text = "server {\n  ssl_certificate /etc/morpheus/ssl/default.crt;\n  ssl_certificate_key /etc/morpheus/ssl/default.key;\n}\n"
        def issuedCalled = false
        def svc = new RenewalService(runner, { Instant.now() })
            .withIssuer({ s, r -> issuedCalled = true; return issued() } as RenewalService.Issuer)
            .withResponderFactory({ s, f -> new WebrootResponder(dir.toString(), f) } as RenewalService.ResponderFactory)
        when:
        def r = svc.run(settings(nginxConfPath: conf.path))
        then:
        r.status == RenewalResult.Status.FAILED
        r.message.contains("nginx['ssl_certificate']")
        !issuedCalled
        runner.commands.isEmpty()
        new File(certPath).text.contains('BEGIN CERTIFICATE')   // untouched
    }

    def "nginx using the configured paths passes the check"() {
        given:
        installCurrent(TestCerts.selfSignedPem('m.example.com', 3650))
        def conf = new File("$dir/site.conf")
        conf.text = "server {\n  ssl_certificate $certPath;\n  ssl_certificate_key $keyPath;\n}\n"
        expect:
        service().run(settings(nginxConfPath: conf.path)).status == RenewalResult.Status.RENEWED
    }

    def "self-signed default certificate is replaced"() {
        given:
        installCurrent(TestCerts.selfSignedPem('m.example.com', 3650))
        expect:
        service().run(settings()).status == RenewalResult.Status.RENEWED
    }

    def "certificate for a different name triggers renewal"() {
        given:
        installCurrent(TestCerts.leafPem(['other.example.com'], 80))
        expect:
        service().run(settings()).status == RenewalResult.Status.RENEWED
    }

    def "force renew replaces a healthy certificate"() {
        given:
        installCurrent(TestCerts.leafPem(['m.example.com'], 90, -10))
        expect:
        service().run(settings(forceRenew: true)).status == RenewalResult.Status.RENEWED
    }

    def "failed nginx restart rolls back to the old certificate and key"() {
        given:
        installCurrent(TestCerts.leafPem(['m.example.com'], 90, -85))
        def oldCert = new File(certPath).text
        runner.failing << 'restart nginx'
        when:
        def r = service().run(settings())
        then:
        r.status == RenewalResult.Status.FAILED
        new File(certPath).text == oldCert
        new File(keyPath).text == 'old-key'
        r.logText().contains('rolling back')
        r.logText().contains('Restored previous files')
    }

    def "nginx not serving the new cert is reported as failure"() {
        given:
        installCurrent(TestCerts.leafPem(['m.example.com'], 90, -85))
        when:
        def r = service(false).run(settings())
        then:
        r.status == RenewalResult.Status.FAILED
        r.message.contains('not serving')
    }

    def "nginx not answering after the restart rolls the old files back"() {
        given:
        installCurrent(TestCerts.leafPem(['m.example.com'], 90, -85))
        def before = new File(certPath).text
        def svc = new RenewalService(runner, { Instant.now() })
            .withIssuer({ s, r -> issued() } as RenewalService.Issuer)
            .withResponderFactory({ s, f -> new WebrootResponder(dir.toString(), f) } as RenewalService.ResponderFactory)
            .withProber({ s -> throw new IOException('connection refused') } as RenewalService.Prober)
        when:
        def r = svc.run(settings())
        then:
        r.status == RenewalResult.Status.FAILED
        r.message.contains('did not answer')
        r.message.contains('restored')
        new File(certPath).text == before
        new File(keyPath).text == 'old-key'
    }

    def "CA failure leaves the installed files untouched"() {
        given:
        installCurrent(TestCerts.leafPem(['m.example.com'], 90, -85))
        def before = new File(certPath).text
        when:
        def r = service(true, true).run(settings())
        then:
        r.status == RenewalResult.Status.FAILED
        r.message.contains('CA says no')
        new File(certPath).text == before
        new File(keyPath).text == 'old-key'
        runner.commands.isEmpty()
    }

    def "invalid settings fail cleanly"() {
        when:
        def r = service().run(settings(domains: '*.example.com'))
        then:
        r.status == RenewalResult.Status.FAILED
        r.message.contains('Wildcard')
    }

    def "sudo mode goes only through the confined helper (no raw sudo install/cp/rm) and never writes /etc directly"() {
        given:
        installCurrent(TestCerts.leafPem(['m.example.com'], 90, -85))
        when:
        def r = service().run(settings(useSudo: true))
        then:
        r.status == RenewalResult.Status.RENEWED
        def h = 'sudo -n /usr/local/sbin/morpheus-tls-helper'
        runner.commands.any { it == "$h write $keyPath 0600".toString() }
        runner.commands.any { it == "$h write $certPath 0644".toString() }
        runner.commands.any { it.startsWith("$h copy $certPath ") }
        // every sudo call is either the helper or morpheus-ctl
        runner.commands.findAll { it.startsWith('sudo') }.every { it.startsWith(h) || it.startsWith('sudo -n /opt/morpheus/bin/morpheus-ctl') }
    }

    def "renewal threshold is capped at a third of the certificate lifetime"() {
        expect:
        RenewalService.effectiveThresholdDays(CertInspector.parseChain(TestCerts.leafPem(['m.example.com'], lifetime).bytes)[0], 30) == expected
        where:
        lifetime | expected
        90       | 30
        45       | 15
        6        | 2
    }

    def "a 45 day certificate with 20 days left is not renewed yet, with 10 days left it is"() {
        given:
        installCurrent(TestCerts.leafPem(['m.example.com'], 45, -25))   // 45 day cert, issued 25 days ago -> 20 left
        expect:
        service().run(settings()).status == RenewalResult.Status.UP_TO_DATE
        when:
        installCurrent(TestCerts.leafPem(['m.example.com'], 45, -35))   // 45 day cert, issued 35 days ago -> 10 left
        then:
        service().run(settings()).status == RenewalResult.Status.RENEWED
    }

    def "failed first install restores the pre-install state (no cert, no key)"() {
        given:
        runner.failing << 'restart nginx'
        when:
        def r = service().run(settings())
        then:
        r.status == RenewalResult.Status.FAILED
        !new File(certPath).exists()
        !new File(keyPath).exists()
    }
}
