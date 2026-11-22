package io.github.themodin.morpheus.tls.core

import spock.lang.Requires
import spock.lang.Shared
import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant

/**
 * Real ACME round trip against a local Pebble test CA (https://github.com/letsencrypt/pebble), including a real
 * HTTP-01 validation answered by StandaloneResponder. Only runs when PEBBLE_DIR points at a directory with the
 * pebble + pebble-challtestsrv binaries and a checkout of the pebble repo in PEBBLE_DIR/src.
 */
@Requires({ System.getenv('PEBBLE_DIR') })
class PebbleEndToEndSpec extends Specification {

    @Shared Process pebble, challtest
    @Shared Path work = Files.createTempDirectory('pebble-e2e')

    static boolean portOpen(int port) {
        try { new Socket('127.0.0.1', port).close(); return true } catch (IOException e) { return false }
    }

    static void waitForPort(int port, int seconds = 30) {
        long end = System.currentTimeMillis() + seconds * 1000
        while (!portOpen(port)) {
            assert System.currentTimeMillis() < end : "port $port never opened"
            Thread.sleep(200)
        }
    }

    def setupSpec() {
        String dir = System.getenv('PEBBLE_DIR')
        // trust Pebble's TLS certificate (minica) for acme4j's HTTPS calls
        def cf = java.security.cert.CertificateFactory.getInstance('X.509')
        def minica = new File("$dir/src/test/certs/pebble.minica.pem").withInputStream { cf.generateCertificate(it) }
        def ks = java.security.KeyStore.getInstance('PKCS12')
        ks.load(null, null)
        ks.setCertificateEntry('minica', minica)
        def tmf = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.defaultAlgorithm)
        tmf.init(ks)
        def ctx = javax.net.ssl.SSLContext.getInstance('TLS')
        ctx.init(null, tmf.trustManagers, null)
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(ctx.socketFactory)
        javax.net.ssl.SSLContext.setDefault(ctx)   // acme4j 3 uses java.net.http.HttpClient

        challtest = new ProcessBuilder("$dir/pebble-challtestsrv-linux-amd64/linux/amd64/pebble-challtestsrv",
                '-http01', '', '-https01', '', '-tlsalpn01', '', '-doh', '', '-dnsserver', ':8053', '-management', ':8055')
                .redirectErrorStream(true).redirectOutput(new File("$work/challtest.log")).start()
        waitForPort(8055)
        def pb = new ProcessBuilder("$dir/pebble-linux-amd64/linux/amd64/pebble", '-config',
                'test/config/pebble-config.json', '-dnsserver', '127.0.0.1:8053')
                .directory(new File("$dir/src")).redirectErrorStream(true).redirectOutput(new File("$work/pebble.log"))
        pb.environment().putAll([PEBBLE_VA_NOSLEEP: '1', PEBBLE_WFE_NONCEREJECT: '0'])
        pebble = pb.start()
        waitForPort(14000)

        // resolve our test domain to localhost
        def c = new URL('http://127.0.0.1:8055/add-a').openConnection()
        c.requestMethod = 'POST'; c.doOutput = true
        c.outputStream.write('{"host":"m.test.local","addresses":["127.0.0.1"]}'.bytes)
        assert c.responseCode == 200
    }

    def cleanupSpec() {
        pebble?.destroyForcibly()
        challtest?.destroyForcibly()
    }

    def "issues, installs and verifies a certificate through real ACME http-01 (standalone responder)"() {
        given:
        String certPath = "$work/cert.pem"
        String keyPath = "$work/key.pem"
        String acct = "$work/acct.pem"
        def s = RenewalSettings.fromOptions([challengeType: 'http-01', domains: 'm.test.local', contactEmail: 'ops@test.local', useSudo: 'false',
                                             acmeDirectoryOverride: 'https://localhost:14000/dir', httpPort: '5002', renewBeforeDays: '1',
                                             certPath: certPath, keyPath: keyPath, accountKeyPath: acct,
                                             restartCommand: 'true', nginxConfPath: 'none', backupDir: "$work/backup".toString(),
                                             verifyAfterInstall: 'true', verifyTimeoutSeconds: '2'])
        def svc = new RenewalService(new CommandRunner.Local(), { Instant.now() })
                .withProber({ st -> CertInspector.parseChain(new File(certPath).bytes)[0] } as RenewalService.Prober)

        when:
        def r = svc.run(s)
        println r.logText()

        then:
        r.status == RenewalResult.Status.RENEWED
        def chain = CertInspector.parseChain(new File(certPath).bytes)
        chain.size() >= 2                                   // leaf + issuer
        CertInspector.dnsNames(chain[0]) == ['m.test.local']
        new File(keyPath).text.contains('PRIVATE KEY')
        new File(acct).text.contains('PRIVATE KEY')

        when: 'a second run right after finds a healthy certificate and does nothing'
        def again = svc.run(s)
        then:
        again.status == RenewalResult.Status.UP_TO_DATE
    }

    def "issues a certificate through real ACME dns-01 (TXT published via the challenge test server)"() {
        given:
        String certPath = "$work/dns-cert.pem"
        String keyPath = "$work/dns-key.pem"
        List<String> ops = []
        def mgmt = { String path, String json ->
            def c = new URL("http://127.0.0.1:8055/$path").openConnection()
            c.requestMethod = 'POST'; c.doOutput = true
            c.outputStream.write(json.bytes)
            assert c.responseCode == 200
        }
        def provider = new FakeDns(
            add   : { String n, String v -> ops << "add $n"; mgmt('set-txt', JsonOut.of(host: n + '.', value: v)); 'h' },
            remove: { String n, String v, String h -> ops << "rm $n"; mgmt('clear-txt', JsonOut.of(host: n + '.')) })
        def s = RenewalSettings.fromOptions([domains: 'm.test.local, *.test.local', contactEmail: 'ops@test.local', useSudo: 'false',
                                             acmeDirectoryOverride: 'https://localhost:14000/dir', renewBeforeDays: '1',
                                             cloudflareApiToken: 'unused', dnsCheckUrl: 'none',
                                             certPath: certPath, keyPath: keyPath, accountKeyPath: "$work/dns-acct.pem",
                                             restartCommand: 'true', nginxConfPath: 'none', backupDir: "$work/backup".toString(),
                                             verifyAfterInstall: 'true', verifyTimeoutSeconds: '2'].collectEntries { k, v -> [k, v.toString()] })
        def svc = new RenewalService(new CommandRunner.Local(), { Instant.now() })
                .withResponderFactory({ st, f -> new DnsResponder(provider, null, 1, { }) } as RenewalService.ResponderFactory)
                .withProber({ st -> CertInspector.parseChain(new File(certPath).bytes)[0] } as RenewalService.Prober)

        when:
        def r = svc.run(s)
        println r.logText()

        then:
        r.status == RenewalResult.Status.RENEWED
        CertInspector.dnsNames(CertInspector.parseChain(new File(certPath).bytes)[0]).sort() == ['*.test.local', 'm.test.local']
        ops.count { it.startsWith('add') } == 2      // one TXT per authorization (name + wildcard)
        ops.count { it.startsWith('rm') } == 2       // and both removed again
    }
}
