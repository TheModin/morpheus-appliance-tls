package io.github.themodin.morpheus.tls.core

import java.nio.file.Files
import java.nio.file.Path

/** Generates throw-away CA-signed (or self-signed) certificates with the JDK's keytool. */
class TestCerts {

    static String keytool() {
        return new File(System.getProperty('java.home'), 'bin/keytool').absolutePath
    }

    static String run(List<String> args, String stdin = null) {
        Process p = new ProcessBuilder(([keytool()] + args).collect { it.toString() }).redirectErrorStream(true).start()
        if (stdin != null) { p.outputStream.write(stdin.bytes) }
        p.outputStream.close()
        String out = p.inputStream.text
        assert p.waitFor() == 0 : "keytool ${args} failed: ${out}"
        return out
    }

    /**
     * Returns PEM of a leaf cert for the given SANs, signed by a fresh test CA.
     * startOffsetDays: negative = certificate became valid that many days ago.
     */
    static String leafPem(List<String> sans, int validityDays, int startOffsetDays = 0) {
        Path dir = Files.createTempDirectory('testcerts')
        String ca = "$dir/ca.p12", leaf = "$dir/leaf.p12"
        run(['-genkeypair', '-alias', 'ca', '-keyalg', 'RSA', '-keysize', '2048', '-dname', 'CN=Test CA',
             '-ext', 'bc:c', '-validity', '3650', '-keystore', ca, '-storetype', 'PKCS12', '-storepass', 'changeit'])
        run(['-genkeypair', '-alias', 'leaf', '-keyalg', 'RSA', '-keysize', '2048', '-dname', "CN=${sans[0]}",
             '-keystore', leaf, '-storetype', 'PKCS12', '-storepass', 'changeit'])
        String csr = run(['-certreq', '-alias', 'leaf', '-keystore', leaf, '-storepass', 'changeit', '-rfc'])
        String san = 'san=' + sans.collect { "dns:$it" }.join(',')
        List<String> gen = ['-gencert', '-alias', 'ca', '-keystore', ca, '-storepass', 'changeit', '-rfc',
                            '-validity', "$validityDays", '-ext', san]
        if (startOffsetDays != 0) { gen += ['-startdate', "${startOffsetDays}d".toString()] }
        return run(gen, csr)
    }

    static String selfSignedPem(String cn, int validityDays) {
        Path dir = Files.createTempDirectory('testcerts')
        String ks = "$dir/s.p12"
        run(['-genkeypair', '-alias', 's', '-keyalg', 'RSA', '-keysize', '2048', '-dname', "CN=$cn",
             '-ext', "san=dns:$cn", '-validity', "$validityDays", '-keystore', ks, '-storetype', 'PKCS12',
             '-storepass', 'changeit'])
        return run(['-exportcert', '-alias', 's', '-keystore', ks, '-storepass', 'changeit', '-rfc'])
    }
}
