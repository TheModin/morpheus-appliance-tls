package io.github.themodin.morpheus.tls

import groovy.util.logging.Slf4j
import java.security.MessageDigest
import java.util.zip.GZIPOutputStream

/**
 * The root-side setup script (embedded in the jar) and the one-line command that carries it. The script text is fixed;
 * only the argument (install, optionally --dry-run) varies, so no user input ever reaches a root shell.
 */
@Slf4j
class SetupScript {
    private final ClassLoader loader
    private volatile String text

    SetupScript(ClassLoader loader) { this.loader = loader }

    /** @return the script, or null when this build does not contain it */
    String getScript() {
        if (text == null) {
            try {
                InputStream is = loader.getResourceAsStream('setup/morpheus-tls-setup.sh')
                text = is == null ? null : new String(is.readAllBytes(), 'UTF-8')
            } catch (Throwable t) {
                log.warn('Could not read the setup script: {}', t.toString())
            }
        }
        return text
    }

    String getSha256() {
        String s = script
        s == null ? null : MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString()
    }

    int getSize() { script == null ? 0 : script.getBytes('UTF-8').length }

    /** Shell command that unpacks the script to a temp file and runs it with sudo. args: install | status | uninstall | install --dry-run */
    String command(String args = 'install') {
        String s = script
        if (s == null) return null
        if (!(args in ['install', 'install --dry-run', 'status', 'uninstall'])) {
            throw new IllegalArgumentException('unsupported setup argument')
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream()
        GZIPOutputStream gz = new GZIPOutputStream(bos)
        gz.write(s.getBytes('UTF-8')); gz.close()
        String b64 = Base64.encoder.encodeToString(bos.toByteArray())
        return "f=\$(mktemp) && echo '" + b64 + "' | base64 -d | gunzip > \"\$f\" && sudo bash \"\$f\" " + args + "; rc=\$?; rm -f \"\$f\"; exit \$rc"
    }
}
