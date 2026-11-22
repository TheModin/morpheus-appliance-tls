import io.github.themodin.morpheus.tls.core.*;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Runs one full renewal against a local Pebble using ONLY the shadow jar on the classpath, proving the bundled
 * dependencies (acme4j, BouncyCastle, jose4j) are complete. Usage: java -cp plugin.jar SmokeShadowJar.java <minica.pem>
 */
public class SmokeShadowJar {
    public static void main(String[] args) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        try (FileInputStream in = new FileInputStream(args[0])) {
            ks.setCertificateEntry("minica", CertificateFactory.getInstance("X.509").generateCertificate(in));
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        SSLContext.setDefault(ctx);

        File dir = Files.createTempDirectory("smoke").toFile();
        Map<String, String> o = new HashMap<>();
        o.put("domains", "m.test.local");
        o.put("contactEmail", "ops@test.local");
        o.put("useSudo", "false");
        o.put("acmeDirectoryOverride", "https://localhost:14000/dir");
        o.put("httpPort", "5002");
        o.put("renewBeforeDays", "1");
        o.put("certPath", dir + "/cert.pem");
        o.put("keyPath", dir + "/key.pem");
        o.put("accountKeyPath", dir + "/acct.pem");
        o.put("morpheusRbPath", dir + "/morpheus.rb");
        o.put("restartCommand", "true");
        o.put("reconfigureCommand", "true");
        o.put("verifyAfterInstall", "false");
        RenewalResult r = new RenewalService(new CommandRunner.Local(), Instant::now).run(RenewalSettings.fromOptions(o));
        System.out.println(r.logText());
        System.out.println("STATUS=" + r.status);
        System.exit(r.isSuccess() ? 0 : 1);
    }
}
