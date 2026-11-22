package io.github.themodin.morpheus.tls.core;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.TokenChallenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.util.function.Consumer;

/** Talks ACME (RFC 8555) to Let's Encrypt using acme4j (DNS-01 or HTTP-01). */
public class AcmeIssuer {

    public static final class Issued {
        public final String fullChainPem;
        public final String privateKeyPem;

        Issued(String fullChainPem, String privateKeyPem) {
            this.fullChainPem = fullChainPem;
            this.privateKeyPem = privateKeyPem;
        }
    }

    private final HostFiles files;
    private final Consumer<String> log;

    public AcmeIssuer(HostFiles files, Consumer<String> log) {
        this.files = files;
        this.log = log;
    }

    /** Loads the ACME account key from disk, or creates and stores a new one. */
    KeyPair loadOrCreateAccountKey(String path) throws IOException {
        byte[] existing = files.read(path);
        if (existing != null && existing.length > 0) {
            return KeyPairUtils.readKeyPair(new StringReader(new String(existing, StandardCharsets.US_ASCII)));
        }
        log.accept("No ACME account key at " + path + " - creating a new one");
        KeyPair kp = KeyPairUtils.createKeyPair(4096);
        StringWriter w = new StringWriter();
        KeyPairUtils.writeKeyPair(kp, w);
        files.write(path, w.toString().getBytes(StandardCharsets.US_ASCII), "0600");
        return kp;
    }

    /**
     * Builds the session with an explicitly chosen provider. Session(String) relies on ServiceLoader and the thread
     * context class loader, which inside the Morpheus appliance's plugin class loader finds no provider at all
     * ("No ACME provider found for acme://...").
     */
    static Session sessionFor(String directory) {
        java.net.URI uri = java.net.URI.create(directory);
        org.shredzone.acme4j.provider.AcmeProvider p = "acme".equals(uri.getScheme())
                ? new org.shredzone.acme4j.provider.letsencrypt.LetsEncryptAcmeProvider()
                : new org.shredzone.acme4j.provider.GenericAcmeProvider();
        return new Session(uri, p);
    }

    public Issued issue(RenewalSettings s, ChallengeResponder responder)
            throws IOException, AcmeException, InterruptedException {
        KeyPair accountKey = loadOrCreateAccountKey(s.accountKeyPath);
        String directory = s.acmeDirectory();
        log.accept("ACME directory: " + directory);
        Session session = sessionFor(directory);

        AccountBuilder ab = new AccountBuilder().agreeToTermsOfService().useKeyPair(accountKey);
        if (s.contactEmail != null) {
            ab.addEmail(s.contactEmail);
        }
        Account account = ab.create(session);
        log.accept("ACME account: " + account.getLocation());

        Order order = account.newOrder().domains(s.domains).create();
        for (Authorization auth : order.getAuthorizations()) {
            String domain = auth.getIdentifier().getDomain();
            if (auth.getStatus() == Status.VALID) {
                log.accept("Authorization for " + domain + " already valid");
                continue;
            }
            String type = responder.challengeType();
            TokenChallenge challenge = auth.findChallenge(type).filter(c -> c instanceof TokenChallenge).map(c -> (TokenChallenge) c)
                    .orElseThrow(() -> new AcmeException("CA offered no " + type + " challenge for " + domain));
            String token = challenge.getJSON().get("token").asString();
            responder.publish(domain, token, challenge.getAuthorization());
            try {
                log.accept("Triggering " + type + " validation for " + domain);
                challenge.trigger();
                auth.waitForStatus(java.util.EnumSet.of(Status.VALID, Status.INVALID), Duration.ofSeconds(120));
                if (auth.getStatus() != Status.VALID) {
                    String why = challenge.getError().map(Object::toString).orElse("no detail from CA");
                    throw new AcmeException("Validation of " + domain + " failed: " + why);
                }
                log.accept("Validated " + domain);
            } finally {
                responder.cleanup(domain, token);
            }
        }

        order.waitUntilReady(Duration.ofSeconds(120));

        KeyPair domainKey = KeyPairUtils.createKeyPair(2048);
        CSRBuilder csr = new CSRBuilder();
        csr.addDomains(s.domains);
        csr.sign(domainKey);
        order.execute(csr.getEncoded());
        order.waitForCompletion(Duration.ofSeconds(120));
        if (order.getStatus() != Status.VALID) {
            throw new AcmeException("Order did not become valid, status=" + order.getStatus());
        }

        StringWriter chain = new StringWriter();
        order.getCertificate().writeCertificate(chain);
        StringWriter key = new StringWriter();
        KeyPairUtils.writeKeyPair(domainKey, key);
        return new Issued(chain.toString(), key.toString());
    }
}
