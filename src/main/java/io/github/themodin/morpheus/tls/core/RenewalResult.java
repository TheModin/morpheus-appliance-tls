package io.github.themodin.morpheus.tls.core;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Outcome of one run, plus the human-readable log that ends up in the Morpheus task output. */
public class RenewalResult {

    public enum Status {
        /** Dry run / certificate still valid long enough; nothing changed. */
        UP_TO_DATE,
        /** New certificate issued and installed. */
        RENEWED,
        /** Check-only run says a renewal is due. */
        RENEWAL_DUE,
        /** Something failed; see message. */
        FAILED
    }

    public Status status = Status.FAILED;
    public String message;
    public Instant notAfterBefore;
    public Instant notAfterAfter;
    private final List<String> log = new ArrayList<>();

    public void log(String line) {
        log.add(line);
    }

    public String logText() {
        return String.join("\n", log);
    }

    public boolean isSuccess() {
        return status != Status.FAILED;
    }
}
