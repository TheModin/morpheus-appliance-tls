package io.github.themodin.morpheus.tls

import spock.lang.Specification

class RunLeaseSpec extends Specification {

    /** Shared fake store: both "nodes" see the same lease value. */
    static class MemStore extends SettingsStore {
        String value
        MemStore() { super(null) }
        @Override String readRaw(String key) { if (value == null) throw new NoSuchElementException(); value }
        @Override void writeRaw(String key, String v) { value = v }
    }

    def "only one node gets the lease while it is valid; the other gets it after expiry"() {
        given:
        def shared = new MemStore()
        def a = new RunLease(shared, 1000L)
        def b = new RunLease(shared, 1000L)
        expect:
        a.tryAcquire(10_000L)
        !b.tryAcquire(10_500L)
        a.tryAcquire(10_600L)       // the holder may renew its own lease
        b.tryAcquire(12_000L)       // expired -> b takes over
        !a.tryAcquire(12_100L)
    }

    def "a failing Cypher means no lease (the run is skipped, not duplicated)"() {
        given:
        def store = new MemStore() { @Override void writeRaw(String k, String v) { throw new IllegalStateException('down') } }
        expect:
        !new RunLease(store).tryAcquire()
    }
}
