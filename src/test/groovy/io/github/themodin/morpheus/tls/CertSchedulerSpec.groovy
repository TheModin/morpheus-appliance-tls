package io.github.themodin.morpheus.tls

import spock.lang.Specification

class CertSchedulerSpec extends Specification {

    static class FakeStore extends SettingsStore {
        Map<String, String> settings = [:]
        boolean unreadable = false
        FakeStore() { super(null) }
        @Override Map<String, String> load() { new LinkedHashMap(settings) }
        @Override boolean isSettingsUnreadable() { unreadable }
    }

    static class FakeRunner extends RenewalRunner {
        List started = []
        FakeRunner(SettingsStore s) { super(s) }
        @Override boolean start(String mode, String trigger) { started << [mode, trigger]; true }
    }

    static class FixedLease extends RunLease {
        boolean grant
        FixedLease(SettingsStore s, boolean grant) { super(s); this.grant = grant }
        @Override boolean tryAcquire(long now) { grant }
    }

    def "auto-renew on and lease granted -> scheduled renew starts"() {
        given:
        def st = new FakeStore(settings: [autoRenew: 'true'])
        def runner = new FakeRunner(st)
        when:
        new CertScheduler(st, runner, new FixedLease(st, true)).tick()
        then:
        runner.started == [['renew', 'schedule']]
    }

    def "auto-renew off -> nothing starts"() {
        given:
        def st = new FakeStore(settings: [autoRenew: 'false'])
        def runner = new FakeRunner(st)
        when:
        new CertScheduler(st, runner, new FixedLease(st, true)).tick()
        then:
        runner.started.isEmpty()
    }

    def "another node holds the lease -> nothing starts"() {
        given:
        def st = new FakeStore(settings: [autoRenew: 'true'])
        def runner = new FakeRunner(st)
        when:
        new CertScheduler(st, runner, new FixedLease(st, false)).tick()
        then:
        runner.started.isEmpty()
    }

    def "unreadable settings -> no run, no exception"() {
        given:
        def st = new FakeStore(settings: [autoRenew: 'true'], unreadable: true)
        def runner = new FakeRunner(st)
        when:
        new CertScheduler(st, runner, new FixedLease(st, true)).tick()
        then:
        runner.started.isEmpty()
        noExceptionThrown()
    }
}
