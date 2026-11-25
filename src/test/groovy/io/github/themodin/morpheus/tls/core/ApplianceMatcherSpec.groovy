package io.github.themodin.morpheus.tls.core

import spock.lang.Specification

import static io.github.themodin.morpheus.tls.core.ApplianceMatcher.Candidate

class ApplianceMatcherSpec extends Specification {

    private static Candidate c(long id, String name, List<String> ips, boolean agent = true, String host = null) {
        new Candidate(id, name, host ?: name, ips, agent, 'ubuntu', 'provisioned')
    }

    def 'the server with the same IP is ranked first and recommended'() {
        given:
        def list = [c(1, 'hol-hvm01', ['10.10.20.122']), c(3, 'hol1-mamager', ['10.10.20.121']), c(5, 'hol1-worker', ['10.10.20.124'], false)]
        when:
        def ranked = ApplianceMatcher.rank(list, ['10.10.20.121', '172.17.0.1'] as Set, 'hol1-manager')
        then:
        ranked*.id == [3, 1, 5]
        ranked[0].score == 100
        ranked[0].reason.contains('10.10.20.121')
        ApplianceMatcher.recommended(ranked).id == 3
    }

    def 'a host name match alone ranks higher but is not recommended'() {
        given:
        def list = [c(1, 'other', ['10.0.0.5']), c(2, 'mgr', ['10.0.0.9'])]
        when:
        def ranked = ApplianceMatcher.rank(list, ['192.168.1.5'] as Set, 'mgr')
        then:
        ranked[0].id == 2
        ranked[0].score == 40
        ApplianceMatcher.recommended(ranked) == null
    }

    def 'a matching server without an agent is not recommended'() {
        when:
        def ranked = ApplianceMatcher.rank([c(7, 'm', ['10.1.1.1'], false)], ['10.1.1.1'] as Set, 'x')
        then:
        ranked[0].score == 100
        ApplianceMatcher.recommended(ranked) == null
    }

    def 'no match gives an alphabetical list and no recommendation'() {
        when:
        def ranked = ApplianceMatcher.rank([c(2, 'b', ['1.1.1.1']), c(1, 'A', ['2.2.2.2'])], ['9.9.9.9'] as Set, '')
        then:
        ranked*.id == [1, 2]
        ApplianceMatcher.recommended(ranked) == null
    }

    def 'missing values do not break matching'() {
        when:
        def ranked = ApplianceMatcher.rank([new Candidate(1, null, null, null, true, null, null)], [] as Set, null)
        then:
        ranked.size() == 1
        ranked[0].score == 0
    }
}
