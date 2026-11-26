package io.github.themodin.morpheus.tls

import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.core.cypher.MorpheusCypherService
import io.reactivex.rxjava3.core.Single
import spock.lang.Specification

class SettingsStoreSpec extends Specification {

    /** In-memory Cypher; reads can be switched to fail. */
    static class FakeCypher {
        Map<String, String> data = [:]
        boolean failReads = false
        MorpheusCypherService service = [
            read : { access, key ->
                if (failReads) return Single.error(new IllegalStateException('cypher unavailable'))
                String v = data[key]
                return v == null ? Single.error(new NoSuchElementException('no value')) : Single.just(v)
            },
            write: { access, key, value, lease -> data[key] = value; return Single.just(value) }
        ] as MorpheusCypherService
    }

    FakeCypher cy = new FakeCypher()
    SettingsStore store

    def setup() {
        MorpheusContext ctx = [getCypher: { -> cy.service }] as MorpheusContext
        store = new SettingsStore(ctx)
    }

    def "first save needs the token, because stored settings could not be read"() {
        when:
        store.save([domains: 'a.example.com'])
        then:
        thrown(SettingsStore.SettingsUnavailableException)
        cy.data.isEmpty()
    }

    def "first save with a token works and the token is kept by later token-less saves"() {
        when:
        store.save([domains: 'a.example.com', cloudflareApiToken: 'tok123'])
        store.save([domains: 'b.example.com', cloudflareApiToken: ''])
        then:
        store.load().domains == 'b.example.com'
        store.load().cloudflareApiToken == 'tok123'
    }

    def "a failed read does not let a token-less save wipe the stored token"() {
        given:
        store.save([domains: 'a.example.com', cloudflareApiToken: 'tok123'])
        cy.failReads = true
        when:
        store.save([domains: 'b.example.com', cloudflareApiToken: ''])
        then: 'the last known copy is used, so the token survives'
        cy.data[SettingsStore.SETTINGS_KEY].contains('tok123')
        store.load().cloudflareApiToken == 'tok123'
    }

    def "a restarted plugin whose Cypher read fails refuses a token-less save and keeps the stored data"() {
        given:
        cy.data[SettingsStore.SETTINGS_KEY] = '{"domains":"a.example.com","cloudflareApiToken":"tok123"}'
        cy.failReads = true
        when:
        store.save([domains: 'b.example.com', cloudflareApiToken: ''])
        then:
        thrown(SettingsStore.SettingsUnavailableException)
        cy.data[SettingsStore.SETTINGS_KEY].contains('tok123')
        cy.data[SettingsStore.SETTINGS_KEY].contains('a.example.com')
    }

    def "masked token placeholder counts as no token"() {
        given:
        cy.failReads = true
        when:
        store.save([domains: 'x.example.com', cloudflareApiToken: '*****'])
        then:
        thrown(SettingsStore.SettingsUnavailableException)
    }
}
