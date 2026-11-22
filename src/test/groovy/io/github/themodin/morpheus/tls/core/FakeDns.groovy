package io.github.themodin.morpheus.tls.core

/** Closure-driven DnsProvider (Groovy map coercion cannot proxy interfaces that have default methods). */
class FakeDns implements DnsProvider {
    Closure add = { n, v -> 'h' }
    Closure remove = { n, v, h -> }
    @Override String addTxt(String n, String v) { add.call(n, v) as String }
    @Override void removeTxt(String n, String v, String h) { remove.call(n, v, h) }
}
