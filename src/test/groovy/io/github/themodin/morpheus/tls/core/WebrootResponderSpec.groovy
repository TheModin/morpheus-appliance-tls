package io.github.themodin.morpheus.tls.core

import spock.lang.Specification

import java.nio.file.Files

class WebrootResponderSpec extends Specification {

    def "writes and removes the challenge file under .well-known"() {
        given:
        def root = Files.createTempDirectory('webroot').toString()
        def r = new WebrootResponder(root, new HostFiles(false, new CommandRunner.Local()))
        when:
        r.publish('abcdefgh12345', 'abcdefgh12345.thumb')
        then:
        new File("$root/.well-known/acme-challenge/abcdefgh12345").text == 'abcdefgh12345.thumb'
        when:
        r.cleanup('abcdefgh12345')
        then:
        !new File("$root/.well-known/acme-challenge/abcdefgh12345").exists()
    }

    def "refuses tokens that could escape the webroot"() {
        given:
        def root = Files.createTempDirectory('webroot').toString()
        def r = new WebrootResponder(root, new HostFiles(false, new CommandRunner.Local()))
        when:
        r.publish('../../escape', 'x')
        then:
        thrown(IllegalArgumentException)
    }
}
