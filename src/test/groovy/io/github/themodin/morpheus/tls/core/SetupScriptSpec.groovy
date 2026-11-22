package io.github.themodin.morpheus.tls.core

import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.Path

/** The setup script that the admin page hands out must be complete and syntactically valid bash. */
class SetupScriptSpec extends Specification {

    private String script() {
        def is = getClass().classLoader.getResourceAsStream('setup/morpheus-tls-setup.sh')
        assert is != null: 'setup/morpheus-tls-setup.sh is not on the classpath'
        new String(is.readAllBytes(), 'UTF-8')
    }

    def 'script embeds the helper and the sudoers template, with no placeholder left'() {
        when:
        String s = script()
        then:
        !s.contains('#@@')
        s.contains('HELPER_VERSION=1')
        s.contains('NOPASSWD: /usr/local/sbin/morpheus-tls-helper')
        s.contains('NOPASSWD: /opt/morpheus/bin/morpheus-ctl restart nginx')
        s.startsWith('#!/bin/bash')
    }

    def 'script is valid bash'() {
        given:
        Path f = Files.createTempFile('le-setup', '.sh')
        Files.writeString(f, script())
        when:
        def syntax = new ProcessBuilder('bash', '-n', f.toString()).redirectErrorStream(true).start()
        String synOut = syntax.inputStream.text
        int synRc = syntax.waitFor()
        then:
        synRc == 0
        synOut.trim().isEmpty()
        cleanup:
        Files.deleteIfExists(f)
    }

    def 'embedded helper is the same file as deploy/morpheus-tls-helper'() {
        given:
        String helper = new File('deploy/morpheus-tls-helper').text.stripTrailing()
        expect:
        script().contains(helper)
    }

    def 'embedded sudoers grants exactly two commands'() {
        given:
        String s = script()
        int a = s.indexOf("cat <<'LE_EMBEDDED_SUDOERS_EOF'")
        String body = s.substring(a, s.indexOf('\nLE_EMBEDDED_SUDOERS_EOF', a))
        when:
        def rules = body.readLines().findAll { it.startsWith('morpheus-app ') }
        then:
        rules.size() == 2
        rules.every { it.contains('NOPASSWD:') && !it.contains('ALL=(ALL)') }
    }
}
