package io.github.themodin.morpheus.tls.core

import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

class SetupCheckSpec extends Specification {

    @TempDir Path dir

    private static CommandRunner fake(Closure<CommandRunner.Result> f) {
        return { List<String> argv, byte[] stdin, int t -> f(argv) } as CommandRunner
    }

    private static CommandRunner.Result res(int code, String out = '') {
        new CommandRunner.Result(code, out.bytes, out)
    }

    private Path helperFile() {
        Path h = dir.resolve('helper')
        Files.writeString(h, '#!/bin/sh\n')
        h.toFile().setExecutable(true)
        h
    }

    private Path conf(String cert, String key) {
        Path c = dir.resolve('morpheus-ssl.conf')
        Files.writeString(c, "server {\n  ssl_certificate ${cert};\n  ssl_certificate_key ${key};\n}\n")
        c
    }

    def 'everything in place is ready'() {
        given:
        Path h = helperFile()
        def runner = fake { List<String> a ->
            a.contains('version') ? res(0, 'morpheus-tls-helper 1') : res(0)
        }
        when:
        def checks = SetupCheck.run(runner, h.toString(), conf('/c.pem', '/k.pem').toString(), '/c.pem', '/k.pem')
        then:
        SetupCheck.ready(checks)
        checks*.id == ['helper', 'sudoers', 'restart', 'nginx', 'files']
    }

    def 'missing helper fails the chain with a clear reason'() {
        when:
        def checks = SetupCheck.run(fake { res(1) }, dir.resolve('nope').toString(), 'none', '/c.pem', '/k.pem')
        def byId = checks.collectEntries { [(it.id): it] }
        then:
        !SetupCheck.ready(checks)
        byId.helper.ok == false
        byId.sudoers.detail == 'needs the helper'
        byId.files.ok == false
    }

    def 'outdated helper without the version operation is reported'() {
        given:
        Path h = helperFile()
        def runner = fake { List<String> a ->
            a.contains('version') ? res(2, "morpheus-tls-helper: unknown operation 'version'") : res(0)
        }
        when:
        def checks = SetupCheck.run(runner, h.toString(), 'none', '/c.pem', '/k.pem')
        def byId = checks.collectEntries { [(it.id): it] }
        then:
        byId.sudoers.ok == false
        byId.sudoers.detail.contains('outdated')
    }

    def 'sudo refusal is reported as missing sudoers rule'() {
        given:
        Path h = helperFile()
        def runner = fake { List<String> a -> res(1, 'sudo: a password is required') }
        when:
        def checks = SetupCheck.run(runner, h.toString(), 'none', '/c.pem', '/k.pem')
        def byId = checks.collectEntries { [(it.id): it] }
        then:
        byId.sudoers.ok == false
        byId.restart.ok == false
        !SetupCheck.ready(checks)
    }

    def 'nginx pointing at other files is not ready'() {
        given:
        Path h = helperFile()
        def runner = fake { List<String> a -> a.contains('version') ? res(0, 'morpheus-tls-helper 1') : res(0) }
        when:
        def checks = SetupCheck.run(runner, h.toString(), conf('/etc/morpheus/ssl/host.crt', '/etc/morpheus/ssl/host.key').toString(),
                '/etc/morpheus/ssl/cert.pem', '/etc/morpheus/ssl/key.pem')
        def byId = checks.collectEntries { [(it.id): it] }
        then:
        byId.nginx.ok == false
        byId.nginx.detail.contains('host.crt')
        !SetupCheck.ready(checks)
    }

    def 'missing certificate files are listed'() {
        given:
        Path h = helperFile()
        def runner = fake { List<String> a ->
            if (a.contains('version')) return res(0, 'morpheus-tls-helper 1')
            if (a.contains('exists')) return res(a.last() == '/c.pem' ? 0 : 1)
            return res(0)
        }
        when:
        def checks = SetupCheck.run(runner, h.toString(), 'none', '/c.pem', '/k.pem')
        def files = checks.find { it.id == 'files' }
        then:
        files.ok == false
        files.detail.contains('/k.pem')
        !files.detail.contains('/c.pem')
    }
}
