package io.github.themodin.morpheus.tls.core

import spock.lang.Shared
import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.Path

/**
 * Runs the real deploy/morpheus-tls-helper script through HostFiles. A fake "sudo" on PATH just drops "-n" and
 * executes the helper as the current user, and the allowed prefix is redirected to a temp dir (the helper only
 * honours that override when it is NOT root).
 */
class HostFilesSpec extends Specification {

    @Shared Path work = Files.createTempDirectory('hostfiles')
    @Shared String allowed = "$work/etc-morpheus"
    @Shared String helper = new File('deploy/morpheus-tls-helper').absolutePath
    @Shared HostFiles files
    @Shared Map helperEnv
    static final String PEM = '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n'

    def setupSpec() {
        new File(allowed).mkdirs()
        def bin = new File("$work/bin"); bin.mkdirs()
        def sudo = new File(bin, 'sudo')
        sudo.text = '#!/bin/sh\nif [ "$1" = "-n" ]; then shift; fi\nexec "$@"\n'
        sudo.executable = true
        def env = [PATH: "$bin:${System.getenv('PATH')}".toString(), LE_HELPER_ALLOWED_PREFIXES: "$allowed/".toString(),
                   LE_HELPER_BACKUP_DIR: "$allowed/ssl/backup".toString()]
        helperEnv = env
        files = new HostFiles(true, new CommandRunner.Local(env), helper)
    }

    def "write sets mode, copy/exists/delete work, content is passed on stdin"() {
        when:
        files.write("$allowed/ssl/key.pem", PEM.bytes, '0600')
        then:
        new File("$allowed/ssl/key.pem").text == PEM
        Files.getPosixFilePermissions(new File("$allowed/ssl/key.pem").toPath()) == ([java.nio.file.attribute.PosixFilePermission.OWNER_READ, java.nio.file.attribute.PosixFilePermission.OWNER_WRITE] as Set)
        files.exists("$allowed/ssl/key.pem")
        when:
        files.copy("$allowed/ssl/key.pem", "$allowed/ssl/backup/20260101000000/key.pem")
        then:
        new File("$allowed/ssl/backup/20260101000000/key.pem").text == PEM
        when:
        files.delete("$allowed/ssl/backup/20260101000000/key.pem")
        then:
        !new File("$allowed/ssl/backup/20260101000000/key.pem").exists()
        !files.exists("$allowed/ssl/backup/20260101000000/key.pem")
    }

    def "reading a missing file returns null"() {
        expect:
        files.read("$allowed/ssl/nope.pem") == null
    }

    def "no temp files are left behind after a write"() {
        when:
        files.write("$allowed/clean/a.pem", PEM.bytes, '0644')
        then:
        new File("$allowed/clean").list().toList() == ['a.pem']
    }

    def "paths outside the allowed prefix are refused: #why"() {
        when:
        files.write(path, PEM.bytes, '0644')
        then:
        def e = thrown(IOException)
        e.message.contains('not allowed') || e.message.contains("'..'") || e.message.contains('absolute')
        where:
        why                    | path
        'elsewhere'            | "${System.getProperty('java.io.tmpdir')}/le-outside.pem"
        'dot-dot traversal'    | "/x/../etc/passwd"
        'relative path'        | 'relative.pem'
    }

    def "a symlink inside the allowed area cannot be used to escape it"() {
        given:
        def outside = Files.createTempDirectory('outside')
        Files.createSymbolicLink(new File("$allowed/link").toPath(), outside)
        when:
        files.write("$allowed/link/pwned.pem", PEM.bytes, '0644')
        then:
        thrown(IOException)
        !new File(outside.toFile(), 'pwned.pem').exists()
    }

    def "unsafe modes are refused"() {
        when:
        files.write("$allowed/m.pem", PEM.bytes, '4755')
        then:
        def e = thrown(IOException)
        e.message.contains('mode not allowed')
    }

    def "only certificate and key files are accessible: #name"() {
        when:
        files.write("$allowed/$name", PEM.bytes, '0644')
        then:
        def e = thrown(IOException)
        e.message.contains('only .pem')
        where:
        name << ['morpheus.rb', 'morpheus-secrets.json', 'host-ssl.conf', 'ssl/x.sh']
    }

    def "writes must be PEM data"() {
        when:
        files.write("$allowed/ssl/notpem.pem", "#!/bin/sh\nrm -rf /\n".bytes, '0644')
        then:
        def e = thrown(IOException)
        e.message.contains('not PEM')
        !new File("$allowed/ssl/notpem.pem").exists()
    }

    def "the helper itself refuses to read outside the allowed area or non-certificate files"() {
        given:
        new File("$allowed/morpheus-secrets.json").text = '{"secret":1}'
        expect:
        !new CommandRunner.Local(helperEnv).run([helper, 'read', path], null, 10).ok()
        where:
        path << ['/etc/passwd', "$work/etc-morpheus/morpheus-secrets.json".toString()]
    }

    def "prune keeps the newest N timestamped backup directories and ignores everything else"() {
        given:
        def b = new File("$allowed/ssl/backup")
        b.deleteDir()
        ['20260101000000', '20260102000000', '20260103000000', '20260104000000', '20260105000000', '20260106000000', '20260107000000'].each {
            files.write("$b/$it/cert.pem", PEM.bytes, '0644')
        }
        new File(b, 'not-a-backup').mkdirs()
        when:
        files.pruneBackups(b.path, 5)
        then:
        b.list().toList().sort() == ['20260103000000', '20260104000000', '20260105000000', '20260106000000', '20260107000000', 'not-a-backup']
    }

    def "prune refuses nonsense counts"() {
        when:
        files.pruneBackups("$allowed/ssl/backup", 0)
        then:
        thrown(IOException)
    }
}
