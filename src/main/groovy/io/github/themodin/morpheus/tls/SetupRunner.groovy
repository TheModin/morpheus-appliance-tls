package io.github.themodin.morpheus.tls

import com.morpheusdata.core.MorpheusContext
import com.morpheusdata.model.ComputeServer
import com.morpheusdata.model.TaskResult
import groovy.util.logging.Slf4j
import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Runs the setup script on a Morpheus-managed server (the appliance itself) through Morpheus, in the background and one
 * at a time. The agent connection can drop while the script restarts nginx, so the result is a hint; the admin page
 * decides "done" from the setup checklist.
 */
@Slf4j
class SetupRunner {
    static final int MAX_OUTPUT = 20000
    private final MorpheusContext morpheus
    private final AtomicBoolean running = new AtomicBoolean(false)
    private volatile Map state = [running: false]

    SetupRunner(MorpheusContext morpheus) { this.morpheus = morpheus }

    Map getState() { new LinkedHashMap(state) }

    boolean isRunning() { running.get() }

    /** @return false when a run is already in progress */
    boolean start(ComputeServer server, String command, String mode, String who) {
        if (!running.compareAndSet(false, true)) return false
        state = [running: true, mode: mode, serverId: server.id, serverName: server.name, startedAt: Instant.now().toString(),
                 startedBy: who]
        Thread t = new Thread({ -> runNow(server, command, mode, who) } as Runnable, 'tls-setup-run')
        t.daemon = true
        t.start()
        return true
    }

    private void runNow(ComputeServer server, String command, String mode, String who) {
        Map base = new LinkedHashMap(state)
        try {
            log.info('Setup ({}) started on server {} by {}', mode, server.id, who)
            TaskResult r = morpheus.executeCommandOnServer(server, command).blockingGet()
            def parts = [r?.output, r?.data, r?.results, r?.error, r?.msg].findAll { it }.collect { it.toString() }
            String out = parts.join('\n')
            String debug = 'success=' + r?.success + ', exitCode=' + r?.exitCode + ', output=' + (r?.output?.length() ?: 0) +
                    ' chars, data=' + (r?.data == null ? 'null' : r.data.getClass().simpleName) + ', results=' +
                    (r?.results == null ? 'null' : r.results.size()) + ', msg=' + (r?.msg ?: '-')
            log.info('Setup run result: {}', debug)
            if (out.length() > MAX_OUTPUT) out = '... (truncated)\n' + out.substring(out.length() - MAX_OUTPUT)
            state = base + [running: false, finishedAt: Instant.now().toString(), success: r?.success == true,
                            exitCode: r?.exitCode, output: out, debug: debug]
        } catch (Throwable t) {
            log.warn('Setup run failed: {}', t.toString())
            state = base + [running: false, finishedAt: Instant.now().toString(), success: false, output: '',
                            error: t.toString()]
        } finally {
            running.set(false)
        }
    }
}
