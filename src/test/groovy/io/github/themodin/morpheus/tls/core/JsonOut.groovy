package io.github.themodin.morpheus.tls.core

class JsonOut {
    static String of(Map m) {
        '{' + m.collect { k, v -> '"' + k + '":"' + v.toString().replace('\\', '\\\\').replace('"', '\\"') + '"' }.join(',') + '}'
    }
}
