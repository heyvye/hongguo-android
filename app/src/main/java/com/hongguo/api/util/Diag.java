// SPDX-License-Identifier: GPL-3.0-only
// Diagnostic logging for the playback-recovery experiment. Unlike {@link Log}, this writes
// the concrete outcome (host, status, byte count, exception class) so a USB session can tell
// why the playback endpoints answer with an empty body. It never prints response bodies,
// signed query strings or credentials.
//
// Logcat output is not reliable on every OEM build, so the same lines are appended to a
// small file in the app's private directory; `adb shell run-as com.hongguo.android cat
// files/diag.log` reads it back without root.
package com.hongguo.api.util;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

public final class Diag {
    private Diag() {}

    private static final Object LOCK = new Object();
    private static final long MAX_BYTES = 512 * 1024;
    private static volatile File target;

    /** Called once from Application with the app's private files directory. */
    public static void init(File dir) {
        if (dir != null) target = new File(dir, "diag.log");
    }

    public static void log(String message) {
        String line = System.currentTimeMillis() + "  " + message;
        System.err.println("HGMiniDiag " + line);
        File file = target;
        if (file == null) return;
        synchronized (LOCK) {
            try {
                if (file.length() > MAX_BYTES) file.delete();
                try (FileOutputStream out = new FileOutputStream(file, true)) {
                    out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
                }
            } catch (Exception ignored) {
                // Diagnostics must never break playback.
            }
        }
    }

    /** Host + path only: query strings carry signed timestamps and identities. */
    public static String endpoint(String url) {
        if (url == null) return "(null)";
        try {
            java.net.URI uri = java.net.URI.create(url);
            String host = uri.getHost() == null ? "?" : uri.getHost();
            String path = uri.getPath() == null ? "/" : uri.getPath();
            return host + path;
        } catch (Exception ignored) {
            return "(unparsable)";
        }
    }
}
