/*
 * Singleton registry that keeps headlessly-opened Version Tracking sessions alive
 * across separate MCP tool calls.
 */
package ghidrassistmcp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.feature.vt.api.main.VTSession;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Owns the long-lived consumer reference for Version Tracking sessions opened via MCP
 * without a human first opening Ghidra's Version Tracking GUI tool on them.
 *
 * Unlike {@link ghidra.program.model.listing.Program}, a VT session has no Ghidra-provided
 * "keep me open" service to lean on (Programs get that for free from {@code ProgramManager}
 * once {@code ProgramManager.openProgram()} is called) — {@code VTController} only tracks a
 * session already opened through the GUI. This registry fills that gap: it is itself the
 * consumer that keeps a {@link DomainObject} checked out, so a session opened via
 * {@code open_program}'s {@code open_vt} action survives across the many separate,
 * stateless MCP tool calls (eval_python, find_addr_in_version, etc.) that follow it.
 *
 * Deliberately does NOT wrap or construct a {@code VTController} — that class lives under
 * {@code ghidra.feature.vt.gui.plugin}, is built by {@code VTPlugin} against a live
 * {@code PluginTool}, and wires session-change listeners into Swing components. Every VT
 * match-querying helper this project actually uses ({@code _vt_index()} in the prelude)
 * only calls {@code VTSession.getMatchSets()}/{@code getMatches()}, so a bare
 * {@link VTSession} reference is all that's ever needed.
 */
public final class VtSessionRegistry {

    /** Sessions opened via this registry pin more heap/DB handles than a typical Program;
     * cap how many an agent can leave open without an explicit close. */
    private static final int MAX_OPEN_SESSIONS = 4;

    private static volatile VtSessionRegistry instance;
    private static final Object LOCK = new Object();

    // Insertion-ordered so eviction can drop the least-recently-opened entry.
    private final Map<String, VTSession> sessionsByPath = new LinkedHashMap<>();

    private VtSessionRegistry() {}

    public static VtSessionRegistry getInstance() {
        if (instance == null) {
            synchronized (LOCK) {
                if (instance == null) {
                    instance = new VtSessionRegistry();
                }
            }
        }
        return instance;
    }

    /**
     * Open (or return the already-open) VT session for a project domain file.
     *
     * @throws IllegalArgumentException if the file is not a Version Tracking session
     * @throws Exception if the underlying Ghidra open fails (locked, missing, etc.)
     */
    public synchronized VTSession open(DomainFile file) throws Exception {
        String path = file.getPathname();
        VTSession existing = sessionsByPath.get(path);
        if (existing != null) {
            return existing;
        }

        DomainObject domainObject = file.getDomainObject(this, false, false, TaskMonitor.DUMMY);
        if (!(domainObject instanceof VTSession session)) {
            String contentType = file.getContentType();
            domainObject.release(this);
            throw new IllegalArgumentException(
                "'" + path + "' is not a Version Tracking session (content type: " + contentType + ")");
        }

        if (sessionsByPath.size() >= MAX_OPEN_SESSIONS) {
            String oldestPath = sessionsByPath.keySet().iterator().next();
            Msg.info(this, "VT session cap (" + MAX_OPEN_SESSIONS + ") reached, evicting: " + oldestPath);
            close(oldestPath);
        }

        sessionsByPath.put(path, session);
        return session;
    }

    /** Release and forget a headlessly-opened session. No-op if not open here (e.g. it was
     * only ever opened via the GUI). Does not affect any other consumer's hold on it. */
    public synchronized boolean close(String pathname) {
        VTSession session = sessionsByPath.remove(pathname);
        if (session == null) {
            return false;
        }
        try {
            ((DomainObject) session).release(this);
        } catch (Exception e) {
            Msg.error(this, "Error releasing VT session: " + pathname, e);
        }
        return true;
    }

    /** All sessions this registry currently holds open, for merging into the prelude's
     * get_vt_sessions() alongside any GUI-opened ones. */
    public synchronized List<VTSession> getSessions() {
        return new ArrayList<>(sessionsByPath.values());
    }

    public synchronized Map<String, VTSession> getOpenSessions() {
        return new LinkedHashMap<>(sessionsByPath);
    }

    /** Release every session this registry holds — called when the last CodeBrowser tool
     * unregisters (see {@link GhidrAssistMCPManager#unregisterTool}), the one reliable
     * "nothing is using this anymore" signal available to a stateless MCP server. */
    public synchronized void releaseAll() {
        for (String path : new ArrayList<>(sessionsByPath.keySet())) {
            close(path);
        }
    }
}
