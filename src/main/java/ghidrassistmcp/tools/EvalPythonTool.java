/*
 * MCP tool for evaluating arbitrary Python 3 code via GhidraScript (PyGhidra).
 *
 * The eval prelude (ghidra/dbg/reng helpers) lives in:
 *   src/main/resources/ghidrassist_prelude.py
 * Edit that file directly — no Java string escaping needed.
 */
package ghidrassistmcp.tools;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Tool to execute arbitrary Python code.
 * Requires pyghidra.bat (Python 3) or falls back to Jython 2.7.
 * Prelude is loaded from ghidrassist_prelude.py bundled in the extension JAR.
 */
public class EvalPythonTool implements McpTool {

    /**
     * System property naming a loose prelude file to read fresh on every call, bypassing the
     * bundled JAR resource entirely. The JAR is locked while Ghidra runs (extension reinstall
     * requires closing it), so it is immutable for the JVM's lifetime and caching it forever is
     * correct; a loose file can be edited in place, so it is deliberately never cached — reading
     * ~150KB from a warm page cache is noise next to the temp-file write + PyGhidra parse this
     * method's caller already does on every eval_python call.
     * Set e.g. -Dghidrassist.prelude.path=E:\...\src\main\resources\ghidrassist_prelude.pyprelude
     * to iterate on the prelude with no rebuild/reinstall/Ghidra-restart.
     */
    public static final String OVERRIDE_PROP = "ghidrassist.prelude.path";

    private static volatile String jarPreludeCache = null;
    private static volatile String lastGoodOverride = null;

    private static java.nio.file.Path resolveOverridePath() {
        String prop = System.getProperty(OVERRIDE_PROP);
        if (prop == null || prop.trim().isEmpty()) return null;
        java.nio.file.Path p = java.nio.file.Path.of(prop.trim());
        return java.nio.file.Files.isRegularFile(p) ? p : null;
    }

    /** Load the prelude: a loose-file override (read fresh) if configured, else the bundled
     * .py resource file (cached after first load — the JAR can't change without a restart). */
    private static String loadPrelude() {
        java.nio.file.Path override = resolveOverridePath();
        if (override != null) {
            try {
                String content = java.nio.file.Files.readString(override, StandardCharsets.UTF_8);
                lastGoodOverride = content;
                return "# prelude-source: " + override.toAbsolutePath() + " (" + content.length() + " chars)\n" + content;
            } catch (IOException e) {
                Msg.warn(EvalPythonTool.class,
                    "Failed to read prelude override: " + override + ", falling back to last good copy", e);
                if (lastGoodOverride != null) {
                    return "# prelude-source: " + override.toAbsolutePath() + " (fallback-cached)\n" + lastGoodOverride;
                }
                // fall through to the bundled resource — no good override to fall back on yet
            }
        }
        if (jarPreludeCache != null) return jarPreludeCache;
        // .pyprelude extension prevents Ghidra's script scanner / PyGhidra from executing it at startup
        try (InputStream is = EvalPythonTool.class.getResourceAsStream("/ghidrassist_prelude.pyprelude")) {
            if (is == null) {
                Msg.error(EvalPythonTool.class, "ghidrassist_prelude.pyprelude not found in JAR resources");
                return "# prelude load failed\n";
            }
            jarPreludeCache = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            return jarPreludeCache;
        } catch (IOException e) {
            Msg.error(EvalPythonTool.class, "Failed to load ghidrassist_prelude.py", e);
            return "# prelude load failed: " + e.getMessage() + "\n";
        }
    }

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public boolean isLongRunning() { return true; }

    // eval_python runs arbitrary scripts (RTTI scans, address iteration) that can legitimately
    // take longer than the platform default; still bounded, still overridable per-call via
    // {"timeout_seconds": N}. See EvalPythonTool docstring's timeout-cap warning below.
    @Override
    public int getDefaultTimeoutSeconds() { return 90; }

    @Override
    public boolean isCacheable() { return false; }

    @Override
    public boolean isDestructive() { return true; }

    @Override
    public boolean isIdempotent() { return false; }

    @Override
    public String getName() { return "eval_python"; }

    @Override
    public String getDescription() {
        return "Execute Python in Ghidra's context. Requires pyghidra (Python 3) or falls back to Jython 2.7. " +
            "Async by default: returns a task_id; poll get_task_status. Pass {\"sync\": true} for inline " +
            "result on quick scripts (<2s) — skips the poll round-trip.\n\n" +
            "TIMEOUT: default " + getDefaultTimeoutSeconds() + "s watchdog, override per-call with " +
            "{\"timeout_seconds\": N} (5-3600). If your script legitimately needs longer (e.g. a full " +
            "binary sweep you can't easily chunk), ask for it explicitly — an unrequested slow script " +
            "only gets " + getDefaultTimeoutSeconds() + "s. Exceeding the timeout marks the task TIMED_OUT " +
            "(you're unblocked, the script keeps running quietly) UNLESS the worker pool is fully busy, " +
            "in which case it is force-cancelled immediately to free capacity for other calls — the same " +
            "rollback risk described below then applies. Prefer many small calls over one large one so a " +
            "timeout costs you one batch, not the whole run.\n\n" +
            "WARNING — rollback on failure/disconnect: Ghidra's own PyGhidraScriptProvider wraps this ENTIRE " +
            "call in one outer transaction automatically, regardless of any transactions your own script " +
            "opens/commits internally. If the MCP client-server connection drops, the extension reloads, or " +
            "anything else interrupts the call before it returns, that outer transaction is rolled back — " +
            "silently undoing everything the script did, even if the script's own logic already called " +
            "endTransaction(..., true) and printed a success message. A printed 'success'/'complete' message " +
            "from a script is therefore NOT proof the changes persisted if the call didn't cleanly return to " +
            "the caller. After any long-running or connection-risky eval_python call (especially bulk/batch " +
            "writes), independently re-verify the actual database state afterward (re-query the specific " +
            "data you expected to change) rather than trusting the script's own printed output alone. For " +
            "large write workloads, prefer many SMALL calls (each completing in well under a minute) over one " +
            "large one, so an interruption loses at most one small batch instead of the whole run.\n\n" +
            "Globals: currentProgram, currentAddress, monitor, state. Symbol search: prefer " +
            "currentProgram.getSymbolTable().getSymbols('name') or getFunctionManager().getFunctions(True); " +
            "AVOID getSymbolIterator() (unbounded, can stall).\n\n" +
            "Three injected helper objects (use dir(x) or help(x.method) for per-method docs):\n" +
            "  ghidra.* — static analysis: decompile, get_func, get_refs_to, set_comment, read_bytes. " +
            "Structs: struct_summary(name) and struct_fields(name) for compact output; " +
            "find_struct(name) returns the raw DataType (large — stringifying dumps every field). " +
            "VT helpers: get_vt_sessions, get_vt_matches, find_addr_in_version, accept_vt_match.\n" +
            "  dbg.*    — live debugger. START a session with dbg.attach(<pid>) (dbg.list_attach_offers() lists " +
            "backends). Prefer dbg.attach(pid, mode='observe') for read-only live memory/struct work (reng.explore/" +
            "find_instances/label/diff*) — dbgeng never suspends the target, so it's the safe default against a " +
            "real/HMD session; reserve mode='default' (invasive, suspends) for when you actually need breakpoints, " +
            "stepping, or register writes. Then memory/registers/breakpoints/stepping, dbg.execute('<windbg cmd>') " +
            "passthrough, dbg.search_memory(value,start,len)/list_regions to find instances, " +
            "dbg.set_control_mode('RW_TARGET') to arm bps, dbg.clear_all_breakpoints(), " +
            "dbg.snapshot(addr,len,then='detach') for VR fast-capture, dbg.detach() when done (captures " +
            "last_event/registers/stack before tearing the trace down, so calling it reflexively after an " +
            "unexpected break doesn't lose that forensic data). Catching a specific exception in a noisy " +
            "multithreaded target: dbg.set_exception_filter(code, 'ignore'|'break'|...) to silence benign " +
            "first-chance storms before arming the one you want (list_exception_filters() shows current sx " +
            "state); on a break, dbg.get_event_thread()/dbg.event_registers() give the actual faulting " +
            "thread/registers (get_registers() alone often returns a parked worker), and dbg.last_event() " +
            "gives the triggering exception's code/thread/first-vs-second-chance so you can tell benign " +
            "from fatal without resuming blindly. dbg.get_stack(thread=...) backtraces via the real dbgeng " +
            "`k` walk. dbg.set_raw_breakpoint(rt_addr) / set_breakpoint(addr, raw=True) breakpoint a runtime " +
            "address directly (bypasses static-mapping) for modules not loaded as a Ghidra program, e.g. " +
            "system DLLs like d3d11.dll/ntdll.\n" +
            "  reng.*   — RE workflow: ASLR (image_base/to_rt/to_static — image_base is the canonical " +
            "live slide, prefer it over list_modules which lags after attach), RTTI " +
            "(rtti/class_hierarchy/vtable_methods), live instance location " +
            "(find_instances(class_or_vtable) finds object instances in target memory), " +
            "ReClass-style struct exploration over live trace memory " +
            "(explore/follow/tree/diff/as_known/as_array), temporal diffing of a single " +
            "singleton across an action via snapshot_state/diff_snapshot (diff() itself " +
            "compares two different instances at once), one-call field commit+apply+verify " +
            "via label(rt_addr, fields), authoring " +
            "(define_class/define_struct/patch_struct/apply_struct), bulk (scan_vtables/rename_vfuncs).\n\n" +
            "Address handling: dbg.* memory + breakpoint methods accept EITHER a static\n" +
            "Ghidra address (0x14xxxxxxx in currentProgram's image range) OR a live runtime\n" +
            "address — translated automatically. Use reng.to_rt/to_static for explicit conversion.\n" +
            "dbg.read_memory returning all zeros usually means cold page not yet captured —\n" +
            "call dbg.refresh_memory(addr, len) first.\n\n" +
            "Companion MCP tools: `scripts` (Script Manager), `open_program` (list/open project programs), `import_file`. " +
            "Debugger session management is all in dbg.* (attach/status/list_sessions/detach).";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("script", Map.of(
                    "type", "string",
                    "description", "The Python script content to execute. Variables like 'currentProgram' and 'monitor' are globally available, just like a standard Ghidra Script."
                )),
                Map.entry("sync", Map.of(
                    "type", "boolean",
                    "description", "If true, execute synchronously and return the result inline — skips the task-id round-trip. Use for quick scripts (<2s). Default false (async via task manager) to avoid blocking on long-running operations like full RTTI scans."
                )),
                Map.entry("timeout_seconds", Map.of(
                    "type", "integer",
                    "description", "Watchdog timeout override, 5-3600 seconds. Default " + getDefaultTimeoutSeconds() +
                        "s. Ask for more only when the script's scope genuinely needs it — the default is " +
                        "deliberately tight so an unbounded/impossibly slow script doesn't pin a worker thread."
                ))
            ),
            List.of("script"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("Error: eval_python requires a backend reference.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        String scriptContent = (String) arguments.get("script");
        if (scriptContent == null || scriptContent.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("script parameter is required")
                .build();
        }

        File tempFile = null;
        try {
            tempFile = File.createTempFile("mcp_eval_", ".py");
            tempFile.deleteOnExit();
            try (FileWriter fw = new FileWriter(tempFile)) {
                fw.write(loadPrelude());
                fw.write(scriptContent);
            }

            ResourceFile sourceFile = new ResourceFile(tempFile);
            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(sourceFile);
            if (provider == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Error: No GhidraScriptProvider found for .py extension. Check PyGhidra or Jython installation.")
                    .build();
            }

            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);

            GhidraScript script = provider.getScriptInstance(sourceFile, printWriter);
            if (script == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Error: Could not obtain GhidraScript instance.")
                    .build();
            }

            GhidraState state;
            GhidrAssistMCPPlugin plugin = backend.getActivePlugin();
            if (plugin != null && plugin.getTool() != null) {
                state = new GhidraState(plugin.getTool(), plugin.getTool().getProject(), currentProgram, null, null, null);
            } else {
                state = new GhidraState(null, null, currentProgram, null, null, null);
            }

            Msg.info(this, "Executing Python script evaluated from LLM...");
            ScriptControls controls = new ScriptControls(printWriter, printWriter, TaskMonitor.DUMMY);
            script.execute(state, controls);

            String output = stringWriter.toString();
            return McpSchema.CallToolResult.builder()
                .addTextContent(output.isEmpty() ? "Script executed successfully (no output)." : output)
                .build();

        } catch (Exception e) {
            Msg.error(this, "Error executing python script", e);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error executing script: " + e.getMessage() + "\n" + e.toString())
                .build();
        } finally {
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
        }
    }
}
