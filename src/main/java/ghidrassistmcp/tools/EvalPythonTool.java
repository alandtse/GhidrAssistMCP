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

    private static volatile String PRELUDE_CACHE = null;

    /** Load prelude from the bundled .py resource file (cached after first load). */
    private static String loadPrelude() {
        if (PRELUDE_CACHE != null) return PRELUDE_CACHE;
        // .pyprelude extension prevents Ghidra's script scanner / PyGhidra from executing it at startup
        try (InputStream is = EvalPythonTool.class.getResourceAsStream("/ghidrassist_prelude.pyprelude")) {
            if (is == null) {
                Msg.error(EvalPythonTool.class, "ghidrassist_prelude.pyprelude not found in JAR resources");
                return "# prelude load failed\n";
            }
            PRELUDE_CACHE = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            return PRELUDE_CACHE;
        } catch (IOException e) {
            Msg.error(EvalPythonTool.class, "Failed to load ghidrassist_prelude.py", e);
            return "# prelude load failed: " + e.getMessage() + "\n";
        }
    }

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public boolean isLongRunning() { return true; }

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
            "Globals: currentProgram, currentAddress, monitor, state. Symbol search: prefer " +
            "currentProgram.getSymbolTable().getSymbols('name') or getFunctionManager().getFunctions(True); " +
            "AVOID getSymbolIterator() (unbounded, can stall).\n\n" +
            "Three injected helper objects (use dir(x) or help(x.method) for per-method docs):\n" +
            "  ghidra.* — static analysis: decompile, get_func, get_refs_to, set_comment, read_bytes. " +
            "Structs: struct_summary(name) and struct_fields(name) for compact output; " +
            "find_struct(name) returns the raw DataType (large — stringifying dumps every field). " +
            "VT helpers: get_vt_sessions, get_vt_matches, find_addr_in_version, accept_vt_match.\n" +
            "  dbg.*    — live debugger. START a session with dbg.attach(<pid>) (dbg.list_attach_offers() lists " +
            "backends); then memory/registers/breakpoints/stepping, dbg.execute('<windbg cmd>') passthrough, " +
            "dbg.search_memory(value,start,len)/list_regions to find instances, dbg.set_control_mode('RW_TARGET') " +
            "to arm bps, dbg.clear_all_breakpoints(), dbg.snapshot(addr,len,then='detach') for VR fast-capture, " +
            "dbg.detach() when done.\n" +
            "  reng.*   — RE workflow: ASLR (image_base/to_rt/to_static), RTTI (rtti/class_hierarchy/vtable_methods), " +
            "ReClass-style struct exploration (explore/follow/tree/diff/as_known/as_array), authoring " +
            "(define_class/define_struct/apply_struct), bulk (scan_vtables/rename_vfuncs).\n\n" +
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
