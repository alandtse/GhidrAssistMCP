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
        try (InputStream is = EvalPythonTool.class.getResourceAsStream("/ghidrassist_prelude.py")) {
            if (is == null) {
                Msg.error(EvalPythonTool.class, "ghidrassist_prelude.py not found in JAR resources");
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
        return "Execute arbitrary Python code in Ghidra's context. Requires pyghidra.bat for Python 3 or uses Jython 2.7. " +
            "Agentic Prelude Active (call via 'ghidra.method'):\n" +
            "- decompile(id): Decompile func name/addr\n" +
            "- get_func(id): Return Function object\n" +
            "- get_program(name): Return open Program object by name\n" +
            "- get_vt_sessions(): Return list of all open VTSessions\n" +
            "- get_vt_session(idx=0): Return a VTSession by index\n" +
            "- list_vt_sessions(): Return [{name, src, dst, match_count}] for open sessions\n" +
            "- get_vt_matches(session=None, status=None): Return [{src, dst, status, similarity, confidence}]; status=ACCEPTED/REJECTED/AVAILABLE\n" +
            "- find_addr_in_version(addr, session=None): Find ACCEPTED destination address for a source address\n" +
            "- accept_vt_match(src_addr, session=None): Accept first AVAILABLE match for src address\n" +
            "- copy_datatype(name, from_prog, to_prog): Copy a Struct/Enum across binaries\n" +
            "- get_refs_to(addr): List of callers' addresses\n" +
            "- set_comment(addr, text, type='eol'|'pre'|'post'|'plate'): Set comment\n" +
            "- find_struct(name): Get Struct DT object\n" +
            "- read_bytes(addr, length): Hex memory read\n" +
            "- VT: VTSession and VTMatchInfo are auto-imported\n" +
            "Context provided: currentProgram, currentAddress, monitor.\n\n" +
            "Debugger Prelude Active (call via 'dbg.method') — requires Debugger plugin + active session:\n" +
            "  Session:     dbg.status() → {connected, trace, snap, thread, has_live_target, control_mode}\n" +
            "  Threads:     dbg.get_threads() → [TraceThread, ...]  dbg.get_thread() / dbg.get_snap()\n" +
            "  Registers:   dbg.get_registers(thread, frame, snap) → {name: int}  dbg.refresh_registers()\n" +
            "               dbg.write_register(name, value)\n" +
            "  Memory:      dbg.read_memory(addr, length, snap) → hex string  dbg.refresh_memory(addr, n)\n" +
            "               dbg.write_memory(addr, hex_bytes)\n" +
            "  Execution:   dbg.resume() / dbg.interrupt() / dbg.step_into() / dbg.step_over() / dbg.step_out() / dbg.kill()\n" +
            "  Breakpoints: dbg.list_breakpoints() / dbg.set_breakpoint(addr, length, name) / dbg.delete_breakpoints(addr)\n" +
            "  Stack:       dbg.get_stack(thread, snap) → [{level, pc}]\n" +
            "  Workflow: call dbg.status() first; if connected=False use `debugger` tool.\n\n" +
            "Reverse Engineering Prelude Active (call via 'reng.method') — works with or without live debugger:\n" +
            "  Address:     reng.image_base() / reng.to_rt(static) / reng.to_static(runtime)\n" +
            "  RTTI:        reng.rtti(rt_ptr) → class name   reng.class_hierarchy(rt_ptr) → inheritance chain\n" +
            "               reng.vtable_methods(rt_ptr) → [{slot, rt, static, name, named}]\n" +
            "  ReClass.NET struct exploration (backed by Ghidra DataTypeManager):\n" +
            "    reng.explore(rt_addr, size=256)     → field table with known field names + auto-inference\n" +
            "                                           INHERITED fields shown with (from ClassName) tag\n" +
            "    reng.follow(rt_addr, offset)         → dereference ptr at offset, explore sub-object\n" +
            "    reng.as_array(rt_addr, off, N, type) → read N consecutive typed values (f32/u32/ptr/...)\n" +
            "    reng.as_known(rt_addr, off, 'Type')  → read inline (non-ptr) embedded struct by Ghidra type name\n" +
            "    reng.diff(ptr_a, ptr_b)              → fields differing between two instances\n" +
            "                                           KEY: damage one Actor, diff → health offset revealed\n" +
            "    reng.tree(ptr, depth=2)              → recursive exploration (follows ptr fields)\n" +
            "    reng.find_type_at(rt_addr, offset)   → cross-reference a single field\n" +
            "    reng.read_struct(rt_addr, fields)    → {name: val} from explicit field map\n" +
            "  Struct authoring (C++ inheritance-aware):\n" +
            "    reng.define_class(name, own_fields, base_class='TESObjectREFR') → embeds base at offset 0\n" +
            "      CORRECT for inheritance; decompiler shows this->TESObjectREFR_base.formID\n" +
            "      own_fields = {fname: (abs_offset, size, comment)} — offsets >= sizeof(base)\n" +
            "    reng.build_hierarchy(rt_ptr) → auto-build full chain from RTTI (TESForm→TESObjectREFR→Actor→...)\n" +
            "    reng.define_struct(name, fields) → flat struct, no inheritance (for simple/value types)\n" +
            "      Call with fields={} to inspect current definition; existing named fields preserved\n" +
            "    reng.apply_struct(static_addr, name) → apply DataType to Ghidra Listing view\n" +
            "  RTTI/vtable bulk operations:\n" +
            "    reng.scan_vtables() → {vtable_static_addr: class_name} — scans .rdata RTTI (cached)\n" +
            "    reng.rename_vfuncs(dry_run=False) → renames FUN_* into ClassName::vfunc_N\n" +
            "  Script management:\n" +
            "    reng.save_script(name, code, category, description) → saves to ~/ghidra_scripts/\n" +
            "    reng.list_scripts(pattern) / reng.load_script(name) / reng.run_script(name)\n" +
            "    (Prefer the `scripts` MCP tool for interactive script management)";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("script", Map.of(
                    "type", "string",
                    "description", "The Python script content to execute. Variables like 'currentProgram' and 'monitor' are globally available, just like a standard Ghidra Script."
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
