/*
 * MCP tool for evaluating arbitrary Python 3 code via GhidraScript (PyGhidra).
 */
package ghidrassistmcp.tools;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
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
 */
public class EvalPythonTool implements McpTool {

    private static final String PRELUDE = 
        "import ghidra.app.decompiler.DecompInterface as DecompInterface\n" +
        "import ghidra.util.task.TaskMonitor as TaskMonitor\n" +
        "import ghidra.program.model.listing.CommentType as CommentType\n" +
        "import ghidra.program.model.symbol.SourceType as SourceType\n" +
        "try:\n" +
        "    from ghidra.feature.vt.api.main import VTSession, VTMatchInfo\n" +
        "except: pass\n" +
        "class GhidraHelpers:\n" +
        "    def get_program(self, name):\n" +
        "        try:\n" +
        "            from ghidra.app.services import ProgramManager\n" +
        "            pm = state.getTool().getService(ProgramManager)\n" +
        "            for p in pm.getAllOpenPrograms():\n" +
        "                if p.getName() == name: return p\n" +
        "        except: pass\n" +
        "        return None\n" +
        "    def get_vt_sessions(self):\n" +
        "        sessions = []\n" +
        "        tool = getattr(state, 'getTool', lambda: None)()\n" +
        "        if tool:\n" +
        "            for s in tool.getServices():\n" +
        "                if 'VTController' in s.getClass().getSimpleName():\n" +
        "                    sess = s.getSession()\n" +
        "                    if sess and sess not in sessions: sessions.append(sess)\n" +
        "        return sessions\n" +
        "    def get_vt_session(self, idx=0):\n" +
        "        sessions = self.get_vt_sessions()\n" +
        "        return sessions[idx] if len(sessions) > idx else None\n" +
        "    def copy_datatype(self, name, from_prog, to_prog):\n" +
        "        try:\n" +
        "            from ghidra.program.model.data import DataTypeConflictHandler\n" +
        "            dt = None\n" +
        "            for d in from_prog.getDataTypeManager().getAllDataTypes():\n" +
        "                if d.getName() == name:\n" +
        "                    dt = d\n" +
        "                    break\n" +
        "            if dt:\n" +
        "                to_prog.getDataTypeManager().addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)\n" +
        "                return True\n" +
        "        except: pass\n" +
        "        return False\n" +
        "    def get_addr(self, s):\n" +
        "        if hasattr(s, 'getAddress'): return s.getAddress()\n" +
        "        return currentProgram.getAddressFactory().getAddress(str(s))\n" +
        "    def get_func(self, id):\n" +
        "        fm = currentProgram.getFunctionManager()\n" +
        "        try: \n" +
        "            a = self.get_addr(id)\n" +
        "            if a: return fm.getFunctionAt(a)\n" +
        "        except: pass\n" +
        "        for f in fm.getFunctions(True):\n" +
        "            if f.getName() == id: return f\n" +
        "        return None\n" +
        "    def decompile(self, id):\n" +
        "        f = self.get_func(id)\n" +
        "        if not f: return 'Function not found'\n" +
        "        di = DecompInterface()\n" +
        "        di.openProgram(currentProgram)\n" +
        "        res = di.decompileFunction(f, 30, monitor)\n" +
        "        ret = res.getDecompiledFunction().getC() if res.isValid() else res.getErrorMessage()\n" +
        "        di.dispose()\n" +
        "        return ret\n" +
        "    def get_refs_to(self, addr):\n" +
        "        rm = currentProgram.getReferenceManager()\n" +
        "        return [r.getFromAddress().toString() for r in rm.getReferencesTo(self.get_addr(addr))]\n" +
        "    def set_comment(self, addr, text, type='eol'):\n" +
        "        ct = {'eol': CommentType.EOL, 'pre': CommentType.PRE, 'post': CommentType.POST, 'plate': CommentType.PLATE}.get(type, CommentType.EOL)\n" +
        "        currentProgram.getListing().setComment(self.get_addr(addr), ct, text)\n" +
        "    def find_struct(self, name):\n" +
        "        for dt in currentProgram.getDataTypeManager().getAllDataTypes():\n" +
        "            if dt.getName() == name and 'Structure' in type(dt).__name__: return dt\n" +
        "        return None\n" +
        "    def read_bytes(self, addr, length):\n" +
        "        try:\n" +
        "            b = currentProgram.getMemory().getBytes(self.get_addr(addr), length)\n" +
        "            return ''.join(['%02x' % (x & 0xff) for x in b])\n" +
        "        except: return 'Error reading bytes'\n" +
        "ghidra = GhidraHelpers()\n\n";

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isLongRunning() {
        return true;
    }

    @Override
    public boolean isCacheable() {
        return false;
    }

    @Override
    public boolean isDestructive() {
        return true;
    }

    @Override
    public boolean isIdempotent() {
        return false;
    }

    @Override
    public String getName() {
        return "eval_python";
    }

    @Override
    public String getDescription() {
        return "Execute arbitrary Python code in Ghidra's context. Requires pyghidra.bat for Python 3 or uses Jython 2.7. " +
            "Agentic Prelude Active (call via 'ghidra.method'):\n" +
            "- decompile(id): Decompile func name/addr\n" +
            "- get_func(id): Return Function object\n" +
            "- get_program(name): Return open Program object by name\n" +
            "- get_vt_sessions(): Return a list of all open VTSessions in the tool\n" +
            "- get_vt_session(idx=0): Return the active VTSession from the VT GUI by index\n" +
            "- copy_datatype(name, from_prog, to_prog): Copy a Struct/Enum across binaries\n" +
            "- get_refs_to(addr): List of callers' addresses\n" +
            "- set_comment(addr, text, type='eol'|'pre'|'post'|'plate'): Set commenting\n" +
            "- find_struct(name): Get Struct DT object\n" +
            "- read_bytes(addr, length): Hex memory read\n" +
            "- VT: VTSession and VTMatchInfo are auto-imported\n" +
            "Context provided: currentProgram, currentAddress, monitor.";
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
            // Write out to a temp python file with PRELUDE
            tempFile = File.createTempFile("mcp_eval_", ".py");
            tempFile.deleteOnExit();
            try (FileWriter fw = new FileWriter(tempFile)) {
                fw.write(PRELUDE);
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

            // Prepare GhidraState with active context
            GhidraState state;
            GhidrAssistMCPPlugin plugin = backend.getActivePlugin();
            if (plugin != null && plugin.getTool() != null) {
                state = new GhidraState(plugin.getTool(), plugin.getTool().getProject(), currentProgram, null, null, null);
            } else {
                state = new GhidraState(null, null, currentProgram, null, null, null);
            }

            // Execute the script
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
