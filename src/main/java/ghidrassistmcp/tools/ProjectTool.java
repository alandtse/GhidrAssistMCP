/*
 * MCP tool for Ghidra project and program management.
 *
 * Actions:
 * - list_files:   List all programs/files already imported into the current Ghidra project
 * - open:         Open an already-imported program in CodeBrowser by name (partial match ok)
 * - import:       Import a new binary file from disk into the project and open it
 *                 (requires file path; security-equivalent to import_file tool)
 *
 * This is the MCP equivalent of: File → Open Project → double-click binary.
 * Allows an agent to bootstrap a session without touching the Ghidra UI.
 */
package ghidrassistmcp.tools;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.services.ProgramManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class ProjectTool implements McpTool {

    @Override
    public String getName() { return "project"; }

    @Override
    public String getDescription() {
        return """
            Manage the Ghidra project — list, open, and import programs. \
            Use this before other tools when no program is active.

            Actions:
              list_files — List all programs already imported into the current Ghidra project
              open       — Open an already-imported program in CodeBrowser: {"action":"open","name":"SkyrimVR.exe"}
                           Partial name matching supported. Opens and makes it the active program.
              import     — Import a new binary from disk and open it: {"action":"import","file_path":"E:/path/to/file.exe"}
                           Performs auto-analysis. Caution: reads arbitrary files from the host filesystem.

            Workflow for a fresh Ghidra session:
              1. `project list_files` — see what's already imported
              2. `project open` with the name — loads it into CodeBrowser
              3. Other tools now work (debugger, eval_python, etc.)
            """;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "action", Map.of(
                    "type", "string",
                    "enum", List.of("list_files", "open", "import"),
                    "description", "Action to perform"
                ),
                "name", Map.of(
                    "type", "string",
                    "description", "Program name to open (for 'open' action, partial match supported)"
                ),
                "file_path", Map.of(
                    "type", "string",
                    "description", "Absolute path to binary file on disk (for 'import' action)"
                )
            ),
            List.of("action"), null, null, null);
    }

    @Override public boolean isReadOnly() { return false; }
    @Override public boolean isLongRunning() { return false; }
    @Override public boolean isCacheable() { return false; }
    @Override public boolean isDestructive() { return false; }
    @Override public boolean isIdempotent() { return false; }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("Error: project tool requires a backend reference.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend) {
        String action = (String) arguments.get("action");
        if (action == null) action = "list_files";

        GhidrAssistMCPPlugin plugin = backend.getActivePlugin();
        if (plugin == null || plugin.getTool() == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: no active Ghidra tool. Ensure Ghidra's CodeBrowser is open.")
                .build();
        }

        PluginTool tool = plugin.getTool();
        Project project = tool.getProject();

        return switch (action) {
            case "list_files" -> doListFiles(project);
            case "open"       -> doOpen(tool, project, (String) arguments.get("name"));
            case "import"     -> doImport(tool, project, (String) arguments.get("file_path"));
            default -> McpSchema.CallToolResult.builder()
                .addTextContent("Unknown action: " + action + ". Use: list_files, open, import")
                .build();
        };
    }

    private McpSchema.CallToolResult doListFiles(Project project) {
        if (project == null) return McpSchema.CallToolResult.builder()
            .addTextContent("No Ghidra project is open. Open a project first (File → Open Project).").build();

        List<String> files = new ArrayList<>();
        collectFiles(project.getProjectData().getRootFolder(), "", files);

        if (files.isEmpty()) return McpSchema.CallToolResult.builder()
            .addTextContent("Project '" + project.getName() + "' is empty. Use action 'import' to add a binary.").build();

        StringBuilder sb = new StringBuilder();
        sb.append("Project: ").append(project.getName()).append("  (").append(files.size()).append(" files)\n\n");
        files.forEach(f -> sb.append("  ").append(f).append("\n"));
        sb.append("\nUse {\"action\":\"open\",\"name\":\"<filename>\"} to load one.");
        return McpSchema.CallToolResult.builder().addTextContent(sb.toString()).build();
    }

    private void collectFiles(DomainFolder folder, String prefix, List<String> result) {
        for (DomainFile f : folder.getFiles()) {
            result.add(prefix + f.getName());
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectFiles(sub, prefix + sub.getName() + "/", result);
        }
    }

    private McpSchema.CallToolResult doOpen(PluginTool tool, Project project, String name) {
        if (name == null || name.isBlank()) return McpSchema.CallToolResult.builder()
            .addTextContent("'name' parameter required. Use list_files to see available programs.").build();
        if (project == null) return McpSchema.CallToolResult.builder()
            .addTextContent("No Ghidra project is open.").build();

        DomainFile match = findFile(project.getProjectData().getRootFolder(), name);
        if (match == null) return McpSchema.CallToolResult.builder()
            .addTextContent("No file matching '" + name + "' found in project. Use list_files to see available programs.").build();

        try {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm == null) return McpSchema.CallToolResult.builder()
                .addTextContent("ProgramManager service not available.").build();

            Program prog = (Program) match.getDomainObject(this, true, false, TaskMonitor.DUMMY);
            pm.openProgram(prog);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Opened: " + match.getName() + "\nNow active — other MCP tools will target this program.")
                .build();
        } catch (Exception e) {
            Msg.error(this, "Error opening program: " + name, e);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error opening '" + name + "': " + e.getMessage()).build();
        }
    }

    private DomainFile findFile(DomainFolder folder, String name) {
        String lower = name.toLowerCase();
        for (DomainFile f : folder.getFiles()) {
            if (f.getName().toLowerCase().contains(lower)) return f;
        }
        for (DomainFolder sub : folder.getFolders()) {
            DomainFile found = findFile(sub, name);
            if (found != null) return found;
        }
        return null;
    }

    private McpSchema.CallToolResult doImport(PluginTool tool, Project project, String filePath) {
        if (filePath == null || filePath.isBlank()) return McpSchema.CallToolResult.builder()
            .addTextContent("'file_path' parameter required. Example: {\"action\":\"import\",\"file_path\":\"E:/SkyrimVR.exe\"}").build();
        if (project == null) return McpSchema.CallToolResult.builder()
            .addTextContent("No Ghidra project is open. Open a project first.").build();

        File f = new File(filePath);
        if (!f.exists()) return McpSchema.CallToolResult.builder()
            .addTextContent("File not found: " + filePath).build();

        try {
            MessageLog log = new MessageLog();
            @SuppressWarnings("unchecked")
            LoadResults<Program> results = (LoadResults<Program>) AutoImporter.importByUsingBestGuess(
                f, project, "/", this, log, TaskMonitor.DUMMY);

            if (results == null || results.size() == 0) return McpSchema.CallToolResult.builder()
                .addTextContent("Import failed. Log:\n" + log.toString()).build();

            results.save(TaskMonitor.DUMMY);
            Program prog = results.getPrimaryDomainObject(this);
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm != null && prog != null) pm.openProgram(prog);

            String msg = "Imported and opened: " + f.getName();
            if (!log.toString().isBlank()) msg += "\nLog: " + log;
            return McpSchema.CallToolResult.builder().addTextContent(msg).build();

        } catch (Exception e) {
            Msg.error(this, "Error importing: " + filePath, e);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error importing '" + filePath + "': " + e.getMessage()).build();
        }
    }
}
