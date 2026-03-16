/*
 * MCP tool for equate operations.
 * Equates associate symbolic names with constant integer values used in disassembly.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for equate operations.
 *
 * Equates map symbolic names to constant values used in disassembly, allowing
 * meaningful names to replace raw numbers in the listing view.
 *
 * Actions:
 * - list:    List all equates (optional pattern filter)
 * - get_info: Get details about a specific equate
 * - create:  Create a new equate with a name and numeric value
 * - rename:  Rename an existing equate
 * - delete:  Delete an equate (removes it from the equate table)
 */
public class EquateTool implements McpTool {

    @Override
    public String getName() {
        return "equate";
    }

    @Override
    public String getDescription() {
        return "Equate operations: list, get_info, create, rename, delete. " +
               "Equates associate symbolic names with constant integer values in disassembly. " +
               "Use 'value' as a decimal integer for create.";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> props = new HashMap<>();
        props.put("action", Map.of(
            "type", "string",
            "description", "Operation to perform: list, get_info, create, rename, delete",
            "enum", List.of("list", "get_info", "create", "rename", "delete")
        ));
        props.put("name", Map.of(
            "type", "string",
            "description", "Equate name"
        ));
        props.put("new_name", Map.of(
            "type", "string",
            "description", "New name for rename action"
        ));
        props.put("value", Map.of(
            "type", "integer",
            "description", "Numeric value for create action"
        ));
        props.put("pattern", Map.of(
            "type", "string",
            "description", "Optional substring filter for list action"
        ));
        props.put("offset", Map.of(
            "type", "integer",
            "description", "Pagination offset for list action (default 0)"
        ));
        props.put("limit", Map.of(
            "type", "integer",
            "description", "Maximum results for list action (default 100)"
        ));
        return new McpSchema.JsonSchema("object", props, List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return execute(arguments, currentProgram, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder().addTextContent("No program currently loaded").build();
        }

        String action = (String) arguments.get("action");
        if (action == null || action.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("action parameter is required. Valid actions: list, get_info, create, rename, delete")
                .build();
        }

        switch (action.toLowerCase()) {
            case "list":     return executeList(arguments, currentProgram);
            case "get_info": return executeGetInfo(arguments, currentProgram);
            case "create":   return executeCreate(arguments, currentProgram, backend);
            case "rename":   return executeRename(arguments, currentProgram, backend);
            case "delete":   return executeDelete(arguments, currentProgram, backend);
            default:
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Unknown action: '" + action + "'. Valid actions: list, get_info, create, rename, delete")
                    .build();
        }
    }

    // ========== LIST ==========

    private McpSchema.CallToolResult executeList(Map<String, Object> arguments, Program program) {
        String pattern = (String) arguments.get("pattern");
        int offset = arguments.get("offset") instanceof Number ? ((Number) arguments.get("offset")).intValue() : 0;
        int limit  = arguments.get("limit")  instanceof Number ? ((Number) arguments.get("limit")).intValue()  : 100;

        EquateTable equateTable = program.getEquateTable();

        List<Equate> equates = new ArrayList<>();
        Iterator<Equate> iter = equateTable.getEquates();
        while (iter.hasNext()) {
            Equate eq = iter.next();
            if (pattern == null || pattern.isEmpty() ||
                    eq.getName().toLowerCase().contains(pattern.toLowerCase())) {
                equates.add(eq);
            }
        }

        equates.sort((a, b) -> a.getName().compareToIgnoreCase(b.getName()));

        StringBuilder sb = new StringBuilder("Equates");
        if (pattern != null && !pattern.isEmpty()) sb.append(" matching '").append(pattern).append("'");
        sb.append(":\n\n");

        int count = 0;
        for (int i = offset; i < equates.size() && count < limit; i++, count++) {
            Equate eq = equates.get(i);
            sb.append("- ").append(eq.getName())
              .append(" = ").append(eq.getValue())
              .append(" (0x").append(Long.toHexString(eq.getValue()).toUpperCase()).append(")")
              .append(" [").append(eq.getReferenceCount()).append(" ref(s)]")
              .append("\n");
        }

        if (equates.isEmpty()) {
            sb.append("No equates found.");
        } else {
            sb.append("\nShowing ").append(count).append(" of ").append(equates.size()).append(" equates");
            if (offset > 0) sb.append(" (offset: ").append(offset).append(")");
        }
        return McpSchema.CallToolResult.builder().addTextContent(sb.toString()).build();
    }

    // ========== GET_INFO ==========

    private McpSchema.CallToolResult executeGetInfo(Map<String, Object> arguments, Program program) {
        String name = getString(arguments, "name");
        if (name == null) {
            return McpSchema.CallToolResult.builder().addTextContent("name parameter is required for get_info").build();
        }

        Equate equate = program.getEquateTable().getEquate(name);
        if (equate == null) {
            return McpSchema.CallToolResult.builder().addTextContent("Equate not found: '" + name + "'").build();
        }

        String info = "Equate: " + equate.getName() + "\n" +
            "Display Name: " + equate.getDisplayName() + "\n" +
            "Value: " + equate.getValue() + " (0x" + Long.toHexString(equate.getValue()).toUpperCase() + ")\n" +
            "References: " + equate.getReferenceCount() + "\n" +
            "Enum-based: " + equate.isEnumBased() + "\n";

        return McpSchema.CallToolResult.builder().addTextContent(info).build();
    }

    // ========== CREATE ==========

    private McpSchema.CallToolResult executeCreate(Map<String, Object> arguments, Program program, GhidrAssistMCPBackend backend) {
        String name = getString(arguments, "name");
        if (name == null) {
            return McpSchema.CallToolResult.builder().addTextContent("name parameter is required for create").build();
        }
        if (!(arguments.get("value") instanceof Number)) {
            return McpSchema.CallToolResult.builder().addTextContent("value parameter (integer) is required for create").build();
        }
        long value = ((Number) arguments.get("value")).longValue();

        EquateTable equateTable = program.getEquateTable();
        if (equateTable.getEquate(name) != null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Equate '" + name + "' already exists. Use rename to change its name.")
                .build();
        }

        int txId = program.startTransaction("Create Equate: " + name);
        boolean committed = false;
        try {
            equateTable.createEquate(name, value);
            committed = true;
            if (backend != null) backend.clearCache();
            return McpSchema.CallToolResult.builder()
                .addTextContent("Created equate '" + name + "' = " + value +
                    " (0x" + Long.toHexString(value).toUpperCase() + ")")
                .build();
        } catch (DuplicateNameException e) {
            return McpSchema.CallToolResult.builder().addTextContent("Equate '" + name + "' already exists").build();
        } catch (InvalidInputException e) {
            return McpSchema.CallToolResult.builder().addTextContent("Invalid equate name '" + name + "': " + e.getMessage()).build();
        } catch (Exception e) {
            Msg.error(this, "Error creating equate", e);
            return McpSchema.CallToolResult.builder().addTextContent("Error creating equate: " + e.getMessage()).build();
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    // ========== RENAME ==========

    private McpSchema.CallToolResult executeRename(Map<String, Object> arguments, Program program, GhidrAssistMCPBackend backend) {
        String name = getString(arguments, "name");
        String newName = getString(arguments, "new_name");
        if (name == null || newName == null) {
            return McpSchema.CallToolResult.builder().addTextContent("name and new_name parameters are required").build();
        }

        Equate equate = program.getEquateTable().getEquate(name);
        if (equate == null) {
            return McpSchema.CallToolResult.builder().addTextContent("Equate not found: '" + name + "'").build();
        }

        int txId = program.startTransaction("Rename Equate: " + name + " -> " + newName);
        boolean committed = false;
        try {
            equate.renameEquate(newName);
            committed = true;
            if (backend != null) backend.clearCache();
            return McpSchema.CallToolResult.builder()
                .addTextContent("Renamed equate '" + name + "' to '" + newName + "'")
                .build();
        } catch (DuplicateNameException e) {
            return McpSchema.CallToolResult.builder().addTextContent("Equate '" + newName + "' already exists").build();
        } catch (InvalidInputException e) {
            return McpSchema.CallToolResult.builder().addTextContent("Invalid equate name '" + newName + "': " + e.getMessage()).build();
        } catch (Exception e) {
            Msg.error(this, "Error renaming equate", e);
            return McpSchema.CallToolResult.builder().addTextContent("Error renaming equate: " + e.getMessage()).build();
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    // ========== DELETE ==========

    private McpSchema.CallToolResult executeDelete(Map<String, Object> arguments, Program program, GhidrAssistMCPBackend backend) {
        String name = getString(arguments, "name");
        if (name == null) {
            return McpSchema.CallToolResult.builder().addTextContent("name parameter is required for delete").build();
        }

        EquateTable equateTable = program.getEquateTable();
        Equate equate = equateTable.getEquate(name);
        if (equate == null) {
            return McpSchema.CallToolResult.builder().addTextContent("Equate not found: '" + name + "'").build();
        }

        int txId = program.startTransaction("Delete Equate: " + name);
        boolean committed = false;
        try {
            boolean removed = equateTable.removeEquate(name);
            committed = removed;
            if (removed && backend != null) backend.clearCache();
            return McpSchema.CallToolResult.builder()
                .addTextContent(removed
                    ? "Deleted equate '" + name + "'"
                    : "Failed to delete equate '" + name + "'")
                .build();
        } catch (Exception e) {
            Msg.error(this, "Error deleting equate", e);
            return McpSchema.CallToolResult.builder().addTextContent("Error deleting equate: " + e.getMessage()).build();
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    // ========== HELPERS ==========

    private String getString(Map<String, Object> args, String key) {
        Object val = args.get(key);
        if (val instanceof String) {
            String s = ((String) val).trim();
            return s.isEmpty() ? null : s;
        }
        return null;
    }
}
