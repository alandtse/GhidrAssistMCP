/*
 * MCP tool for enum data type operations.
 * Supports listing, inspecting, creating, modifying, and deleting enum data types.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.InvalidNameException;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for enum data type operations.
 *
 * Actions:
 * - list:         List all enums in the program (optional pattern filter)
 * - get_info:     Get detailed info about a specific enum
 * - create:       Create a new enum with optional initial values
 * - add_value:    Add a named value to an existing enum
 * - remove_value: Remove a named value from an existing enum
 * - rename_value: Rename a value within an existing enum
 * - rename:       Rename the enum data type itself
 * - delete:       Delete an enum data type
 */
public class EnumTool implements McpTool {

    // ghidra.program.model.data.Enum is imported via fully qualified name throughout
    // to avoid shadowing java.lang.Enum in a confusing way.

    @Override
    public String getName() {
        return "enum";
    }

    @Override
    public String getDescription() {
        return "Enum data type operations: list, get_info, create, add_value, remove_value, rename_value, rename, delete. " +
               "Use 'values' in create with format \"NAME=VALUE,NAME2=0x10\" for initial values. " +
               "category accepts a path like \"/MyCategory\" to scope lookups.";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isDestructive() {
        return false; // delete action is destructive but we flag per-action
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> props = new HashMap<>();
        props.put("action", Map.of(
            "type", "string",
            "description", "Operation to perform: list, get_info, create, add_value, remove_value, rename_value, rename, delete",
            "enum", List.of("list", "get_info", "create", "add_value", "remove_value", "rename_value", "rename", "delete")
        ));
        props.put("name", Map.of(
            "type", "string",
            "description", "Enum name (or full path starting with '/' to resolve unambiguously)"
        ));
        props.put("category", Map.of(
            "type", "string",
            "description", "Category path (e.g. '/MyTypes') to scope lookup or set destination for create"
        ));
        props.put("new_name", Map.of(
            "type", "string",
            "description", "New name for rename or rename_value actions"
        ));
        props.put("size", Map.of(
            "type", "integer",
            "description", "Size in bytes for create action (1, 2, 4, or 8; default 4)"
        ));
        props.put("values", Map.of(
            "type", "string",
            "description", "Comma-separated NAME=VALUE pairs for create, e.g. \"A=0,B=1,C=0xFF\""
        ));
        props.put("value_name", Map.of(
            "type", "string",
            "description", "Name of the specific enum value for add_value, remove_value, rename_value"
        ));
        props.put("value", Map.of(
            "type", "integer",
            "description", "Numeric value for add_value"
        ));
        props.put("comment", Map.of(
            "type", "string",
            "description", "Optional comment for add_value"
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
                .addTextContent("action parameter is required. Valid actions: list, get_info, create, add_value, remove_value, rename_value, rename, delete")
                .build();
        }

        switch (action.toLowerCase()) {
            case "list":         return executeList(arguments, currentProgram);
            case "get_info":     return executeGetInfo(arguments, currentProgram);
            case "create":       return executeCreate(arguments, currentProgram, backend);
            case "add_value":    return executeAddValue(arguments, currentProgram, backend);
            case "remove_value": return executeRemoveValue(arguments, currentProgram, backend);
            case "rename_value": return executeRenameValue(arguments, currentProgram, backend);
            case "rename":       return executeRename(arguments, currentProgram, backend);
            case "delete":       return executeDelete(arguments, currentProgram, backend);
            default:
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Unknown action: '" + action + "'. Valid actions: list, get_info, create, add_value, remove_value, rename_value, rename, delete")
                    .build();
        }
    }

    // ========== LIST ==========

    private McpSchema.CallToolResult executeList(Map<String, Object> arguments, Program program) {
        String pattern = (String) arguments.get("pattern");
        int offset = arguments.get("offset") instanceof Number ? ((Number) arguments.get("offset")).intValue() : 0;
        int limit  = arguments.get("limit")  instanceof Number ? ((Number) arguments.get("limit")).intValue()  : 100;

        DataTypeManager dtm = program.getDataTypeManager();
        List<ghidra.program.model.data.Enum> matches = new ArrayList<>();

        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt instanceof ghidra.program.model.data.Enum) {
                if (pattern == null || pattern.isEmpty() ||
                        dt.getName().toLowerCase().contains(pattern.toLowerCase())) {
                    matches.add((ghidra.program.model.data.Enum) dt);
                }
            }
        }

        matches.sort((a, b) -> {
            int c = a.getCategoryPath().getPath().compareTo(b.getCategoryPath().getPath());
            return c != 0 ? c : a.getName().compareTo(b.getName());
        });

        StringBuilder sb = new StringBuilder("Enums");
        if (pattern != null && !pattern.isEmpty()) sb.append(" matching '").append(pattern).append("'");
        sb.append(":\n\n");

        int count = 0;
        for (int i = offset; i < matches.size() && count < limit; i++, count++) {
            ghidra.program.model.data.Enum e = matches.get(i);
            sb.append("- ").append(e.getName())
              .append(" [").append(e.getCategoryPath().getPath()).append("]")
              .append(" (").append(e.getLength()).append(" bytes, ").append(e.getCount()).append(" values)")
              .append("\n");
        }

        if (matches.isEmpty()) {
            sb.append("No enums found.");
        } else {
            sb.append("\nShowing ").append(count).append(" of ").append(matches.size()).append(" enums");
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

        ResolveResult resolved = resolveEnum(program.getDataTypeManager(), name, (String) arguments.get("category"));
        if (!resolved.ok) {
            return McpSchema.CallToolResult.builder().addTextContent(resolved.message).build();
        }

        ghidra.program.model.data.Enum enumDt = resolved.enumDt;
        StringBuilder sb = new StringBuilder();
        sb.append("Enum: ").append(enumDt.getName()).append("\n");
        sb.append("Category: ").append(enumDt.getCategoryPath().getPath()).append("\n");
        sb.append("Size: ").append(enumDt.getLength()).append(" byte(s)\n");
        sb.append("Signed: ").append(enumDt.isSigned()).append("\n");
        sb.append("Values (").append(enumDt.getCount()).append("):\n");

        String[] names = enumDt.getNames();
        Arrays.sort(names);
        for (String n : names) {
            try {
                long v = enumDt.getValue(n);
                String comment = enumDt.getComment(n);
                sb.append(String.format("  %-40s = %d (0x%X)", n, v, v));
                if (comment != null && !comment.isEmpty()) {
                    sb.append("  // ").append(comment);
                }
                sb.append("\n");
            } catch (NoSuchElementException e) {
                // skip
            }
        }
        return McpSchema.CallToolResult.builder().addTextContent(sb.toString()).build();
    }

    // ========== CREATE ==========

    private McpSchema.CallToolResult executeCreate(Map<String, Object> arguments, Program program, GhidrAssistMCPBackend backend) {
        String name = getString(arguments, "name");
        if (name == null) {
            return McpSchema.CallToolResult.builder().addTextContent("name parameter is required for create").build();
        }

        String category = (String) arguments.get("category");
        CategoryPath categoryPath = (category != null && !category.isEmpty())
            ? new CategoryPath(category)
            : CategoryPath.ROOT;

        int size = 4;
        if (arguments.get("size") instanceof Number) {
            size = ((Number) arguments.get("size")).intValue();
        }
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            return McpSchema.CallToolResult.builder().addTextContent("size must be 1, 2, 4, or 8 bytes").build();
        }

        String valuesStr = (String) arguments.get("values");

        DataTypeManager dtm = program.getDataTypeManager();
        int txId = program.startTransaction("Create Enum: " + name);
        boolean committed = false;
        try {
            EnumDataType enumDt = new EnumDataType(categoryPath, name, size);

            if (valuesStr != null && !valuesStr.isEmpty()) {
                String error = parseAndAddValues(enumDt, valuesStr);
                if (error != null) {
                    return McpSchema.CallToolResult.builder().addTextContent("Error parsing values: " + error).build();
                }
            }

            DataType added = dtm.addDataType(enumDt, null);
            committed = true;
            if (backend != null) backend.clearCache();

            return McpSchema.CallToolResult.builder()
                .addTextContent("Created enum '" + added.getName() + "' at " + added.getCategoryPath().getPath() +
                    " (size=" + size + " bytes, " + enumDt.getCount() + " initial values)")
                .build();
        } catch (Exception e) {
            Msg.error(this, "Error creating enum '" + name + "'", e);
            return McpSchema.CallToolResult.builder().addTextContent("Error creating enum: " + e.getMessage()).build();
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    // ========== ADD_VALUE ==========

    private McpSchema.CallToolResult executeAddValue(Map<String, Object> arguments, Program program, GhidrAssistMCPBackend backend) {
        String name = getString(arguments, "name");
        String valueName = getString(arguments, "value_name");
        if (name == null || valueName == null) {
            return McpSchema.CallToolResult.builder().addTextContent("name and value_name parameters are required").build();
        }
        if (!(arguments.get("value") instanceof Number)) {
            return McpSchema.CallToolResult.builder().addTextContent("value parameter (integer) is required").build();
        }
        long value = ((Number) arguments.get("value")).longValue();
        String comment = (String) arguments.get("comment");

        ResolveResult resolved = resolveEnum(program.getDataTypeManager(), name, (String) arguments.get("category"));
        if (!resolved.ok) {
            return McpSchema.CallToolResult.builder().addTextContent(resolved.message).build();
        }

        ghidra.program.model.data.Enum enumDt = resolved.enumDt;
        int txId = program.startTransaction("Enum Add Value: " + valueName);
        boolean committed = false;
        try {
            if (comment != null && !comment.isEmpty()) {
                enumDt.add(valueName, value, comment);
            } else {
                enumDt.add(valueName, value);
            }
            committed = true;
            if (backend != null) backend.clearCache();
            return McpSchema.CallToolResult.builder()
                .addTextContent("Added value '" + valueName + "' = " + value +
                    " (0x" + Long.toHexString(value).toUpperCase() + ") to enum '" + enumDt.getName() + "'")
                .build();
        } catch (Exception e) {
            Msg.error(this, "Error adding value to enum", e);
            return McpSchema.CallToolResult.builder().addTextContent("Error adding value: " + e.getMessage()).build();
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    // ========== REMOVE_VALUE ==========

    private McpSchema.CallToolResult executeRemoveValue(Map<String, Object> arguments, Program program, GhidrAssistMCPBackend backend) {
        String name = getString(arguments, "name");
        String valueName = getString(arguments, "value_name");
        if (name == null || valueName == null) {
            return McpSchema.CallToolResult.builder().addTextContent("name and value_name parameters are required").build();
        }

        ResolveResult resolved = resolveEnum(program.getDataTypeManager(), name, (String) arguments.get("category"));
        if (!resolved.ok) {
            return McpSchema.CallToolResult.builder().addTextContent(resolved.message).build();
        }

        ghidra.program.model.data.Enum enumDt = resolved.enumDt;
        if (!enumDt.contains(valueName)) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Value '" + valueName + "' not found in enum '" + enumDt.getName() + "'")
                .build();
        }

        int txId = program.startTransaction("Enum Remove Value: " + valueName);
        boolean committed = false;
        try {
            enumDt.remove(valueName);
            committed = true;
            if (backend != null) backend.clearCache();
            return McpSchema.CallToolResult.builder()
                .addTextContent("Removed value '" + valueName + "' from enum '" + enumDt.getName() + "'")
                .build();
        } catch (Exception e) {
            Msg.error(this, "Error removing value from enum", e);
            return McpSchema.CallToolResult.builder().addTextContent("Error removing value: " + e.getMessage()).build();
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    // ========== RENAME_VALUE ==========

    private McpSchema.CallToolResult executeRenameValue(Map<String, Object> arguments, Program program, GhidrAssistMCPBackend backend) {
        String name = getString(arguments, "name");
        String valueName = getString(arguments, "value_name");
        String newName = getString(arguments, "new_name");
        if (name == null || valueName == null || newName == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("name, value_name, and new_name parameters are required")
                .build();
        }

        ResolveResult resolved = resolveEnum(program.getDataTypeManager(), name, (String) arguments.get("category"));
        if (!resolved.ok) {
            return McpSchema.CallToolResult.builder().addTextContent(resolved.message).build();
        }

        ghidra.program.model.data.Enum enumDt = resolved.enumDt;
        if (!enumDt.contains(valueName)) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Value '" + valueName + "' not found in enum '" + enumDt.getName() + "'")
                .build();
        }

        int txId = program.startTransaction("Enum Rename Value: " + valueName + " -> " + newName);
        boolean committed = false;
        try {
            long numValue = enumDt.getValue(valueName);
            String existingComment = enumDt.getComment(valueName);
            enumDt.remove(valueName);
            if (existingComment != null && !existingComment.isEmpty()) {
                enumDt.add(newName, numValue, existingComment);
            } else {
                enumDt.add(newName, numValue);
            }
            committed = true;
            if (backend != null) backend.clearCache();
            return McpSchema.CallToolResult.builder()
                .addTextContent("Renamed value '" + valueName + "' to '" + newName + "' in enum '" + enumDt.getName() + "'")
                .build();
        } catch (NoSuchElementException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Value '" + valueName + "' not found in enum '" + enumDt.getName() + "'")
                .build();
        } catch (Exception e) {
            Msg.error(this, "Error renaming enum value", e);
            return McpSchema.CallToolResult.builder().addTextContent("Error renaming value: " + e.getMessage()).build();
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

        ResolveResult resolved = resolveEnum(program.getDataTypeManager(), name, (String) arguments.get("category"));
        if (!resolved.ok) {
            return McpSchema.CallToolResult.builder().addTextContent(resolved.message).build();
        }

        ghidra.program.model.data.Enum enumDt = resolved.enumDt;
        int txId = program.startTransaction("Rename Enum: " + name + " -> " + newName);
        boolean committed = false;
        try {
            enumDt.setName(newName);
            committed = true;
            if (backend != null) backend.clearCache();
            return McpSchema.CallToolResult.builder()
                .addTextContent("Renamed enum '" + name + "' to '" + newName + "'")
                .build();
        } catch (InvalidNameException e) {
            return McpSchema.CallToolResult.builder().addTextContent("Invalid name '" + newName + "': " + e.getMessage()).build();
        } catch (Exception e) {
            Msg.error(this, "Error renaming enum", e);
            return McpSchema.CallToolResult.builder().addTextContent("Error renaming enum: " + e.getMessage()).build();
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

        DataTypeManager dtm = program.getDataTypeManager();
        ResolveResult resolved = resolveEnum(dtm, name, (String) arguments.get("category"));
        if (!resolved.ok) {
            return McpSchema.CallToolResult.builder().addTextContent(resolved.message).build();
        }

        ghidra.program.model.data.Enum enumDt = resolved.enumDt;

        if (enumDt.getDataTypeManager() != dtm) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Cannot delete enum '" + enumDt.getName() + "': not owned by this program's DataTypeManager (may be built-in or from an archive)")
                .build();
        }

        String path = enumDt.getCategoryPath().getPath() + "/" + enumDt.getName();
        int txId = program.startTransaction("Delete Enum: " + name);
        boolean committed = false;
        try {
            boolean removed = dtm.remove(enumDt);
            if (!removed) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Failed to delete enum '" + enumDt.getName() + "'. It may be referenced by other data types.")
                    .build();
            }
            committed = true;
            if (backend != null) backend.clearCache();
            return McpSchema.CallToolResult.builder()
                .addTextContent("Deleted enum at " + path)
                .build();
        } catch (Exception e) {
            Msg.error(this, "Error deleting enum", e);
            return McpSchema.CallToolResult.builder().addTextContent("Error deleting enum: " + e.getMessage()).build();
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    // ========== HELPERS ==========

    private static class ResolveResult {
        final boolean ok;
        final ghidra.program.model.data.Enum enumDt;
        final String message;

        private ResolveResult(boolean ok, ghidra.program.model.data.Enum enumDt, String message) {
            this.ok = ok;
            this.enumDt = enumDt;
            this.message = message;
        }

        static ResolveResult ok(ghidra.program.model.data.Enum enumDt) {
            return new ResolveResult(true, enumDt, null);
        }

        static ResolveResult error(String message) {
            return new ResolveResult(false, null, message);
        }
    }

    private ResolveResult resolveEnum(DataTypeManager dtm, String name, String category) {
        if (category != null && !category.isEmpty()) {
            DataType dt = dtm.getDataType(new CategoryPath(category), name);
            if (dt instanceof ghidra.program.model.data.Enum) {
                return ResolveResult.ok((ghidra.program.model.data.Enum) dt);
            }
            return ResolveResult.error("Enum not found: '" + name + "' in category '" + category + "'");
        }

        if (name.startsWith("/")) {
            DataType dt = dtm.getDataType(name);
            if (dt instanceof ghidra.program.model.data.Enum) {
                return ResolveResult.ok((ghidra.program.model.data.Enum) dt);
            }
            return ResolveResult.error("Enum not found at path: '" + name + "'");
        }

        List<ghidra.program.model.data.Enum> matches = new ArrayList<>();
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt instanceof ghidra.program.model.data.Enum && name.equals(dt.getName())) {
                matches.add((ghidra.program.model.data.Enum) dt);
            }
        }

        if (matches.isEmpty()) {
            return ResolveResult.error("Enum not found: '" + name + "'. Use list to see available enums.");
        }
        if (matches.size() == 1) {
            return ResolveResult.ok(matches.get(0));
        }

        // Ambiguous: same name in multiple categories
        StringBuilder msg = new StringBuilder("Ambiguous enum name '").append(name).append("': found in multiple categories:\n");
        for (ghidra.program.model.data.Enum e : matches) {
            msg.append("  ").append(e.getCategoryPath().getPath()).append("/").append(e.getName()).append("\n");
        }
        msg.append("Provide 'category' or use a full path as 'name' (e.g. '/MyCategory/").append(name).append("').");
        return ResolveResult.error(msg.toString());
    }

    private String parseAndAddValues(ghidra.program.model.data.Enum enumDt, String valuesStr) {
        // Format: "NAME=VALUE,NAME2=0x10,NAME3=20"
        String[] pairs = valuesStr.split(",");
        for (String pair : pairs) {
            pair = pair.trim();
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            if (eq < 0) {
                return "Invalid format for '" + pair + "' (expected NAME=VALUE)";
            }
            String vName = pair.substring(0, eq).trim();
            String vValueStr = pair.substring(eq + 1).trim();
            if (vName.isEmpty()) {
                return "Empty value name in: '" + pair + "'";
            }
            try {
                long numValue;
                if (vValueStr.startsWith("0x") || vValueStr.startsWith("0X")) {
                    numValue = Long.parseLong(vValueStr.substring(2), 16);
                } else {
                    numValue = Long.parseLong(vValueStr);
                }
                enumDt.add(vName, numValue);
            } catch (NumberFormatException e) {
                return "Invalid numeric value '" + vValueStr + "' for '" + vName + "'";
            } catch (Exception e) {
                return "Error adding '" + vName + "': " + e.getMessage();
            }
        }
        return null; // no error
    }

    private String getString(Map<String, Object> args, String key) {
        Object val = args.get(key);
        if (val instanceof String) {
            String s = ((String) val).trim();
            return s.isEmpty() ? null : s;
        }
        return null;
    }
}
