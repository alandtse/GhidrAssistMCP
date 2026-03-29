package ghidrassistmcp.tools;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

import java.util.List;
import java.util.Map;

public class GetFunctionSignatureTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "get_function_signature";
    }

    @Override
    public String getDescription() {
        return "Get the native GhidrAssist byte signature for a function";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema(
            "object",
            Map.of(
                "function_name_or_address",
                Map.of("type", "string", "description", "Function name, qualified name, or address")
            ),
            List.of("function_name_or_address"),
            null,
            null,
            null
        );
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String identifier = (String) arguments.get("function_name_or_address");
        if (identifier == null || identifier.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("function_name_or_address is required")
                .build();
        }

        Function function = findFunction(currentProgram, identifier);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + identifier)
                .build();
        }

        NativeFunctionSignatureGenerator generator =
            new NativeFunctionSignatureGenerator(currentProgram, TaskMonitor.DUMMY);

        JsonObject result = new JsonObject();
        result.addProperty("name", function.getName());
        result.addProperty("address", function.getEntryPoint().toString());
        String signature = generator.generate(function);
        if (signature == null) {
            result.add("signature", JsonNull.INSTANCE);
        } else {
            result.addProperty("signature", signature);
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    private Function findFunction(Program program, String identifier) {
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func != null) {
                    return func;
                }

                func = program.getFunctionManager().getFunctionContaining(addr);
                if (func != null) {
                    return func;
                }
            }
        } catch (Exception e) {
            // Not an address, continue to name lookup.
        }

        if (identifier.contains("::")) {
            String[] parts = identifier.split("::");
            if (parts.length >= 2) {
                String simpleName = parts[parts.length - 1];
                String[] namespaceParts = new String[parts.length - 1];
                System.arraycopy(parts, 0, namespaceParts, 0, parts.length - 1);

                for (Function function : program.getFunctionManager().getFunctions(true)) {
                    if (function.getName().equals(simpleName) &&
                        matchesNamespaceHierarchy(function, namespaceParts)) {
                        return function;
                    }
                }
            }
        }

        for (Function function : program.getFunctionManager().getFunctions(true)) {
            if (function.getName().equals(identifier)) {
                return function;
            }
        }

        return null;
    }

    private boolean matchesNamespaceHierarchy(Function function, String[] namespaceParts) {
        Namespace ns = function.getParentNamespace();
        for (int i = namespaceParts.length - 1; i >= 0; i--) {
            if (ns == null || ns.isGlobal()) {
                return false;
            }
            if (!ns.getName().equals(namespaceParts[i])) {
                return false;
            }
            ns = ns.getParentNamespace();
        }
        return true;
    }
}
