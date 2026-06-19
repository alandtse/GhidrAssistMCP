/*
 * MCP tool for Ghidra Debugger session management.
 *
 * Actions:
 * - status:       Current debugger state (connected, active trace, thread, snap)
 * - list_sessions: All open traces and TraceRMI connections
 * - server_info:  TraceRMI server address and listening state
 *
 * Heavy-lifting (breakpoints, registers, memory, stepping) is done via eval_python
 * using the injected `dbg` helper object.
 */
package ghidrassistmcp.tools;

import java.net.SocketAddress;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class DebuggerTool implements McpTool {

    @Override
    public String getName() {
        return "debugger";
    }

    @Override
    public String getDescription() {
        return """
            Ghidra Debugger session management. Use this tool to check connection state and list \
            active debug sessions before using eval_python for dynamic analysis.

            Actions:
              status        — Current state: is a debugger connected, which trace/thread is active, current snap
              list_sessions — All open Trace objects and active TraceRMI connections with their descriptions
              server_info   — TraceRMI TCP server address and whether it is listening for inbound connections

            For dynamic analysis (registers, memory, breakpoints, stepping) use eval_python with the \
            injected `dbg` helper. The `dbg` object is only functional when `debugger status` shows \
            connected=true. Typical workflow:
              1. `debugger status` — confirm a session is active
              2. `eval_python` with `dbg.status()`, `dbg.get_registers()`, `dbg.read_memory(addr, n)`, etc.
              3. `eval_python` with `dbg.resume()` / `dbg.step_into()` / `dbg.step_over()` to control execution
            """;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "action", Map.of(
                    "type", "string",
                    "enum", List.of("status", "list_sessions", "server_info"),
                    "description", "Action to perform"
                )
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public boolean isReadOnly() { return true; }
    @Override
    public boolean isLongRunning() { return false; }
    @Override
    public boolean isCacheable() { return false; }
    @Override
    public boolean isDestructive() { return false; }
    @Override
    public boolean isIdempotent() { return true; }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("Error: debugger tool requires a backend reference.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend) {
        String action = (String) arguments.get("action");
        if (action == null) action = "status";

        GhidrAssistMCPPlugin plugin = backend.getActivePlugin();
        if (plugin == null || plugin.getTool() == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: no active Ghidra tool available.")
                .build();
        }

        docking.Tool tool = plugin.getTool();

        return switch (action) {
            case "status" -> doStatus(tool);
            case "list_sessions" -> doListSessions(tool);
            case "server_info" -> doServerInfo(tool);
            default -> McpSchema.CallToolResult.builder()
                .addTextContent("Unknown action: " + action + ". Valid: status, list_sessions, server_info")
                .build();
        };
    }

    private McpSchema.CallToolResult doStatus(docking.Tool tool) {
        StringBuilder sb = new StringBuilder();
        try {
            Class<?> tmClass = Class.forName("ghidra.app.services.DebuggerTraceManagerService");
            Object tm = tool.getService((Class) tmClass);
            if (tm == null) {
                sb.append("connected: false\n");
                sb.append("reason: DebuggerTraceManagerService not loaded (Debugger plugin not active)\n");
                sb.append("\nTo enable: Window > Debugger > Connect, or load the Debugger plugin.");
                return McpSchema.CallToolResult.builder().addTextContent(sb.toString()).build();
            }

            Object trace = tmClass.getMethod("getCurrentTrace").invoke(tm);
            if (trace == null) {
                sb.append("connected: false\n");
                sb.append("reason: Debugger plugin is loaded but no active trace/session\n");
                sb.append("\nStart a debug session: Debugger > Debug Active Process or connect via TraceRMI.");
                return McpSchema.CallToolResult.builder().addTextContent(sb.toString()).build();
            }

            sb.append("connected: true\n");
            sb.append("trace: ").append(trace.getClass().getMethod("getName").invoke(trace)).append("\n");

            Object thread = tmClass.getMethod("getCurrentThread").invoke(tm);
            sb.append("thread: ").append(thread != null ? thread.toString() : "none").append("\n");

            long snap = (long) tmClass.getMethod("getCurrentSnap").invoke(tm);
            sb.append("snap: ").append(snap).append("\n");

            Collection<?> openTraces = (Collection<?>) tmClass.getMethod("getOpenTraces").invoke(tm);
            sb.append("open_traces: ").append(openTraces.size()).append("\n");

        } catch (Exception e) {
            sb.append("connected: false\n");
            sb.append("error: ").append(e.getMessage()).append("\n");
            Msg.warn(this, "debugger status failed", e);
        }
        return McpSchema.CallToolResult.builder().addTextContent(sb.toString()).build();
    }

    private McpSchema.CallToolResult doListSessions(docking.Tool tool) {
        StringBuilder sb = new StringBuilder();
        try {
            // Open traces
            Class<?> tmClass = Class.forName("ghidra.app.services.DebuggerTraceManagerService");
            Object tm = tool.getService((Class) tmClass);
            if (tm != null) {
                Collection<?> traces = (Collection<?>) tmClass.getMethod("getOpenTraces").invoke(tm);
                sb.append("open_traces (").append(traces.size()).append("):\n");
                for (Object t : traces) {
                    String name = (String) t.getClass().getMethod("getName").invoke(t);
                    sb.append("  - ").append(name).append("\n");
                }
            } else {
                sb.append("open_traces: Debugger plugin not loaded\n");
            }

            // TraceRMI connections
            Class<?> rmiClass = Class.forName("ghidra.app.services.TraceRmiService");
            Object rmiSvc = tool.getService((Class) rmiClass);
            if (rmiSvc != null) {
                Collection<?> conns = (Collection<?>) rmiClass.getMethod("getAllConnections").invoke(rmiSvc);
                sb.append("\ntraceRMI_connections (").append(conns.size()).append("):\n");
                for (Object c : conns) {
                    try {
                        String desc = c.getClass().getMethod("getDescription").invoke(c).toString();
                        sb.append("  - ").append(desc).append("\n");
                    } catch (Exception e) {
                        sb.append("  - ").append(c.toString()).append("\n");
                    }
                }

                Collection<?> acceptors = (Collection<?>) rmiClass.getMethod("getAllAcceptors").invoke(rmiSvc);
                if (!acceptors.isEmpty()) {
                    sb.append("\npending_acceptors (").append(acceptors.size()).append("):\n");
                    for (Object a : acceptors) {
                        try {
                            Object addr = a.getClass().getMethod("getAddress").invoke(a);
                            sb.append("  - listening on ").append(addr).append("\n");
                        } catch (Exception e) {
                            sb.append("  - ").append(a.toString()).append("\n");
                        }
                    }
                }
            } else {
                sb.append("\ntraceRMI_connections: TraceRmiService not loaded\n");
            }

        } catch (Exception e) {
            sb.append("error: ").append(e.getMessage());
            Msg.warn(this, "debugger list_sessions failed", e);
        }
        return McpSchema.CallToolResult.builder().addTextContent(sb.toString()).build();
    }

    private McpSchema.CallToolResult doServerInfo(docking.Tool tool) {
        StringBuilder sb = new StringBuilder();
        try {
            Class<?> rmiClass = Class.forName("ghidra.app.services.TraceRmiService");
            Object rmiSvc = tool.getService((Class) rmiClass);
            if (rmiSvc == null) {
                sb.append("TraceRmiService not loaded (Debugger plugin not active)");
                return McpSchema.CallToolResult.builder().addTextContent(sb.toString()).build();
            }

            boolean started = (boolean) rmiClass.getMethod("isServerStarted").invoke(rmiSvc);
            sb.append("server_started: ").append(started).append("\n");

            SocketAddress addr = (SocketAddress) rmiClass.getMethod("getServerAddress").invoke(rmiSvc);
            sb.append("server_address: ").append(addr != null ? addr.toString() : "not bound").append("\n");

            if (started) {
                sb.append("\nDebuggers can connect to this address using TraceRMI.\n");
                sb.append("Example (gdb): ghidra trace connect \"").append(addr).append("\"");
            } else {
                sb.append("\nServer not started. Use Debugger > Connect to start it or launch a backend.");
            }

        } catch (Exception e) {
            sb.append("error: ").append(e.getMessage());
            Msg.warn(this, "debugger server_info failed", e);
        }
        return McpSchema.CallToolResult.builder().addTextContent(sb.toString()).build();
    }
}
