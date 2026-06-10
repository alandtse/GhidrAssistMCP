package ghidrassistmcp.scripts;

import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPHeadlessServer;

/**
 * Headless GhidraScript that starts the GhidrAssistMCP server.
 * Designed to be run as a -preScript before GhidrAssistHL scripts so that
 * the MCP server is available for tool calls during ReAct analysis.
 *
 * Usage in analyzeHeadless:
 *   -preScript GAMCPStartServerScript.java
 *   -postScript GAHLQueryScript.java ...
 */
public class GAMCPStartServerScript extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            Msg.warn(this, "GAMCPStartServerScript: No program loaded, skipping MCP server start");
            return;
        }

        String host = "localhost";
        int port = 8080;
        boolean waitForClients = false;

        // Parse optional arguments: host=... port=... wait=true|false
        String[] args = getScriptArgs();
        if (args != null) {
            for (String arg : args) {
                if (arg.startsWith("host=")) {
                    host = arg.substring(5);
                } else if (arg.startsWith("port=")) {
                    try {
                        port = Integer.parseInt(arg.substring(5));
                    } catch (NumberFormatException e) {
                        Msg.warn(this, "Invalid port argument, using default 8080");
                    }
                } else if (arg.startsWith("wait=")) {
                    waitForClients = Boolean.parseBoolean(arg.substring(5));
                }
            }
        }

        GhidrAssistMCPHeadlessServer mcpServer = GhidrAssistMCPHeadlessServer.getInstance();

        if (mcpServer.isRunning()) {
            Msg.info(this, "MCP server already running, updating program reference");
            mcpServer.setProgram(currentProgram);
            if (waitForClients) {
                waitUntilCancelled(mcpServer);
            }
            return;
        }

        Msg.info(this, "Starting headless MCP server for: " + currentProgram.getName());
        mcpServer.start(currentProgram, host, port);
        Msg.info(this, "Headless MCP server ready on " + host + ":" + port);
        if (waitForClients) {
            waitUntilCancelled(mcpServer);
        }
    }

    private void waitUntilCancelled(GhidrAssistMCPHeadlessServer mcpServer) {
        Msg.info(this, "Headless MCP server wait mode enabled; cancel the script or terminate analyzeHeadless to stop");
        try {
            while (!monitor.isCancelled() && mcpServer.isRunning()) {
                Thread.sleep(1000);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            mcpServer.stop();
        }
    }
}
