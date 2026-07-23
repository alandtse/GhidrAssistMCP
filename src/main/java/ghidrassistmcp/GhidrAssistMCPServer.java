package ghidrassistmcp;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.server.transport.HttpServletSseServerTransportProvider;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.prompts.McpPrompt;
import ghidrassistmcp.resources.McpResource;

/**
 * Refactored MCP Server implementation that uses the backend architecture.
 * This class handles HTTP transport and delegates business logic to McpBackend.
 * Supports both Streamable HTTP and SSE transports side-by-side.
 */
public class GhidrAssistMCPServer {
    
    private final McpBackend backend;
    private final GhidrAssistMCPProvider provider;
    private Server jettyServer;
    private final String host;
    private final int port;
    
    public GhidrAssistMCPServer(String host, int port, McpBackend backend) {
        this(host, port, backend, null);
    }
    
    public GhidrAssistMCPServer(String host, int port, McpBackend backend, GhidrAssistMCPProvider provider) {
        this.host = host;
        this.port = port;
        this.backend = backend;
        this.provider = provider;
    }
    
    public void start() throws Exception {
        Msg.info(this, "Starting MCP Server initialization...");
        
        try {
            // Create Jetty server
            Msg.info(this, "Creating Jetty server on port " + port);
            jettyServer = new Server();
            
            ServerConnector connector = new ServerConnector(jettyServer);
            connector.setHost(host);
            connector.setPort(port);
            connector.setIdleTimeout(0); // Disable idle timeout so Jetty does not close idle MCP stream connections
            jettyServer.addConnector(connector);

            // Create servlet context
            Msg.info(this, "Setting up servlet context");
            ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
            context.setContextPath("/");
            jettyServer.setHandler(context);
            
            // Add CORS and Accept header normalization filter
            FilterHolder corsFilterHolder = new FilterHolder(new Filter() {
                @Override
                public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                        throws IOException, ServletException {
                    HttpServletRequest httpRequest = (HttpServletRequest) req;
                    HttpServletResponse httpResponse = (HttpServletResponse) res;

                    // Add CORS and Expose-Headers so fetch/mcp-remote clients can read Mcp-Session-Id
                    httpResponse.setHeader("Access-Control-Allow-Origin", "*");
                    httpResponse.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                    httpResponse.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept, Mcp-Session-Id, mcp-session-id, Authorization");
                    httpResponse.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id, mcp-session-id");

                    if ("OPTIONS".equalsIgnoreCase(httpRequest.getMethod())) {
                        httpResponse.setStatus(HttpServletResponse.SC_OK);
                        return;
                    }

                    // Forward GET requests without session ID (targeting base /mcp) to SSE transport handler for native SSE clients
                    String uri = httpRequest.getRequestURI();
                    if ("GET".equalsIgnoreCase(httpRequest.getMethod()) &&
                        httpRequest.getHeader("Mcp-Session-Id") == null &&
                        httpRequest.getHeader("mcp-session-id") == null &&
                        !uri.endsWith("/sse") && !uri.endsWith("/message")) {
                        req.getRequestDispatcher("/mcp/sse").forward(req, res);
                        return;
                    }

                    // Normalize Accept header if missing or incomplete for streamable transport
                    String accept = httpRequest.getHeader("Accept");
                    if (accept == null || !accept.contains("text/event-stream") || !accept.contains("application/json")) {
                        httpRequest = new HttpServletRequestWrapper(httpRequest) {
                            @Override
                            public String getHeader(String name) {
                                if ("Accept".equalsIgnoreCase(name)) {
                                    String orig = super.getHeader("Accept");
                                    return orig != null ? orig + ", text/event-stream, application/json" : "text/event-stream, application/json";
                                }
                                return super.getHeader(name);
                            }

                            @Override
                            public Enumeration<String> getHeaders(String name) {
                                if ("Accept".equalsIgnoreCase(name)) {
                                    return Collections.enumeration(List.of("text/event-stream, application/json"));
                                }
                                return super.getHeaders(name);
                            }
                        };
                    }

                    chain.doFilter(httpRequest, httpResponse);
                }
            });
            context.addFilter(corsFilterHolder, "/*", java.util.EnumSet.of(jakarta.servlet.DispatcherType.REQUEST));
            
            // Create MCP transport provider using custom ObjectMapper that ignores unknown properties
            Msg.info(this, "Creating MCP transport providers");
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            JacksonMcpJsonMapper mapper = new JacksonMcpJsonMapper(objectMapper);
            String mcpEndpoint = "/mcp";

            HttpServletStreamableServerTransportProvider streamableTransportProvider =
                HttpServletStreamableServerTransportProvider.builder()
                    .jsonMapper(mapper)
                    .mcpEndpoint(mcpEndpoint)
                    .keepAliveInterval(Duration.ofSeconds(15))
                    .build();

            HttpServletSseServerTransportProvider sseTransportProvider =
                HttpServletSseServerTransportProvider.builder()
                    .jsonMapper(mapper)
                    .sseEndpoint("/mcp/sse")
                    .messageEndpoint("/mcp/message")
                    .build();

            // Build MCP server using backend for configuration
            Msg.info(this, "Building MCP server with backend tools");
            var streamableServerBuilder = McpServer.sync(streamableTransportProvider)
                .serverInfo(backend.getServerInfo())
                .capabilities(backend.getCapabilities());

            var sseServerBuilder = McpServer.sync(sseTransportProvider)
                .serverInfo(backend.getServerInfo())
                .capabilities(backend.getCapabilities());

            // Register each tool individually with its own handler
            for (McpSchema.Tool toolSchema : backend.getAvailableTools()) {
                String toolName = toolSchema.name();
                BiFunction<McpSyncServerExchange, McpSchema.CallToolRequest, McpSchema.CallToolResult> toolHandler =
                    (exchange, request) -> {
                        // The backend now handles all logging through event listeners
                        Map<String, Object> params = request.arguments();
                        return backend.callTool(toolName, params);
                    };

                streamableServerBuilder.toolCall(toolSchema, toolHandler);
                sseServerBuilder.toolCall(toolSchema, toolHandler);
                Msg.info(this, "Registered tool with MCP server: " + toolName);
            }

            // Register MCP resources and prompts if backend supports them
            if (backend instanceof GhidrAssistMCPBackend) {
                GhidrAssistMCPBackend ghidraBackend = (GhidrAssistMCPBackend) backend;
                registerResources(streamableServerBuilder, ghidraBackend);
                registerPrompts(streamableServerBuilder, ghidraBackend);
                registerResources(sseServerBuilder, ghidraBackend);
                registerPrompts(sseServerBuilder, ghidraBackend);
            }

            streamableServerBuilder.build();
            sseServerBuilder.build();
            
            // Register MCP servlets (register SSE transport before Streamable to prevent wildcard route hijacking)
            Msg.info(this, "Registering MCP servlets");
            
            try {
                ServletHolder mcpSseServletHolder = new ServletHolder("mcp-sse-transport", sseTransportProvider);
                mcpSseServletHolder.setAsyncSupported(true);
                context.addServlet(mcpSseServletHolder, "/sse");
                context.addServlet(mcpSseServletHolder, "/message");
                context.addServlet(mcpSseServletHolder, "/mcp/sse");
                context.addServlet(mcpSseServletHolder, "/mcp/message");

                ServletHolder mcpStreamableServletHolder = new ServletHolder("mcp-streamable-transport", streamableTransportProvider);
                mcpStreamableServletHolder.setAsyncSupported(true);
                context.addServlet(mcpStreamableServletHolder, "/mcp");
                context.addServlet(mcpStreamableServletHolder, "/mcp/");
                Msg.info(this, "Registered MCP Streamable and SSE servlet mappings");
                
                // Log configuration
                Msg.info(this, "Streamable HTTP transport provider class: " + streamableTransportProvider.getClass().getName());
                Msg.info(this, "Streamable MCP endpoint: http://" + host + ":" + port + mcpEndpoint);
                
            } catch (Exception e) {
                Msg.error(this, "Failed to register MCP servlet", e);
            }
            
            // Start Jetty server
            Msg.info(this, "Starting Jetty server...");
            jettyServer.start();
            
            // Verify server is listening
            if (jettyServer.isStarted()) {
                Msg.info(this, "GhidrAssistMCP Server successfully started on port " + port);
                Msg.info(this, "MCP Streamable endpoint: http://" + host + ":" + port + mcpEndpoint);
                Msg.info(this, "Server state: " + jettyServer.getState());
                
                // Log all registered servlets
                var servletHandler = context.getServletHandler();
                var servletMappings = servletHandler.getServletMappings();
                Msg.info(this, "Registered servlet mappings:");
                for (var mapping : servletMappings) {
                    Msg.info(this, "  " + mapping.getServletName() + " -> " + String.join(", ", mapping.getPathSpecs()));
                }
                
                // Log server startup to UI
                if (provider != null) {
                    provider.logSession("Jetty server listening on port " + port);
                    provider.logSession("Registered " + backend.getAvailableTools().size() + " MCP tools");
                    provider.logSession("Ready for MCP client connections");
                }
            } else {
                Msg.error(this, "Failed to start Jetty server - server not in started state");
            }
            
        } catch (Exception e) {
            Msg.error(this, "Exception during MCP Server startup: " + e.getMessage(), e);
            throw e;
        }
    }
    
    public void stop() throws Exception {
        if (jettyServer != null) {
            jettyServer.stop();
            Msg.info(this, "GhidrAssistMCP Server stopped");
        }
    }
    
    public void setCurrentProgram(Program program) {
        backend.onProgramActivated(program);
    }

    /**
     * Register MCP prompts with the server builders.
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private void registerPrompts(McpServer.SyncSpecification serverBuilder,
                                  GhidrAssistMCPBackend ghidraBackend) {
        try {
            List<McpPrompt> prompts = ghidraBackend.getAvailablePrompts();
            java.util.List<McpServerFeatures.SyncPromptSpecification> promptSpecs = new java.util.ArrayList<>();

            for (McpPrompt prompt : prompts) {
                // Create McpSchema.Prompt for each prompt
                McpSchema.Prompt mcpPrompt = new McpSchema.Prompt(
                    prompt.getName(),
                    prompt.getDescription(),
                    prompt.getArguments()
                );

                // Create handler for getting the prompt
                BiFunction<McpSyncServerExchange, McpSchema.GetPromptRequest, McpSchema.GetPromptResult> promptHandler =
                    (exchange, request) -> {
                        Map<String, Object> rawArgs = request.arguments();
                        Map<String, String> args = new java.util.HashMap<>();
                        if (rawArgs != null) {
                            for (Map.Entry<String, Object> entry : rawArgs.entrySet()) {
                                args.put(entry.getKey(), entry.getValue() != null ? entry.getValue().toString() : null);
                            }
                        }
                        Program program = ghidraBackend.getCurrentProgram();
                        return prompt.generatePrompt(args, program);
                    };

                // Create specification
                McpServerFeatures.SyncPromptSpecification spec =
                    new McpServerFeatures.SyncPromptSpecification(mcpPrompt, promptHandler);
                promptSpecs.add(spec);
                Msg.info(this, "Prepared prompt for registration: " + prompt.getName());
            }

            // Register all prompts with builder
            if (!promptSpecs.isEmpty()) {
                serverBuilder.prompts(promptSpecs);
                Msg.info(this, "Registered " + promptSpecs.size() + " MCP prompts");
            }

        } catch (Exception e) {
            Msg.warn(this, "Failed to register MCP prompts: " + e.getMessage(), e);
        }
    }

    /**
     * Register MCP resources with the server builders.
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private void registerResources(McpServer.SyncSpecification serverBuilder,
                                   GhidrAssistMCPBackend ghidraBackend) {
        try {
            List<McpResource> resources = ghidraBackend.getAvailableResources();
            java.util.List<McpServerFeatures.SyncResourceSpecification> resourceSpecs = new java.util.ArrayList<>();

            for (McpResource resource : resources) {
                // Create McpSchema.Resource for each resource
                McpSchema.Resource mcpResource = McpSchema.Resource.builder()
                    .uri(resource.getUriPattern())
                    .name(resource.getName())
                    .description(resource.getDescription())
                    .mimeType(resource.getMimeType())
                    .build();

                // Create handler for reading the resource
                BiFunction<McpSyncServerExchange, McpSchema.ReadResourceRequest, McpSchema.ReadResourceResult> readHandler =
                    (exchange, request) -> {
                        String uri = request.uri();
                        String content = ghidraBackend.readResource(uri);

                        if (content == null) {
                            content = "{\"error\": \"Resource not found: " + uri + "\"}";
                        }

                        McpSchema.ResourceContents contents = new McpSchema.TextResourceContents(
                            uri,
                            resource.getMimeType(),
                            content
                        );

                        return new McpSchema.ReadResourceResult(List.of(contents));
                    };

                // Create specification
                McpServerFeatures.SyncResourceSpecification spec =
                    new McpServerFeatures.SyncResourceSpecification(mcpResource, readHandler);
                resourceSpecs.add(spec);
                Msg.info(this, "Prepared resource for registration: " + resource.getName());
            }

            // Register all resources with builder
            if (!resourceSpecs.isEmpty()) {
                serverBuilder.resources(resourceSpecs);
                Msg.info(this, "Registered " + resourceSpecs.size() + " MCP resources");
            }

        } catch (Exception e) {
            Msg.warn(this, "Failed to register MCP resources: " + e.getMessage(), e);
        }
    }
}