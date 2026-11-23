package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

/**
 * Protocol-only JSON-RPC routing used by the HTTP servlet and contract tests.
 *
 * <p>{@link #handleMessage} validates and classifies one JSON-RPC message the
 * way the MCP 2025-06-18 Streamable HTTP transport requires (requests get a
 * response, notifications and responses are accepted with 202). {@link #handle}
 * routes an already-validated request.
 */
final class JsonRpcDispatcher {
    /** The only MCP protocol revision this endpoint speaks. */
    static final String PROTOCOL_VERSION = ToolDocumentationExporter.MCP_PROTOCOL_VERSION;

    static final int INVALID_REQUEST = -32600;
    static final int METHOD_NOT_FOUND = -32601;
    static final int INVALID_PARAMS = -32602;
    static final int REQUEST_CANCELLED = -32800;

    /**
     * Outcome of one POSTed message: the HTTP status and the JSON body, or a
     * null body when the message needs no response (202 Accepted).
     */
    record Reply(int status, JsonNode body) {
        static Reply accepted() {
            return new Reply(202, null);
        }
    }

    private static final String INITIALIZE_INSTRUCTIONS =
        "CRITICAL RULES for Burp MCP Bridge tools:\n\n" +
        "1. SENDING HTTP REQUESTS: Use burp_custom_http for immediate sends, protocol controls, and raw request work. " +
        "Use burp_http_jobs for managed background HTTP batches: START returns job_id, then poll STATUS and page RESULTS. " +
        "HTTP jobs require Burp Professional's Montoya 2026.7 managed engine; PAUSE, RESUME, and CANCEL control a job. " +
        "RESULTS pages use stable input indices with PENDING placeholders; next_offset=null ends pagination, not the job. Recheck STATUS and revisit pending rows. " +
        "Jobs use direct managed sending without proxy-routing, protocol, SNI, or connection controls. " +
        "burp_repeater only creates UI tabs and CANNOT send requests. " +
        "burp_intruder only configures attacks and CANNOT execute them.\n\n" +
        "2. RAW REQUEST HOST HEADER: Specify the port in the Host header. " +
        "HTTP: Host: example.com:80 | HTTPS: Host: example.com:443. " +
        "burp_custom_http defaults to HTTPS:443 without an explicit port or URL scheme. " +
        "For HTTP jobs, URL schemes take precedence over use_https. Otherwise explicit use_https selects TLS; omission infers HTTP for port 80 and HTTPS for other ports or no port.\n\n" +
        "3. CONTENT-LENGTH: The Node bridge repairs ordinary burp_custom_http requests. " +
        "raw_request and SEND_PIPELINED preserve framing. Raw burp_http_jobs requests must supply valid framing and body lengths.\n\n" +
        "4. LINE ENDINGS: Ordinary custom HTTP request headers accept \\n or \\r\\n. " +
        "Managed-job raw request headers are normalized to CRLF; body bytes and lengths are preserved.\n\n" +
        "5. PARALLEL REQUESTS: Use burp_custom_http SEND_PARALLEL with 'requests' array (not 'request' + 'count').\n\n" +
        "6. DISCOVERY: Use burp_help to list tools or search by capability before starting.\n\n" +
        "7. SCANNING: Always use burp_scanner GET_STATUS to check scan progress after starting a scan. " +
        "Use insertionPointParams to scan specific parameters by name (like Burp UI's 'Scan selected insertion point').\n\n" +
        "8. VISIBILITY: burp_custom_http SEND_REQUEST defaults route_via_proxy=true, so it appears in Proxy History. " +
        "SEND_PARALLEL and SEND_PIPELINED default route_via_proxy=false, so they stay out of Proxy History unless you opt in. " +
        "Direct sends still appear in the Target tab (Site Map) when add_to_sitemap=true.\n\n" +
        "9. BROWSER TRAFFIC: Configure the browser to use Burp's proxy listener before expecting its requests in " +
        "burp_proxy_history or applying proxy interception rules. Browser proxy configuration depends on the client environment. " +
        "For AUTOMATIC modification, set burp_global_interceptor rules FIRST (enable, then set_auth/add_header/add_request_rule), THEN navigate - " +
        "it transforms-and-forwards inline (no queue, no polling, no deadlock; works with normal browser_click). " +
        "For MANUAL hold/modify/forward with burp_proxy_interceptor, you MUST trigger the held request NON-BLOCKING - " +
        "fire-and-forget via browser_evaluate running an un-awaited fetch(), then get_queue -> modify_request -> disable. " +
        "Do NOT trigger held traffic with a blocking browser_click/browser_navigate: the agent gets stuck in that call and cannot poll/forward (deadlock).\n\n" +
        "Tool quick reference:\n" +
        "- Send/modify HTTP requests -> burp_custom_http\n" +
        "- Background HTTP batches with progress and paginated results -> burp_http_jobs\n" +
        "- Scan for vulnerabilities -> burp_scanner\n" +
        "- View captured traffic -> burp_proxy_history (traffic that flowed through Burp's proxy listener, including default SEND_REQUEST calls)\n" +
        "- Out-of-band testing -> burp_collaborator: " +
        "Use GENERATE_PAYLOAD and use the exact unique domain it returns, " +
        "inject it into requests (SSRF, blind XXE, blind SQLi, email header injection), " +
        "then CHECK_INTERACTIONS to check if the target made DNS/HTTP requests to it.\n" +
        "- Inject auth/headers or match-replace across browser + all Burp tools -> burp_global_interceptor (AUTOMATIC rules)\n" +
        "- Manage target scope -> burp_scope";

    private final ObjectMapper objectMapper;
    private final Map<String, McpTool> tools;
    private final AsyncToolExecutor asyncToolExecutor;
    private final IntSupplier requestTimeoutMs;
    private final IntSupplier serverPort;
    private final Supplier<String> configSummary;
    private final ToolDocumentationExporter documentationExporter;
    /**
     * Tool calls that a {@code notifications/cancelled} can still stop, keyed by
     * {@link #inFlightKey}. Without sessions the key can only scope ids by client
     * host, so two clients on one host that reuse a request id concurrently can
     * cancel each other's call; the first registration of a key wins.
     */
    private final Map<String, CompletableFuture<Object>> inFlight = new ConcurrentHashMap<>();

    JsonRpcDispatcher(ObjectMapper objectMapper,
                      Map<String, McpTool> tools,
                      AsyncToolExecutor asyncToolExecutor,
                      IntSupplier requestTimeoutMs,
                      IntSupplier serverPort,
                      Supplier<String> configSummary,
                      ToolDocumentationExporter documentationExporter) {
        this.objectMapper = objectMapper;
        this.tools = tools;
        this.asyncToolExecutor = asyncToolExecutor;
        this.requestTimeoutMs = requestTimeoutMs;
        this.serverPort = serverPort;
        this.configSummary = configSummary;
        this.documentationExporter = documentationExporter;
    }

    static boolean isSupportedProtocolVersion(String version) {
        return PROTOCOL_VERSION.equals(version);
    }

    /**
     * Validate and classify one JSON-RPC message received over HTTP.
     * Requests are routed through {@link #handle}; notifications and responses
     * are accepted without a body; anything malformed is a 400 Invalid Request.
     */
    Reply handleMessage(JsonNode message, String clientHost) throws Exception {
        if (message == null || message.isMissingNode()) {
            return invalidRequest(null, "Empty JSON-RPC message");
        }
        if (message.isArray()) {
            return invalidRequest(null, "Batch requests are not supported");
        }
        if (!message.isObject()) {
            return invalidRequest(null, "JSON-RPC message must be an object");
        }

        JsonNode idNode = message.get("id");
        JsonNode echoId = isValidId(idNode) ? idNode : null;

        JsonNode version = message.get("jsonrpc");
        if (version == null || !version.isTextual() || !"2.0".equals(version.asText())) {
            return invalidRequest(echoId, "'jsonrpc' must be \"2.0\"");
        }

        if (message.has("method")) {
            JsonNode methodNode = message.get("method");
            if (!methodNode.isTextual() || methodNode.asText().isEmpty()) {
                return invalidRequest(echoId, "'method' must be a non-empty string");
            }
            JsonNode params = message.get("params");
            if (params != null && !params.isObject()) {
                return invalidRequest(echoId, "'params' must be an object");
            }
            String method = methodNode.asText();
            if (idNode == null) {
                handleNotification(method, params, clientHost);
                return Reply.accepted();
            }
            if (echoId == null) {
                return invalidRequest(null, "'id' must be a string or number");
            }
            return new Reply(200, handle(method, message, clientHost));
        }

        if (echoId != null && isValidResponseBody(message)) {
            // A client's reply to a server->client request. This server never
            // sends those, so there is nothing to correlate it with.
            return Reply.accepted();
        }
        return invalidRequest(echoId, "Message is neither a request, a notification, nor a response");
    }

    private Reply invalidRequest(JsonNode id, String detail) {
        return new Reply(400, createErrorResponse(id, INVALID_REQUEST, "Invalid Request: " + detail));
    }

    private static boolean isValidId(JsonNode id) {
        return id != null && (id.isTextual() || id.isNumber());
    }

    private static boolean isValidResponseBody(JsonNode message) {
        boolean hasResult = message.has("result");
        boolean hasError = message.has("error");
        if (hasResult == hasError) {
            return false;
        }
        if (hasResult) {
            return true;
        }
        JsonNode error = message.get("error");
        return error.isObject()
            && error.path("code").isIntegralNumber()
            && error.path("message").isTextual();
    }

    private void handleNotification(String method, JsonNode params, String clientHost) {
        if (!"notifications/cancelled".equals(method) || params == null) {
            // notifications/initialized and everything else need no action.
            return;
        }
        JsonNode requestId = params.get("requestId");
        if (!isValidId(requestId)) {
            return;
        }
        CompletableFuture<Object> future = inFlight.get(inFlightKey(clientHost, requestId));
        if (future != null) {
            // AsyncRequestHandler interrupts the worker when its future is cancelled.
            future.cancel(true);
        }
    }

    /** Number of tool calls currently cancellable; exposed for tests. */
    int inFlightCount() {
        return inFlight.size();
    }

    /** JsonNode#toString keeps "1" and 1 distinct, as JSON-RPC ids are. */
    private static String inFlightKey(String clientHost, JsonNode id) {
        return clientHost + '\0' + id.toString();
    }

    JsonNode handle(String method, JsonNode request, String clientHost) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();

        switch (method) {
            case "initialize":
                // Only one revision is supported, so the answer is always it; a
                // client that asked for another decides whether to continue.
                result.put("protocolVersion", PROTOCOL_VERSION);
                result.put("capabilities", Map.of("tools", Map.of()));
                result.put("serverInfo", Map.of("name", "burp-mcp-bridge", "version", Version.VERSION));
                result.put("instructions", INITIALIZE_INSTRUCTIONS);
                break;

            case "tools/list":
                result.put("tools", tools.entrySet().stream()
                    .map(entry -> AgentToolMetadata.forToolsList(entry.getKey(), entry.getValue().getToolInfo()))
                    .toList());
                break;

            case "tools/call":
            case "tools/call_sync":
                // Both HTTP methods wait for a result, and must share the same
                // host checks, rate limit, cancellation, and execution deadline.
                return handleAsyncToolCall(request, clientHost);

            case "docs/export":
                return createSuccessResponse(request, documentationExporter.exportSnapshot());

            case "ping":
                return createSuccessResponse(request, Map.of());

            case "stats":
                Map<String, Object> stats = new LinkedHashMap<>();
                stats.put("asyncStats", String.valueOf(asyncToolExecutor.getStats()));
                stats.put("toolCount", tools.size());
                stats.put("serverPort", serverPort.getAsInt());
                stats.put("configSummary", configSummary.get());
                result.put("stats", stats);
                break;

            default:
                return createErrorResponse(request.get("id"), METHOD_NOT_FOUND, "Method not found: " + method);
        }

        return createSuccessResponse(request, result);
    }

    private JsonNode handleAsyncToolCall(JsonNode request, String clientHost) throws Exception {
        JsonNode idNode = request.get("id");
        JsonNode params = request.get("params");
        JsonNode nameNode = params == null ? null : params.get("name");
        if (nameNode == null || !nameNode.isTextual()) {
            return createErrorResponse(idNode, INVALID_PARAMS, "Missing or invalid params.name");
        }

        String toolName = nameNode.asText();
        JsonNode arguments = params.has("arguments") ? params.get("arguments") : objectMapper.createObjectNode();
        if (!tools.containsKey(toolName)) {
            return createErrorResponse(idNode, INVALID_PARAMS, "Unknown tool: " + toolName);
        }

        String cancelKey = isValidId(idNode) ? inFlightKey(clientHost, idNode) : null;
        CompletableFuture<Object> future = null;
        try {
            future = asyncToolExecutor.executeAsync(toolName, arguments, clientHost);
            if (cancelKey != null) {
                inFlight.putIfAbsent(cancelKey, future);
            }
            Object toolResult = future.get(requestTimeoutMs.getAsInt(), TimeUnit.MILLISECONDS);

            Map<String, Object> result = new LinkedHashMap<>();
            applyToolResult(result, toolResult);
            return createSuccessResponse(request, result);
        } catch (CancellationException e) {
            // The client cancelled and will discard whatever is sent back.
            return createErrorResponse(idNode, REQUEST_CANCELLED, "Request cancelled");
        } catch (TimeoutException e) {
            return toolExecutionError(request,
                "Tool execution timed out after " + requestTimeoutMs.getAsInt() + "ms");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return toolExecutionError(request, "Tool execution interrupted");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return toolExecutionError(request, "Tool execution failed: " + cause.getMessage());
        } catch (Exception e) {
            return toolExecutionError(request, "Tool execution failed: " + e.getMessage());
        } finally {
            if (cancelKey != null && future != null) {
                inFlight.remove(cancelKey, future);
            }
            if (future != null && !future.isDone()) {
                future.cancel(true);
            }
        }
    }

    /**
     * Failures while running a known tool are tool results with isError, not
     * JSON-RPC errors, so the model sees them (MCP tools spec).
     */
    private JsonNode toolExecutionError(JsonNode request, String message) {
        Map<String, Object> result = new LinkedHashMap<>();
        applyToolResult(result, Map.of(
            "content", List.of(Map.of("type", "text", "text", message)),
            "isError", true
        ));
        return createSuccessResponse(request, result);
    }

    JsonNode createErrorResponse(JsonNode idNode, int code, String message) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("jsonrpc", "2.0");
        if (idNode != null) {
            response.put("id", idNode);
        }

        Map<String, Object> error = new LinkedHashMap<>();
        error.put("code", code);
        error.put("message", message);
        response.put("error", error);
        return objectMapper.valueToTree(response);
    }

    private JsonNode createSuccessResponse(JsonNode request, Object result) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("jsonrpc", "2.0");
        if (request.has("id")) {
            response.put("id", request.get("id"));
        }
        response.put("result", result);
        return objectMapper.valueToTree(response);
    }

    @SuppressWarnings("unchecked")
    private void applyToolResult(Map<String, Object> result, Object toolResult) {
        if (toolResult instanceof Map<?, ?> map &&
            (map.containsKey("content") || map.containsKey("structuredContent") || map.containsKey("isError"))) {
            Map<String, Object> wrapped = (Map<String, Object>) map;
            if (wrapped.containsKey("content")) {
                result.put("content", wrapped.get("content"));
            }
            if (wrapped.containsKey("structuredContent")) {
                result.put("structuredContent", wrapped.get("structuredContent"));
            }
            if (wrapped.containsKey("isError")) {
                result.put("isError", wrapped.get("isError"));
            }
            attachStructuredContentIfMissing(result);
            return;
        }

        result.put("content", toolResult);
        attachStructuredContentIfMissing(result);
    }

    /**
     * When a tool returns no structuredContent, attach the parsed JSON object, a
     * text wrapper, or an empty object fallback so strict MCP clients accept the
     * response for tools with outputSchema. This also applies to tool-execution
     * errors: CallToolResult allows structuredContent alongside isError.
     */
    @SuppressWarnings("unchecked")
    private void attachStructuredContentIfMissing(Map<String, Object> result) {
        if (result.containsKey("structuredContent")) {
            return;
        }
        Object content = result.get("content");
        if (!(content instanceof List<?> list) || list.isEmpty()) {
            result.put("structuredContent", Map.of());
            return;
        }
        Object first = list.get(0);
        if (!(first instanceof Map<?, ?> blockMap)) {
            result.put("structuredContent", Map.of());
            return;
        }
        Map<String, Object> block = (Map<String, Object>) blockMap;
        if (!"text".equals(block.get("type"))) {
            result.put("structuredContent", Map.of());
            return;
        }
        Object textValue = block.get("text");
        if (!(textValue instanceof String text)) {
            result.put("structuredContent", Map.of());
            return;
        }
        String trimmed = text.trim();
        if (trimmed.isEmpty() || (trimmed.charAt(0) != '{' && trimmed.charAt(0) != '[')) {
            result.put("structuredContent", Map.of("text", text));
            return;
        }
        try {
            Object parsed = objectMapper.readValue(trimmed, Object.class);
            if (parsed instanceof Map) {
                result.put("structuredContent", parsed);
            } else if (parsed instanceof List) {
                result.put("structuredContent", Map.of("items", parsed));
            }
        } catch (Exception ignored) {
            result.put("structuredContent", Map.of("text", text));
        }
    }
}
