package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.Predicate;

/**
 * HTTP front end of the extension's JSON-RPC endpoint: a stateless MCP
 * 2025-06-18 Streamable HTTP server that answers every request with a single
 * JSON body (no SSE stream, no sessions, no batches).
 *
 * <p>Deliberate deviation: a missing {@code MCP-Protocol-Version} header is
 * accepted rather than treated as 2025-03-26, because the Node bridge never
 * sends it and never batches. Neither {@code Accept} nor {@code Host} is
 * enforced, for the same bridge and for sandboxed clients that reach Burp as
 * {@code host.docker.internal}.
 *
 * <p>Kept free of Montoya dependencies so its HTTP behaviour can be tested with
 * embedded Jetty.
 */
final class McpHttpServlet extends HttpServlet {
    static final String PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version";
    private static final String ALLOWED_METHODS = "POST, OPTIONS";
    private static final String ALLOWED_HEADERS =
        "Content-Type, Accept, MCP-Protocol-Version, Mcp-Session-Id, Last-Event-ID";

    private final transient ObjectMapper objectMapper;
    private final transient JsonRpcDispatcher jsonRpcDispatcher;
    private final transient Predicate<String> originHostAllowed;
    private final transient LongSupplier maxRequestBytes;
    private final transient Consumer<String> logError;

    McpHttpServlet(ObjectMapper objectMapper,
                   JsonRpcDispatcher jsonRpcDispatcher,
                   Predicate<String> originHostAllowed,
                   LongSupplier maxRequestBytes,
                   Consumer<String> logError) {
        this.objectMapper = objectMapper;
        this.jsonRpcDispatcher = jsonRpcDispatcher;
        this.originHostAllowed = originHostAllowed;
        this.maxRequestBytes = maxRequestBytes;
        this.logError = logError;
    }

    /** Checks that apply to every HTTP method before it is dispatched. */
    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String originHeader = request.getHeader("Origin");
        if (originHeader != null) {
            if (!isOriginAllowed(originHeader)) {
                writeError(response, 403, -32000, "Origin not allowed");
                return;
            }
            response.setHeader("Access-Control-Allow-Origin", originHeader);
            response.setHeader("Vary", "Origin");
            response.setHeader("Access-Control-Allow-Methods", ALLOWED_METHODS);
            response.setHeader("Access-Control-Allow-Headers", ALLOWED_HEADERS);
        }

        // Browsers never send custom headers on a CORS preflight.
        if (!"OPTIONS".equals(request.getMethod())) {
            String protocolVersion = request.getHeader(PROTOCOL_VERSION_HEADER);
            if (protocolVersion != null && !JsonRpcDispatcher.isSupportedProtocolVersion(protocolVersion)) {
                writeError(response, 400, JsonRpcDispatcher.INVALID_REQUEST,
                    "Unsupported " + PROTOCOL_VERSION_HEADER + ": " + protocolVersion
                        + " (supported: " + JsonRpcDispatcher.PROTOCOL_VERSION + ")");
                return;
            }
        }

        super.service(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        JsonNode message;
        try {
            byte[] body = readBoundedBody(request);
            message = objectMapper.readTree(body);
        } catch (PayloadTooLargeException e) {
            writeError(response, 413, -32001, e.getMessage());
            return;
        } catch (Exception e) {
            writeError(response, 400, -32700, "Invalid JSON payload: " + e.getMessage());
            return;
        }

        // readTree returns null (or a missing node) for an empty body without throwing.
        if (message == null || message.isMissingNode()) {
            writeError(response, 400, -32700, "Empty JSON payload");
            return;
        }

        JsonRpcDispatcher.Reply reply;
        try {
            reply = jsonRpcDispatcher.handleMessage(message, request.getRemoteAddr());
        } catch (Exception e) {
            logError.accept("Error handling MCP request: " + e.getMessage());
            JsonNode id = message.isObject() ? message.get("id") : null;
            response.setStatus(500);
            response.setContentType("application/json");
            objectMapper.writeValue(response.getOutputStream(),
                jsonRpcDispatcher.createErrorResponse(id, -32603, "Internal error: " + e.getMessage()));
            return;
        }

        response.setStatus(reply.status());
        if (reply.body() != null) {
            response.setContentType("application/json");
            objectMapper.writeValue(response.getOutputStream(), reply.body());
        }
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Allow", ALLOWED_METHODS);
        response.setHeader("Access-Control-Max-Age", "600");
        response.setStatus(200);
    }

    /** No SSE stream is offered, so GET is not allowed (spec: 405). */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        methodNotAllowed(response);
    }

    /** Stateless server: there is no session to delete. */
    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) {
        methodNotAllowed(response);
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) {
        methodNotAllowed(response);
    }

    @Override
    protected void doHead(HttpServletRequest request, HttpServletResponse response) {
        methodNotAllowed(response);
    }

    @Override
    protected void doTrace(HttpServletRequest request, HttpServletResponse response) {
        methodNotAllowed(response);
    }

    private static void methodNotAllowed(HttpServletResponse response) {
        response.setHeader("Allow", ALLOWED_METHODS);
        response.setStatus(405);
    }

    private void writeError(HttpServletResponse response, int status, int code, String message)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        objectMapper.writeValue(response.getOutputStream(),
            jsonRpcDispatcher.createErrorResponse(null, code, message));
    }

    private boolean isOriginAllowed(String originHeader) {
        try {
            URI uri = new URI(originHeader);
            String host = uri.getHost();
            if (host == null) {
                return false;
            }
            int port = uri.getPort();
            String hostPort = port > 0 ? host + ":" + port : host;
            boolean allowed = originHostAllowed.test(host) || originHostAllowed.test(hostPort);
            if (!allowed) {
                logError.accept("CORS origin rejected: " + originHeader);
            }
            return allowed;
        } catch (URISyntaxException e) {
            logError.accept("Invalid origin header: " + originHeader);
            return false;
        }
    }

    private byte[] readBoundedBody(HttpServletRequest request) throws IOException, PayloadTooLargeException {
        long maxBytes = maxRequestBytes.getAsLong();
        long contentLength = request.getContentLengthLong();
        if (contentLength > maxBytes) {
            throw new PayloadTooLargeException("Request body too large: " + contentLength + " bytes (max " + maxBytes + ")");
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[8192];
        long totalRead = 0;
        int nRead;
        while ((nRead = request.getInputStream().read(data, 0, data.length)) != -1) {
            totalRead += nRead;
            if (totalRead > maxBytes) {
                throw new PayloadTooLargeException("Request body exceeded limit of " + maxBytes + " bytes");
            }
            buffer.write(data, 0, nRead);
        }
        return buffer.toByteArray();
    }

    private static final class PayloadTooLargeException extends Exception {
        PayloadTooLargeException(String message) {
            super(message);
        }
    }
}
