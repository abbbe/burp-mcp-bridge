package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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
 * HTTP front end of the extension's JSON-RPC endpoint. Kept free of Montoya
 * dependencies so its HTTP behaviour can be tested with embedded Jetty.
 */
final class McpHttpServlet extends HttpServlet {
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

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        response.setContentType("application/json");

        String originHeader = request.getHeader("Origin");
        boolean originAllowed = originHeader == null || isOriginAllowed(originHeader);
        if (!originAllowed) {
            response.setStatus(403);
            objectMapper.writeValue(response.getOutputStream(),
                jsonRpcDispatcher.createErrorResponse(null, -32000, "Origin not allowed"));
            return;
        }

        if (originHeader != null) {
            response.setHeader("Access-Control-Allow-Origin", originHeader);
            response.setHeader("Vary", "Origin");
        }
        response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");

        String clientHost = request.getRemoteAddr();

        JsonNode requestNode;
        try {
            byte[] body = readBoundedBody(request);
            requestNode = objectMapper.readTree(body);
        } catch (PayloadTooLargeException e) {
            response.setStatus(413);
            objectMapper.writeValue(response.getOutputStream(),
                jsonRpcDispatcher.createErrorResponse(null, -32001, e.getMessage()));
            return;
        } catch (Exception e) {
            response.setStatus(400);
            objectMapper.writeValue(response.getOutputStream(),
                jsonRpcDispatcher.createErrorResponse(null, -32700, "Invalid JSON payload: " + e.getMessage()));
            return;
        }

        // readTree returns null for an empty body (no exception) — guard before deref.
        if (requestNode == null) {
            response.setStatus(400);
            objectMapper.writeValue(response.getOutputStream(),
                jsonRpcDispatcher.createErrorResponse(null, -32700, "Empty JSON payload"));
            return;
        }

        JsonNode methodNode = requestNode.get("method");
        if (methodNode == null || !methodNode.isTextual()) {
            response.setStatus(400);
            objectMapper.writeValue(response.getOutputStream(),
                jsonRpcDispatcher.createErrorResponse(requestNode.get("id"), -32600, "Missing or invalid 'method'"));
            return;
        }

        try {
            JsonNode responseNode = jsonRpcDispatcher.handle(methodNode.asText(), requestNode, clientHost);
            objectMapper.writeValue(response.getOutputStream(), responseNode);
        } catch (Exception e) {
            logError.accept("Error handling MCP request: " + e.getMessage());
            response.setStatus(500);
            objectMapper.writeValue(response.getOutputStream(),
                jsonRpcDispatcher.createErrorResponse(requestNode.get("id"), -32603, "Internal error: " + e.getMessage()));
        }
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
        String originHeader = request.getHeader("Origin");
        boolean originAllowed = originHeader == null || isOriginAllowed(originHeader);
        if (!originAllowed) {
            response.setStatus(403);
            return;
        }

        if (originHeader != null) {
            response.setHeader("Access-Control-Allow-Origin", originHeader);
            response.setHeader("Vary", "Origin");
        }
        response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");
        response.setHeader("Access-Control-Max-Age", "600");
        response.setStatus(200);
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
