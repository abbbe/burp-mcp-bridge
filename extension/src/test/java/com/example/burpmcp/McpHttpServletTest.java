package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** HTTP-level behaviour of the extension endpoint, served by embedded Jetty. */
public class McpHttpServletTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String ALLOWED_ORIGIN = "http://localhost:6274";
    private static final String DISALLOWED_ORIGIN = "http://evil.example";
    private static final long MAX_BYTES = 4096;

    private static Server server;
    private static URI endpoint;
    private static HttpClient client;

    @BeforeClass
    public static void startServer() throws Exception {
        Map<String, McpTool> tools = new LinkedHashMap<>();
        tools.put("echo_tool", new EchoTool());
        AsyncToolExecutor executor = new AsyncToolExecutor() {
            @Override
            public CompletableFuture<Object> executeAsync(String toolName, JsonNode arguments, String clientHost) {
                try {
                    return CompletableFuture.completedFuture(tools.get(toolName).execute(arguments));
                } catch (Exception e) {
                    return CompletableFuture.failedFuture(e);
                }
            }

            @Override
            public Object getStats() {
                return "stats";
            }
        };
        JsonRpcDispatcher dispatcher = new JsonRpcDispatcher(
            MAPPER, tools, executor, () -> 1000, () -> 0, () -> "config",
            new ToolDocumentationExporter(tools));
        Set<String> allowedHosts = Set.of("localhost", "127.0.0.1");

        server = new Server();
        ServerConnector connector = new ServerConnector(server);
        connector.setHost("127.0.0.1");
        connector.setPort(0);
        server.addConnector(connector);
        ServletContextHandler context = new ServletContextHandler();
        context.setContextPath("/");
        context.addServlet(new ServletHolder(new McpHttpServlet(
            MAPPER, dispatcher, allowedHosts::contains, () -> MAX_BYTES, message -> { })), "/*");
        server.setHandler(context);
        server.start();

        endpoint = URI.create("http://127.0.0.1:" + connector.getLocalPort() + "/");
        client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    }

    @AfterClass
    public static void stopServer() throws Exception {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    public void notificationIsAcceptedWithEmptyBody() throws Exception {
        HttpResponse<String> response = post("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");

        assertEquals(202, response.statusCode());
        assertEquals("", response.body());
        assertFalse(response.headers().firstValue("Content-Type").isPresent());
    }

    @Test
    public void clientResponseIsAcceptedWithEmptyBody() throws Exception {
        HttpResponse<String> response = post("{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}");

        assertEquals(202, response.statusCode());
        assertEquals("", response.body());
    }

    @Test
    public void requestGetsJsonResponse() throws Exception {
        HttpResponse<String> response = post(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"echo_tool\",\"arguments\":{}}}");

        assertEquals(200, response.statusCode());
        assertTrue(response.headers().firstValue("Content-Type").orElse("").startsWith("application/json"));
        JsonNode body = MAPPER.readTree(response.body());
        assertEquals(1, body.path("id").asInt());
        assertEquals("echoed", body.path("result").path("content").get(0).path("text").asText());
    }

    @Test
    public void batchIsRejected() throws Exception {
        HttpResponse<String> response = post("[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}]");

        assertEquals(400, response.statusCode());
        assertEquals(-32600, MAPPER.readTree(response.body()).path("error").path("code").asInt());
    }

    @Test
    public void getAndDeleteAreNotAllowed() throws Exception {
        for (String method : List.of("GET", "DELETE", "PUT")) {
            HttpResponse<String> response = send(request(method, null).build());
            assertEquals(method, 405, response.statusCode());
            assertEquals(method, "POST, OPTIONS", response.headers().firstValue("Allow").orElse(""));
        }
    }

    @Test
    public void disallowedOriginIsForbiddenForEveryMethod() throws Exception {
        for (String method : List.of("POST", "GET", "DELETE", "OPTIONS")) {
            String body = "POST".equals(method) ? "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}" : null;
            HttpResponse<String> response = send(request(method, body).header("Origin", DISALLOWED_ORIGIN).build());
            assertEquals(method, 403, response.statusCode());
            assertFalse(method, response.headers().firstValue("Access-Control-Allow-Origin").isPresent());
        }
    }

    @Test
    public void unsupportedProtocolVersionHeaderIsRejected() throws Exception {
        for (String method : List.of("POST", "GET")) {
            String body = "POST".equals(method) ? "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}" : null;
            HttpResponse<String> response = send(request(method, body)
                .header("MCP-Protocol-Version", "2025-03-26").build());
            assertEquals(method, 400, response.statusCode());
            assertTrue(method, response.body().contains("2025-06-18"));
        }
    }

    @Test
    public void supportedOrAbsentProtocolVersionHeaderIsAccepted() throws Exception {
        String ping = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";

        HttpResponse<String> withHeader = send(request("POST", ping)
            .header("MCP-Protocol-Version", "2025-06-18").build());
        HttpResponse<String> withoutHeader = post(ping);

        assertEquals(200, withHeader.statusCode());
        assertEquals(200, withoutHeader.statusCode());
    }

    @Test
    public void preflightFromAllowedOriginAdvertisesMcpHeaders() throws Exception {
        HttpResponse<String> response = send(request("OPTIONS", null)
            .header("Origin", ALLOWED_ORIGIN)
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "content-type, mcp-protocol-version")
            .build());

        assertEquals(200, response.statusCode());
        assertEquals(ALLOWED_ORIGIN, response.headers().firstValue("Access-Control-Allow-Origin").orElse(""));
        assertTrue(response.headers().firstValue("Access-Control-Allow-Headers").orElse("")
            .contains("MCP-Protocol-Version"));
        assertEquals("600", response.headers().firstValue("Access-Control-Max-Age").orElse(""));
    }

    @Test
    public void postFromAllowedOriginCarriesCorsHeaders() throws Exception {
        HttpResponse<String> response = send(request("POST", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}")
            .header("Origin", ALLOWED_ORIGIN).build());

        assertEquals(200, response.statusCode());
        assertEquals(ALLOWED_ORIGIN, response.headers().firstValue("Access-Control-Allow-Origin").orElse(""));
        assertEquals("Origin", response.headers().firstValue("Vary").orElse(""));
    }

    @Test
    public void emptyOrInvalidJsonIsAParseError() throws Exception {
        for (String body : List.of("", "{not json")) {
            HttpResponse<String> response = post(body);
            assertEquals("'" + body + "'", 400, response.statusCode());
            assertEquals(-32700, MAPPER.readTree(response.body()).path("error").path("code").asInt());
        }
    }

    @Test
    public void oversizeBodyIsRejected() throws Exception {
        HttpResponse<String> response = post("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"pad\":\""
            + "x".repeat((int) MAX_BYTES) + "\"}");

        assertEquals(413, response.statusCode());
    }

    private HttpResponse<String> post(String body) throws Exception {
        return send(request("POST", body).build());
    }

    private static HttpRequest.Builder request(String method, String body) {
        HttpRequest.BodyPublisher publisher = body == null
            ? HttpRequest.BodyPublishers.noBody()
            : HttpRequest.BodyPublishers.ofString(body);
        HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(10))
            .method(method, publisher);
        if (body != null) {
            builder.header("Content-Type", "application/json");
        }
        return builder;
    }

    private static HttpResponse<String> send(HttpRequest request) throws Exception {
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static final class EchoTool implements McpTool {
        @Override
        public Map<String, Object> getToolInfo() {
            return Map.of(
                "name", "echo_tool",
                "description", "Echo tool",
                "inputSchema", Map.of("type", "object")
            );
        }

        @Override
        public Object execute(JsonNode arguments) {
            return Map.of("content", List.of(Map.of("type", "text", "text", "echoed")));
        }
    }
}
