package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Before;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class JsonRpcDispatcherTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private Map<String, McpTool> tools;
    private FakeAsyncToolExecutor executor;
    private JsonRpcDispatcher dispatcher;

    @Before
    public void setUp() {
        tools = new LinkedHashMap<>();
        tools.put("first_tool", new FakeTool("first_tool"));
        tools.put("second_tool", new FakeTool("second_tool"));
        executor = new FakeAsyncToolExecutor(tools);
        dispatcher = new JsonRpcDispatcher(
            mapper,
            tools,
            executor,
            () -> 1000,
            () -> 8081,
            () -> "test config",
            new ToolDocumentationExporter(tools)
        );
    }

    @Test
    public void toolsListPreservesRegisteredOrder() throws Exception {
        JsonNode response = dispatcher.handle("tools/list", request(1, "tools/list"), "127.0.0.1");
        JsonNode listedTools = response.path("result").path("tools");

        assertEquals(2, listedTools.size());
        assertEquals("first_tool", listedTools.get(0).path("name").asText());
        assertEquals("second_tool", listedTools.get(1).path("name").asText());
    }

    @Test
    public void toolsCallAttachesStructuredContentForJsonText() throws Exception {
        ObjectNode request = request(2, "tools/call");
        request.set("params", mapper.valueToTree(Map.of("name", "first_tool", "arguments", Map.of())));

        JsonNode response = dispatcher.handle("tools/call", request, "127.0.0.1");

        assertFalse(response.has("error"));
        assertTrue(response.path("result").path("structuredContent").path("ok").asBoolean());
        assertEquals("first_tool", response.path("result").path("structuredContent").path("tool").asText());
    }

    @Test
    public void toolsCallAttachesStructuredContentForPlainText() throws Exception {
        tools.put("plain_tool", new PlainTextTool());
        dispatcher = new JsonRpcDispatcher(
            mapper,
            tools,
            new FakeAsyncToolExecutor(tools),
            () -> 1000,
            () -> 8081,
            () -> "test config",
            new ToolDocumentationExporter(tools)
        );

        ObjectNode request = request(6, "tools/call");
        request.set("params", mapper.valueToTree(Map.of("name", "plain_tool", "arguments", Map.of())));

        JsonNode response = dispatcher.handle("tools/call", request, "127.0.0.1");

        assertFalse(response.has("error"));
        assertEquals("plain response", response.path("result").path("structuredContent").path("text").asText());
    }

    @Test
    public void toolsCallWrapsPrimitiveJsonArraysInItems() throws Exception {
        tools.put("array_tool", new PrimitiveArrayTool());
        dispatcher = new JsonRpcDispatcher(
            mapper,
            tools,
            new FakeAsyncToolExecutor(tools),
            () -> 1000,
            () -> 8081,
            () -> "test config",
            new ToolDocumentationExporter(tools)
        );

        ObjectNode request = request(7, "tools/call");
        request.set("params", mapper.valueToTree(Map.of("name", "array_tool", "arguments", Map.of())));

        JsonNode response = dispatcher.handle("tools/call", request, "127.0.0.1");

        assertFalse(response.has("error"));
        assertEquals("first", response.path("result").path("structuredContent").path("items").get(0).asText());
        assertEquals(2, response.path("result").path("structuredContent").path("items").get(1).asInt());
    }

    @Test
    public void toolsCallAttachesStructuredContentForToolExecutionErrors() throws Exception {
        tools.put("error_tool", new ErrorTextTool());
        dispatcher = new JsonRpcDispatcher(
            mapper,
            tools,
            new FakeAsyncToolExecutor(tools),
            () -> 1000,
            () -> 8081,
            () -> "test config",
            new ToolDocumentationExporter(tools)
        );

        ObjectNode request = request(8, "tools/call");
        request.set("params", mapper.valueToTree(Map.of("name", "error_tool", "arguments", Map.of())));

        JsonNode response = dispatcher.handle("tools/call", request, "127.0.0.1");

        assertFalse(response.has("error"));
        assertTrue(response.path("result").path("isError").asBoolean());
        assertEquals("failed", response.path("result").path("structuredContent").path("text").asText());
    }

    @Test
    public void toolsCallAttachesEmptyStructuredContentForNonTextContent() throws Exception {
        tools.put("non_text_tool", new NonTextTool());
        dispatcher = new JsonRpcDispatcher(
            mapper,
            tools,
            new FakeAsyncToolExecutor(tools),
            () -> 1000,
            () -> 8081,
            () -> "test config",
            new ToolDocumentationExporter(tools)
        );

        ObjectNode request = request(9, "tools/call");
        request.set("params", mapper.valueToTree(Map.of("name", "non_text_tool", "arguments", Map.of())));

        JsonNode response = dispatcher.handle("tools/call", request, "127.0.0.1");

        assertFalse(response.has("error"));
        assertTrue(response.path("result").path("structuredContent").isObject());
        assertEquals(0, response.path("result").path("structuredContent").size());
    }

    @Test
    public void unknownToolAndUnknownMethodReturnJsonRpcErrors() throws Exception {
        ObjectNode toolRequest = request(3, "tools/call");
        toolRequest.set("params", mapper.valueToTree(Map.of("name", "missing_tool")));

        JsonNode unknownTool = dispatcher.handle("tools/call", toolRequest, "127.0.0.1");
        JsonNode unknownMethod = dispatcher.handle("missing/method", request(4, "missing/method"), "127.0.0.1");

        assertEquals(-32602, unknownTool.path("error").path("code").asInt());
        assertEquals("Unknown tool: missing_tool", unknownTool.path("error").path("message").asText());
        assertEquals(-32601, unknownMethod.path("error").path("code").asInt());
        assertEquals("Method not found: missing/method", unknownMethod.path("error").path("message").asText());
    }

    @Test
    public void docsExportUsesLiveToolMetadata() throws Exception {
        JsonNode response = dispatcher.handle("docs/export", request(5, "docs/export"), "127.0.0.1");
        JsonNode snapshot = response.path("result");

        assertEquals(Version.VERSION, snapshot.path("version").asText());
        assertEquals(2, snapshot.path("toolCount").asInt());
        assertEquals("first_tool", snapshot.path("tools").get(0).path("name").asText());
        assertEquals("Uncategorized", snapshot.path("tools").get(0).path("category").asText());
        assertEquals(1, snapshot.path("categories").size());
    }

    // --- Message classification (MCP 2025-06-18 Streamable HTTP) ------------

    @Test
    public void notificationsAreAcceptedWithoutBody() throws Exception {
        for (String json : new String[]{
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/whatever\",\"params\":{}}",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":null}}",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":99}}",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\"}"
        }) {
            JsonRpcDispatcher.Reply reply = dispatcher.handleMessage(mapper.readTree(json), "127.0.0.1");
            assertEquals(json, 202, reply.status());
            assertNull(json, reply.body());
        }
    }

    @Test
    public void validResponsesAreAcceptedWithoutBody() throws Exception {
        for (String json : new String[]{
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
            "{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"error\":{\"code\":-32000,\"message\":\"nope\"}}"
        }) {
            JsonRpcDispatcher.Reply reply = dispatcher.handleMessage(mapper.readTree(json), "127.0.0.1");
            assertEquals(json, 202, reply.status());
            assertNull(json, reply.body());
        }
    }

    @Test
    public void batchesAreRejected() throws Exception {
        String json = "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}]";
        JsonRpcDispatcher.Reply reply = dispatcher.handleMessage(mapper.readTree(json), "127.0.0.1");

        assertEquals(400, reply.status());
        assertEquals(-32600, reply.body().path("error").path("code").asInt());
        assertTrue(reply.body().path("error").path("message").asText().contains("Batch"));
    }

    @Test
    public void malformedEnvelopesAreInvalidRequestsAndNeverReachTools() throws Exception {
        String call = "\"method\":\"tools/call\",\"params\":{\"name\":\"first_tool\"}";
        String[] invalid = {
            "\"hello\"",
            "42",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":42}",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"\"}",
            "{\"jsonrpc\":\"2.0\",\"method\":\"\"}",
            "{\"id\":1," + call + "}",
            "{\"jsonrpc\":\"1.0\",\"id\":1," + call + "}",
            "{\"jsonrpc\":2.0,\"id\":1," + call + "}",
            "{\"jsonrpc\":\"2.0\",\"id\":null," + call + "}",
            "{\"jsonrpc\":\"2.0\",\"id\":true," + call + "}",
            "{\"jsonrpc\":\"2.0\",\"id\":{}," + call + "}",
            "{\"jsonrpc\":\"2.0\",\"id\":[1]," + call + "}",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":[]}",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":[1]}",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{},\"error\":{\"code\":1,\"message\":\"x\"}}",
            "{\"jsonrpc\":\"2.0\",\"id\":1}",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"message\":\"x\"}}",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1.5,\"message\":\"x\"}}",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":\"x\"}",
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"result\":{}}",
            "{\"jsonrpc\":\"2.0\",\"result\":{}}"
        };
        for (String json : invalid) {
            JsonRpcDispatcher.Reply reply = dispatcher.handleMessage(mapper.readTree(json), "127.0.0.1");
            assertEquals(json, 400, reply.status());
            assertEquals(json, -32600, reply.body().path("error").path("code").asInt());
            JsonNode id = reply.body().get("id");
            assertTrue(json + " echoed an invalid id", id == null || id.isTextual() || id.isNumber());
        }
        assertEquals(0, executor.calls.get());
    }

    @Test
    public void invalidRequestEchoesOnlyAValidId() throws Exception {
        JsonRpcDispatcher.Reply badMethod = dispatcher.handleMessage(
            mapper.readTree("{\"jsonrpc\":\"2.0\",\"id\":\"x1\",\"method\":42}"), "127.0.0.1");
        JsonRpcDispatcher.Reply badId = dispatcher.handleMessage(
            mapper.readTree("{\"jsonrpc\":\"2.0\",\"id\":true,\"method\":\"ping\"}"), "127.0.0.1");

        assertEquals("x1", badMethod.body().path("id").asText());
        assertFalse(badId.body().has("id"));
    }

    @Test
    public void requestsAreRoutedWithStatus200() throws Exception {
        JsonRpcDispatcher.Reply reply = dispatcher.handleMessage(
            mapper.readTree("{\"jsonrpc\":\"2.0\",\"id\":\"p\",\"method\":\"ping\"}"), "127.0.0.1");

        assertEquals(200, reply.status());
        assertEquals("p", reply.body().path("id").asText());
        assertTrue(reply.body().path("result").isObject());
    }

    @Test
    public void initializeAlwaysAnswersTheSupportedVersionWithoutLogging() throws Exception {
        for (String requested : new String[]{"2025-06-18", "2025-03-26", "2099-01-01"}) {
            ObjectNode request = request(1, "initialize");
            ((ObjectNode) request.get("params")).put("protocolVersion", requested);

            JsonRpcDispatcher.Reply reply = dispatcher.handleMessage(request, "127.0.0.1");
            JsonNode result = reply.body().path("result");

            assertEquals(200, reply.status());
            assertEquals("2025-06-18", result.path("protocolVersion").asText());
            assertTrue(result.path("capabilities").has("tools"));
            assertFalse(result.path("capabilities").has("logging"));
        }
    }

    @Test
    public void legacyInitializedRequestIsAnUnknownMethod() throws Exception {
        JsonNode response = dispatcher.handle("initialized", request(1, "initialized"), "127.0.0.1");
        assertEquals(-32601, response.path("error").path("code").asInt());
    }

    @Test
    public void missingOrNonTextToolNameIsInvalidParams() throws Exception {
        ObjectNode noName = request(1, "tools/call");
        ObjectNode numericName = request(2, "tools/call");
        ((ObjectNode) numericName.get("params")).put("name", 5);
        ObjectNode noParams = request(3, "tools/call");
        noParams.remove("params");

        for (ObjectNode request : List.of(noName, numericName, noParams)) {
            JsonNode response = dispatcher.handle("tools/call", request, "127.0.0.1");
            assertEquals(request.toString(), -32602, response.path("error").path("code").asInt());
        }
        assertEquals(0, executor.calls.get());
    }

    @Test
    public void toolTimeoutIsAToolExecutionError() throws Exception {
        executor.pending = true;
        JsonRpcDispatcher fastTimeout = new JsonRpcDispatcher(
            mapper, tools, executor, () -> 50, () -> 8081, () -> "test config",
            new ToolDocumentationExporter(tools));

        JsonNode response = fastTimeout.handle("tools/call", toolCall(1), "127.0.0.1");

        assertFalse(response.has("error"));
        assertEquals(1, response.path("id").asInt());
        assertTrue(response.path("result").path("isError").asBoolean());
        assertTrue(response.path("result").path("content").get(0).path("text").asText().contains("timed out"));
        assertTrue(response.path("result").path("structuredContent").isObject());
        assertTrue(executor.lastFuture.isCancelled());
        assertEquals(0, fastTimeout.inFlightCount());
    }

    @Test
    public void toolFailureIsAToolExecutionError() throws Exception {
        executor.failure = new IllegalStateException("boom");

        JsonNode response = dispatcher.handle("tools/call", toolCall(1), "127.0.0.1");

        assertFalse(response.has("error"));
        assertTrue(response.path("result").path("isError").asBoolean());
        assertTrue(response.path("result").path("content").get(0).path("text").asText().contains("boom"));
    }

    @Test
    public void cancelledNotificationStopsTheMatchingCall() throws Exception {
        executor.pending = true;
        JsonRpcDispatcher slow = new JsonRpcDispatcher(
            mapper, tools, executor, () -> 10_000, () -> 8081, () -> "test config",
            new ToolDocumentationExporter(tools));

        CompletableFuture<JsonRpcDispatcher.Reply> call = CompletableFuture.supplyAsync(() -> {
            try {
                return slow.handleMessage(toolCall(7), "127.0.0.1");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        awaitInFlight(slow, 1);

        // Neither another client's cancel nor a string id "7" matches numeric id 7.
        assertEquals(202, slow.handleMessage(cancelled(mapper.getNodeFactory().numberNode(7)), "10.0.0.2").status());
        assertEquals(202, slow.handleMessage(cancelled(mapper.getNodeFactory().textNode("7")), "127.0.0.1").status());
        assertFalse(executor.lastFuture.isCancelled());

        JsonRpcDispatcher.Reply ack = slow.handleMessage(cancelled(mapper.getNodeFactory().numberNode(7)), "127.0.0.1");
        assertEquals(202, ack.status());
        assertNull(ack.body());

        JsonRpcDispatcher.Reply reply = call.get(5, TimeUnit.SECONDS);
        assertTrue(executor.lastFuture.isCancelled());
        assertEquals(200, reply.status());
        assertEquals(7, reply.body().path("id").asInt());
        assertEquals(-32800, reply.body().path("error").path("code").asInt());
        assertEquals(0, slow.inFlightCount());
    }

    private static void awaitInFlight(JsonRpcDispatcher dispatcher, int expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (dispatcher.inFlightCount() != expected) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("call never became cancellable");
            }
            Thread.sleep(5);
        }
    }

    private ObjectNode toolCall(int id) {
        ObjectNode request = request(id, "tools/call");
        request.set("params", mapper.valueToTree(Map.of("name", "first_tool", "arguments", Map.of())));
        return request;
    }

    private ObjectNode cancelled(JsonNode requestId) {
        ObjectNode notification = mapper.createObjectNode();
        notification.put("jsonrpc", "2.0");
        notification.put("method", "notifications/cancelled");
        notification.putObject("params").set("requestId", requestId);
        return notification;
    }

    private ObjectNode request(int id, String method) {
        ObjectNode request = mapper.createObjectNode();
        request.put("jsonrpc", "2.0");
        request.put("id", id);
        request.put("method", method);
        request.set("params", mapper.createObjectNode());
        return request;
    }

    private static final class FakeTool implements McpTool {
        private final String name;

        private FakeTool(String name) {
            this.name = name;
        }

        @Override
        public Map<String, Object> getToolInfo() {
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", name);
            info.put("title", name);
            info.put("description", "Fake tool " + name);
            info.put("inputSchema", Map.of("type", "object"));
            return info;
        }

        @Override
        public Object execute(JsonNode arguments) {
            return Map.of(
                "content", List.of(Map.of("type", "text", "text", "{\"ok\":true,\"tool\":\"" + name + "\"}"))
            );
        }
    }

    private static final class FakeAsyncToolExecutor implements AsyncToolExecutor {
        private final Map<String, McpTool> tools;
        private final AtomicInteger calls = new AtomicInteger();
        /** When set, calls return a future that never completes on its own. */
        private volatile boolean pending;
        /** When set, calls fail with this exception. */
        private volatile Exception failure;
        private volatile CompletableFuture<Object> lastFuture;

        private FakeAsyncToolExecutor(Map<String, McpTool> tools) {
            this.tools = tools;
        }

        @Override
        public CompletableFuture<Object> executeAsync(String toolName, JsonNode arguments, String clientHost) {
            calls.incrementAndGet();
            if (pending) {
                lastFuture = new CompletableFuture<>();
                return lastFuture;
            }
            if (failure != null) {
                return CompletableFuture.failedFuture(failure);
            }
            try {
                return CompletableFuture.completedFuture(tools.get(toolName).execute(arguments));
            } catch (Exception e) {
                return CompletableFuture.failedFuture(e);
            }
        }

        @Override
        public Object getStats() {
            return "fake stats";
        }
    }

    private static final class PlainTextTool implements McpTool {
        @Override
        public Map<String, Object> getToolInfo() {
            return Map.of(
                "name", "plain_tool",
                "description", "Plain text tool",
                "inputSchema", Map.of("type", "object")
            );
        }

        @Override
        public Object execute(JsonNode arguments) {
            return List.of(Map.of("type", "text", "text", "plain response"));
        }
    }

    private static final class NonTextTool implements McpTool {
        @Override
        public Map<String, Object> getToolInfo() {
            return Map.of(
                "name", "non_text_tool",
                "description", "Non-text tool",
                "inputSchema", Map.of("type", "object")
            );
        }

        @Override
        public Object execute(JsonNode arguments) {
            return List.of(Map.of("type", "image", "data", "ignored"));
        }
    }

    private static final class PrimitiveArrayTool implements McpTool {
        @Override
        public Map<String, Object> getToolInfo() {
            return Map.of(
                "name", "array_tool",
                "description", "Primitive array tool",
                "inputSchema", Map.of("type", "object")
            );
        }

        @Override
        public Object execute(JsonNode arguments) {
            return List.of(Map.of("type", "text", "text", "[\"first\",2]"));
        }
    }

    private static final class ErrorTextTool implements McpTool {
        @Override
        public Map<String, Object> getToolInfo() {
            return Map.of(
                "name", "error_tool",
                "description", "Error text tool",
                "inputSchema", Map.of("type", "object")
            );
        }

        @Override
        public Object execute(JsonNode arguments) {
            return Map.of(
                "content", List.of(Map.of("type", "text", "text", "failed")),
                "isError", true
            );
        }
    }
}
