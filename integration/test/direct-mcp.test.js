// MCP clients that connect straight to the extension's port, without the Node
// bridge. The extension must behave as a stateless MCP 2025-06-18 Streamable
// HTTP server: a real SDK client completes the handshake and calls tools, and
// the transport edges (notifications, GET, version header, batches) answer as
// the spec says.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from '../lib/session.js';
import { apiEndpoint } from '../lib/endpoints.js';

// The bridge's own SDK copy (installed by `npm ci` in bridge/), so the
// integration suite still needs nothing installed of its own.
const SDK = '../../bridge/node_modules/@modelcontextprotocol/sdk/dist/esm/client/';
const { Client } = await import(new URL(SDK + 'index.js', import.meta.url));
const { StreamableHTTPClientTransport } = await import(new URL(SDK + 'streamableHttp.js', import.meta.url));

const { host, port } = apiEndpoint();
const ENDPOINT = `http://${host}:${port}/`;

let direct;
let bridged;

before(async () => {
  direct = new Client({ name: 'burp-mcp-direct-it', version: '1.0.0' });
  await direct.connect(new StreamableHTTPClientTransport(new URL(ENDPOINT)));
  bridged = await connect();
});

after(async () => {
  await direct?.close();
  await bridged?.stop();
});

function post(body, headers = {}) {
  return fetch(ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body)
  });
}

test('SDK client negotiates 2025-06-18 and sees the same tools as the bridge', async () => {
  assert.equal(direct.getServerVersion()?.name, 'burp-mcp-bridge');
  assert.ok(direct.getServerCapabilities()?.tools, 'server advertises tools');

  const directNames = (await direct.listTools()).tools.map((t) => t.name).sort();
  const bridgedNames = (await bridged.listTools()).tools.map((t) => t.name).sort();
  assert.ok(directNames.includes('burp_help'));
  assert.deepEqual(directNames, bridgedNames);
});

test('SDK client calls burp_help directly', async () => {
  const r = await direct.callTool({ name: 'burp_help', arguments: { list: true } });
  assert.notEqual(r.isError, true, JSON.stringify(r.content));
  const text = r.content.filter((c) => c.type === 'text').map((c) => c.text).join('\n');
  assert.match(text, /burp_custom_http/);
});

test('unknown tool is a JSON-RPC invalid-params error', async () => {
  const res = await post({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'no_such_tool' } });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).error.code, -32602);
});

test('notification is accepted with 202 and no body', async () => {
  const res = await post({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(res.status, 202);
  assert.equal(await res.text(), '');
});

test('GET is 405 because no SSE stream is offered', async () => {
  const res = await fetch(ENDPOINT, { headers: { Accept: 'text/event-stream' } });
  assert.equal(res.status, 405);
  assert.match(res.headers.get('allow') ?? '', /POST/);
});

test('unsupported MCP-Protocol-Version header is 400', async () => {
  const res = await post({ jsonrpc: '2.0', id: 1, method: 'ping' }, { 'MCP-Protocol-Version': '2025-03-26' });
  assert.equal(res.status, 400);
});

test('batch is rejected with 400 invalid request', async () => {
  const res = await post([{ jsonrpc: '2.0', id: 1, method: 'ping' }]);
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error.code, -32600);
});
