// dsh-fleet-mesh — smoke suite: the actual route table, with a REAL signature.
//
//   node harness\plugins\dsh-fleet-mesh\test\smoke.mjs
//
// The unit suite proves the parts; this proves the wiring. It mounts the plugin on a
// stub web server, writes a peer identity into a temp fleet root, signs a real body
// with a real Ed25519 key, and drives the handler with fabricated req/res objects.
// That is the closest thing to a fleet POST that can run without the fleet.
import { generateKeyPairSync, createPrivateKey } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { apply, createMeshHandler, normalizeConfig } from '../lib/index.js';
import { signPayload } from '../lib/crypto.mjs';
import { buildEnvelope, wireBody } from '../lib/envelope.mjs';

let pass = 0;
let fail = 0;
const eq = (name, actual, expected) => {
	const a = JSON.stringify(actual);
	const e = JSON.stringify(expected);
	if (a === e) {
		pass += 1;
		console.log(`  ok   ${name}`);
	} else {
		fail += 1;
		console.log(`  FAIL ${name}\n         expected ${e}\n         actual   ${a}`);
	}
};

// ---- a peer, with a key of its own, in a throwaway fleet root ------------------
const peers = {};
const root = mkdtempSync(join(tmpdir(), 'dsh-fleet-mesh-smoke-'));
for (const name of ['ada', 'bob']) {
	const { privateKey, publicKey } = generateKeyPairSync('ed25519');
	peers[name] = {
		privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
		publicPem: publicKey.export({ type: 'spki', format: 'pem' }),
	};
	mkdirSync(join(root, name), { recursive: true });
	// The quoted multi-line framing — the shape the live fleet actually uses.
	writeFileSync(
		join(root, name, 'identity.yaml'),
		`id: ${name}\ntransports:\n  hermes_webhook:\n    auth:\n      public_key: '${peers[name].publicPem.trim()}'\n`
	);
}

// ---- a stub agent that records what it was handed ------------------------------
const delivered = [];
const agent = {
	id: 'session-lily-1',
	session: { header: { agentPreset: 'lily', createdAt: 1 } },
	followup: (m) => delivered.push(['followup', m]),
	steer: (m) => delivered.push(['steer', m]),
	inject: (m) => delivered.push(['inject', m]),
};
const agent2 = {
	id: 'session-echo-1',
	session: { header: { agentPreset: 'echo', createdAt: 2 } },
	followup: () => {},
	steer: () => {},
	inject: () => {},
};
const agents = { list: () => [agent, agent2], get: (id) => [agent, agent2].find((a) => a.id === id) ?? null };

const listeners = new Map();
const ctx = {
	logger: { info() {}, warn() {}, debug() {} },
	effect: (fn) => fn(),
	// The plugin DECLARES `agents` (see its `inject`) and reads it as a property. A stub that
	// served it only through a get() helper would hide the very failure that broke the real
	// load — Cordis throws on reading an undeclared service, and a forgiving stub does not.
	agents,
	on: (name, fn) => {
		listeners.set(name, fn);
		return () => listeners.delete(name);
	},
};

const settings = normalizeConfig({
	fleetRoot: root,
	// The plugin ships no subnets; the deployment names its own. A fixture here.
	allow: ['192.168.0.0/23'],
	agents: {
		lily: { preset: 'lily', wake: ['ada'] },
		// A dedicated entry with the wake budget off, so the runaway guard can be driven
		// deterministically instead of fighting the budget.
		echo: { preset: 'echo', wake: ['ada'], wakeBudgetMs: 0 },
	},
});
eq('the plugin exports apply() for the loader', typeof apply, 'function');
// The measured constraint: the harness web server is loopback-only, so dsh-fleet-mesh owns
// its listener — and defaults to loopback, meaning installing it opens nothing.
eq('defaults to loopback on the chosen mesh port', [settings.host, settings.port], ['127.0.0.1', 8760]);
const handler = createMeshHandler(ctx, settings);
eq('and builds a request handler', typeof handler, 'function');

/** Drive the mounted handler with a fabricated request. */
function call(method, path, { headers = {}, body = Buffer.alloc(0), remote = '127.0.0.1' } = {}) {
	return new Promise((resolve) => {
		const req = new EventEmitter();
		req.method = method;
		req.url = path;
		req.headers = headers;
		req.socket = { remoteAddress: remote };
		req.destroy = () => {};
		const res = {
			statusCode: 0,
			headersSent: false,
			writeHead(code) {
				this.statusCode = code;
				this.headersSent = true;
			},
			end(chunk) {
				const text = chunk ? String(chunk) : '';
				resolve({ code: this.statusCode, json: text ? JSON.parse(text) : null });
			},
			destroy() {
				resolve({ code: this.statusCode, json: null });
			},
		};
		handler(req, res);
		setImmediate(() => {
			if (body.length > 0) req.emit('data', body);
			req.emit('end');
		});
	});
}

/** Build one signed POST exactly as session_relay.py would. */
function signedPost({ from = 'ada', to = 'lily', id = 'm-1', action = 'info', reply = 'no', ref = null, text = 'hello from the fleet', timestamp = String(Date.now() / 1000), signer = from, tamper = false } = {}) {
	const envelope = buildEnvelope({ from, to, id, action, reply, ref, body: text });
	const raw = Buffer.from(wireBody(from, envelope));
	const signature = signPayload(createPrivateKey(peers[signer].privatePem), timestamp, raw);
	return {
		body: tamper ? Buffer.from(wireBody(from, `${envelope} `)) : raw,
		headers: { 'x-mesh-signature': signature, 'x-mesh-timestamp': timestamp, 'content-type': 'application/json' },
	};
}

// ---- the route table -----------------------------------------------------------
console.log('\nroutes');
const health = await call('GET', '/mesh/health');
eq('GET /mesh/health answers', health.code, 200);
eq('and reports healthy', health.json.status, 'healthy');
eq('and lists the configured agent', health.json.agents[0].name, 'lily');
eq('and reports whether delivery is possible, not just liveness', health.json.agents[0].delivery, {
	agentsService: 'ok',
	sessionsForPreset: 1,
	sessionIdOverride: null,
});
eq('and the allow list it enforces', health.json.allow, ['192.168.0.0/23']);
eq('GET /mesh/nope is a 404', (await call('GET', '/mesh/nope')).code, 404);
eq('GET /mesh/receive is not a POST', (await call('GET', '/mesh/receive')).code, 404);

console.log('\nreceive — the happy path');
delivered.length = 0;
const good = await call('POST', '/mesh/receive', signedPost());
eq('a signed envelope is accepted', good.code, 200);
eq('and reported delivered', good.json.delivered, true);
eq('a wake-listed peer opening a new thread fires a turn', good.json.mode, 'followup');
eq('the agent was handed exactly one message', delivered.length, 1);
eq('through the method the policy chose', delivered[0][0], 'followup');
eq('as a plugin-sourced message', delivered[0][1].source, { kind: 'plugin', plugin: 'dsh-fleet-mesh', form: 'mesh-receive' });
eq('carrying the peer text', delivered[0][1].content[0].text.includes('hello from the fleet'), true);
eq('and naming the sender', delivered[0][1].content[0].text.startsWith('[mesh from ada'), true);

console.log('\nreceive — idempotency and policy');
delivered.length = 0;
const dupe = await call('POST', '/mesh/receive', signedPost({ id: 'm-1' }));
eq('a redelivered envelope does not fire a second turn', dupe.json.delivered, false);
eq('it is reported as a duplicate', dupe.json.code, 'duplicate');
eq('as a success, so the sender stops retrying', dupe.code, 200);
eq('and nothing reached the agent', delivered.length, 0);

delivered.length = 0;
const offList = await call('POST', '/mesh/receive', signedPost({ from: 'bob', id: 'm-2' }));
eq('a peer off the wake list is still delivered', offList.json.delivered, true);
eq('but never wakes anyone', offList.json.mode, 'inject');
eq('and it does reach the agent', delivered[0][0], 'inject');

delivered.length = 0;
const broadcast = await call('POST', '/mesh/receive', signedPost({ from: 'ada', to: '*', id: 'm-3' }));
eq('a broadcast is delivered', broadcast.json.delivered, true);
eq('and never wakes', broadcast.json.mode, 'inject');

delivered.length = 0;
const steer = await call('POST', '/mesh/receive', signedPost({ from: 'ada', id: 'm-4', ref: 'm-1', action: 'do' }));
eq('a reply into the same thread steers', steer.json.mode, 'steer');

console.log('\nreceive — the source-address door');
eq('a peer in 192.168.1.* is served', (await call('POST', '/mesh/receive', { ...signedPost({ id: 'm-20' }), remote: '192.168.1.34' })).code, 200);
eq('a peer in 192.168.0.* is served', (await call('GET', '/mesh/health', { remote: '192.168.0.7' })).code, 200);
eq('an IPv4-mapped LAN peer is served', (await call('GET', '/mesh/health', { remote: '::ffff:192.168.1.34' })).code, 200);
eq('a peer outside the allow list is refused', (await call('POST', '/mesh/receive', { ...signedPost({ id: 'm-21' }), remote: '10.0.0.5' })).code, 403);
eq('and health is not a bypass', (await call('GET', '/mesh/health', { remote: '8.8.8.8' })).code, 403);
eq('nor is an unknown path', (await call('GET', '/mesh/nope', { remote: '192.168.2.1' })).code, 403);

console.log('\nreceive — the refusals');
eq('a tampered body fails the signature', (await call('POST', '/mesh/receive', signedPost({ id: 'm-5', tamper: true }))).code, 401);
const unknown = await call('POST', '/mesh/receive', {
	body: Buffer.from('{"from":"nobody","text":"[mesh][from:nobody][to:lily][id:m-6][action:info][reply:no] hi"}'),
	headers: { 'x-mesh-signature': 'AA==', 'x-mesh-timestamp': String(Date.now() / 1000) },
});
eq('an unknown sender is unauthorized', unknown.code, 401);
eq('a signature from the wrong key is rejected', (await call('POST', '/mesh/receive', signedPost({ from: 'ada', id: 'm-7', signer: 'bob' }))).code, 401);
eq('a timestamp outside the replay window is rejected', (await call('POST', '/mesh/receive', signedPost({ id: 'm-8', timestamp: String(Date.now() / 1000 - 3600) }))).code, 401);
eq('a recipient this substrate does not serve is a 404', (await call('POST', '/mesh/receive', signedPost({ to: 'nobody', id: 'm-9' }))).code, 404);
eq('a non-envelope body is a 400', (await call('POST', '/mesh/receive', { body: Buffer.from('{"from":"ada","text":"just chatter"}'), headers: { 'x-mesh-signature': 'AA==', 'x-mesh-timestamp': String(Date.now() / 1000) } })).code, 400);
eq('malformed JSON is a 400', (await call('POST', '/mesh/receive', { body: Buffer.from('{not json') })).code, 400);

console.log('\nreceive — wire and envelope must agree');
const mismatch = (() => {
	const envelope = buildEnvelope({ from: 'ada', to: 'lily', id: 'm-10', action: 'info', reply: 'no', body: 'x' });
	const raw = Buffer.from(wireBody('bob', envelope)); // wire says bob, envelope says ada
	const ts = String(Date.now() / 1000);
	return { body: raw, headers: { 'x-mesh-signature': signPayload(createPrivateKey(peers.bob.privatePem), ts, raw), 'x-mesh-timestamp': ts } };
})();
eq('a wire/envelope sender mismatch is unauthorized', (await call('POST', '/mesh/receive', mismatch)).code, 401);

console.log('\nreceive — the runaway guard is a breaker, not a latch');
for (let i = 0; i < 4; i += 1) {
	await call('POST', '/mesh/receive', signedPost({ to: 'echo', id: `rw-${i}` }));
}
const latched = await call('POST', '/mesh/receive', signedPost({ to: 'echo', id: 'rw-4' }));
eq('after runawayLimit mesh turns the guard refuses', latched.json.code, 'runaway');
// Our own injections carry source.kind 'plugin' — mesh traffic must never be able to
// vouch for itself and clear the breaker.
listeners.get('session/event')?.({ header: { agentPreset: 'echo' } }, { type: 'user/message', data: { source: { kind: 'plugin' } } });
eq('a plugin-sourced message cannot release it', (await call('POST', '/mesh/receive', signedPost({ to: 'echo', id: 'rw-5' }))).json.code, 'runaway');
listeners.get('session/event')?.({ header: { agentPreset: 'echo' } }, { type: 'user/message', data: { source: { kind: 'user' } } });
eq('but a real human message does', (await call('POST', '/mesh/receive', signedPost({ to: 'echo', id: 'rw-6' }))).json.delivered, true);

rmSync(root, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
