// dsh-fleet-mesh — round trip: the tools talking to this plugin's own receive route.
//
//   node test/roundtrip.test.mjs
//
// This is the test that makes the two halves one thing. It stands up:
//   * the plugin's REAL receive handler on a loopback port,
//   * a REAL fleet identity store in a temp directory,
//   * a stub registry that VERIFIES the registration signature rather than accepting it,
//
// and then drives the five tools through it. Nothing here talks to a real fleet, and nothing
// is mocked at the boundary that matters: the envelope is signed for real, POSTed over a real
// socket, verified against a real public key, and delivered to a real handler.
import { createServer } from 'node:http';
import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { apply, createMeshHandler, inject, normalizeConfig } from '../lib/index.js';
import { createToolDescriptors, registerMeshTools } from '../lib/tools.mjs';
import { canonicalJson } from '../lib/registry.mjs';

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
const ok = (name, value) => {
	if (value) {
		pass += 1;
		console.log(`  ok   ${name}`);
	} else {
		fail += 1;
		console.log(`  FAIL ${name}`);
	}
};

// ---- my own keypair, and an identity store holding it ---------------------------
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
const keyPath = join(mkdtempSync(join(tmpdir(), 'dfm-key-')), 'lily.pem');
writeFileSync(keyPath, privPem);

const fleetRoot = mkdtempSync(join(tmpdir(), 'dfm-fleet-'));
const identityFor = (name, url) =>
	`id: ${name}\nname: ${name}\nrole: Fixture\ntransports:\n  hermes_webhook:\n    url: ${url}\n    auth:\n      public_key: '${pubPem.trim()}'\n`;
mkdirSync(join(fleetRoot, 'lily'), { recursive: true });
// A peer that exists but has no URL — the send must refuse it rather than guess.
mkdirSync(join(fleetRoot, 'nourl'), { recursive: true });
writeFileSync(join(fleetRoot, 'nourl', 'identity.yaml'), `id: nourl\nname: nourl\ntransports:\n  hermes_webhook:\n    auth:\n      public_key: '${pubPem.trim()}'\n`);

// ---- the plugin's own receive route, on a real socket ---------------------------
const received = [];
const agent = {
	id: 'session-lily-1',
	session: { header: { agentPreset: 'lily', createdAt: 1 } },
	followup: (m) => received.push(['followup', m]),
	steer: (m) => received.push(['steer', m]),
	inject: (m) => received.push(['inject', m]),
};
// A context that behaves like CORDIS, not like a plain object.
//
// This is the fix for a real false green. The original stub was an ordinary object, so reading
// an undeclared service returned `undefined` — while Cordis's context proxy THROWS
// ("cannot get property \"tools\" without inject"). So `ctx.get?.('tools') ?? ctx.tools` passed
// this suite and killed the plugin in the harness, which then removed it from the profile.
// A stub more forgiving than the real thing is worse than no stub.
const logs = [];
const effectDisposers = [];
const agentService = { list: () => [agent], get: () => agent };
const cordisCtx = (services = {}) =>
	new Proxy(
		{
			logger: { info: (m) => logs.push(m), warn: (m) => logs.push(m), debug() {} },
			effect: (fn) => {
				const dispose = fn();
				if (typeof dispose === 'function') effectDisposers.push(dispose);
				return dispose;
			},
			on: () => () => {},
			...services,
		},
		{
			get: (target, prop) => {
				if (typeof prop === 'symbol' || String(prop).startsWith('_')) return Reflect.get(target, prop);
				if (prop in target) return Reflect.get(target, prop);
				throw new Error(`cannot get property "${String(prop)}" without inject`);
			},
		}
	);
const receiveCtx = cordisCtx({ agents: agentService });

let receiveHandler = null;
const receiveServer = createServer((req, res) => receiveHandler(req, res));
await new Promise((resolve) => receiveServer.listen(0, '127.0.0.1', resolve));
const receiveUrl = `http://127.0.0.1:${receiveServer.address().port}/mesh/receive`;

// Now that the port is known, publish my own identity into the store.
writeFileSync(join(fleetRoot, 'lily', 'identity.yaml'), identityFor('lily', receiveUrl));

// ---- a stub registry that VERIFIES the signature ---------------------------------
const registryCalls = [];
let lastSignatureValid = null;
const registryServer = createServer((req, res) => {
	const chunks = [];
	req.on('data', (c) => chunks.push(c));
	req.on('end', () => {
		const body = Buffer.concat(chunks).toString('utf8');
		const signature = req.headers['x-mesh-signature'] ?? '';
		registryCalls.push({ method: req.method, url: req.url, body });
		const json = (code, value) => {
			res.writeHead(code, { 'content-type': 'application/json' });
			res.end(JSON.stringify(value));
		};
		if (req.method === 'POST' && req.url === '/register') {
			// The real registry signs the CANONICAL JSON of the payload subset and verifies
			// against the public key in that same payload. Do exactly that.
			try {
				const payload = JSON.parse(body);
				lastSignatureValid = verify(
					null,
					Buffer.from(canonicalJson(payload), 'utf8'),
					createPublicKey(payload.public_key),
					Buffer.from(signature, 'base64')
				);
			} catch {
				lastSignatureValid = false;
			}
			if (!lastSignatureValid) return json(401, { error: 'invalid signature' });
			return json(200, { ok: true, peer: JSON.parse(body) });
		}
		if (req.method === 'GET' && req.url === '/peers') {
			return json(200, { peers: [{ name: 'ada', url: 'http://203.0.113.10:8752/mesh/receive' }] });
		}
		if (req.method === 'GET' && req.url.startsWith('/peers/')) {
			const name = decodeURIComponent(req.url.slice('/peers/'.length));
			return json(200, { name, url: `http://203.0.113.10:8752/mesh/receive`, role: 'Fixture' });
		}
		if (req.method === 'DELETE' && req.url.startsWith('/peers/')) return json(200, { ok: true });
		return json(404, { error: 'no route' });
	});
});
await new Promise((resolve) => registryServer.listen(0, '127.0.0.1', resolve));
const registryUrl = `http://127.0.0.1:${registryServer.address().port}`;

// ---- the tools, wired to the same store ------------------------------------------
const settings = normalizeConfig({
	fleetRoot,
	registryUrl,
	cacheDir: join(fleetRoot, '..', 'cache'),
	agents: { lily: { preset: 'lily', keyPath, url: receiveUrl, role: 'Fixture', description: 'A fixture agent' } },
});
receiveHandler = createMeshHandler(receiveCtx, settings);
const tools = Object.fromEntries(createToolDescriptors(settings).map((d) => [d.name, d]));

eq('the five tools are named as hermes-mesh names them', Object.keys(tools).sort(), [
	'mesh_deregister',
	'mesh_list',
	'mesh_register',
	'mesh_send',
	'mesh_sync',
]);

// ---- list ------------------------------------------------------------------------
console.log('\nmesh_list');
const listed = await tools.mesh_list.execute({});
eq('it sees the store', listed.count, 2);
ok('and reports which peers are actually addressable', listed.peers.find((p) => p.name === 'lily')?.reachable === true);
ok('and flags one that is not', listed.peers.find((p) => p.name === 'nourl')?.reachable === false);
eq('reachableOnly filters', (await tools.mesh_list.execute({ reachableOnly: true })).count, 1);

// ---- send, over a real socket, verified for real ---------------------------------
console.log('\nmesh_send — the round trip');
received.length = 0;
const sent = await tools.mesh_send.execute({ agent: 'lily', message: 'hello from the round trip', action: 'do', reply: 'yes' });
eq('the send reports delivery', sent.state, 'delivered');
ok('and carries an envelope id', typeof sent.message_id === 'string' && sent.message_id.length > 0);
eq('the receiver handed it to the agent', received.length, 1);
eq('through inject, because the wake list is empty by default', received[0][0], 'inject');
ok('and the prompt names the sender', received[0][1].content[0].text.startsWith('[mesh from lily'), true);
ok('and carries the body', received[0][1].content[0].text.includes('hello from the round trip'), true);
ok('and the reply expectation', received[0][1].content[0].text.includes('reply yes'), true);

console.log('\nmesh_send — the refusals');
eq('an unknown peer is refused, not guessed at', (await tools.mesh_send.execute({ agent: 'nobody', message: 'x' })).status, 'unknown-peer');
eq('a peer with no URL is unreachable', (await tools.mesh_send.execute({ agent: 'nourl', message: 'x' })).status, 'unreachable');
const noIdentity = createToolDescriptors({ ...settings, agents: {} })[1];
eq('with no outbound identity it refuses rather than signing with nothing', (await noIdentity.execute({ agent: 'lily', message: 'x' })).status, 'not-configured');

// ---- register --------------------------------------------------------------------
console.log('\nmesh_register');
const registered = await tools.mesh_register.execute({});
eq('it reports registration', registered.state, 'registered');
eq('and names itself', registered.name, 'lily');
eq('THE STUB REGISTRY VERIFIED THE SIGNATURE', lastSignatureValid, true);
ok('the registry saw the row it expects', registryCalls.some((c) => c.method === 'POST' && c.url === '/register' && JSON.parse(c.body).name === 'lily'));
eq('and the row carries my receive URL', JSON.parse(registryCalls.find((c) => c.url === '/register').body).url, receiveUrl);

// ---- sync ------------------------------------------------------------------------
console.log('\nmesh_sync');
const synced = await tools.mesh_sync.execute({});
eq('it syncs what the registry returned', synced.synced, ['ada']);
ok('and writes only to its own cache', readdirSync(settings.cacheDir).includes('ada.json'));
eq('one peer by name', (await tools.mesh_sync.execute({ agent: 'ada' })).synced, ['ada']);

// ---- deregister ------------------------------------------------------------------
console.log('\nmesh_deregister');
eq('it withdraws the row', (await tools.mesh_deregister.execute({})).state, 'removed');
ok('and the registry saw the DELETE', registryCalls.some((c) => c.method === 'DELETE' && c.url === '/peers/lily'));

// ---- the wiring: what a restart actually depends on ------------------------------
// Every other suite calls createToolDescriptors or createMeshHandler directly, so none of them
// would notice if apply() failed to hand the tools to the harness. That is the seam this closes.
console.log('\napply() — the wiring');
const applyConfig = () => ({ fleetRoot, port: 0, host: '127.0.0.1', agents: { lily: { preset: 'lily' } } });

// The regression guard for the failure that actually happened: the plugin read `ctx.tools` and
// `ctx.agents` without declaring them, Cordis threw, and the harness removed the plugin from the
// profile. If a future edit drops either from `inject`, this fails immediately.
eq('the plugin declares every service it reads', [...inject].sort(), ['agents', 'tools']);

// The helper on its own: this is the five-tools-into-the-harness step.
const handed = [];
const stubTools = {
	register: (definition) => {
		handed.push(definition);
		return () => handed.pop();
	},
};
const wiringDisposers = registerMeshTools({ tools: stubTools, defineTool: (d) => d, settings, logger: () => {} });
eq('all five tools are handed to the harness', handed.map((d) => d.name).sort(), [
	'mesh_deregister',
	'mesh_list',
	'mesh_register',
	'mesh_send',
	'mesh_sync',
]);
eq('and a disposer comes back for each', wiringDisposers.length, 5);
for (const dispose of wiringDisposers) dispose();
eq('which unregister them again', handed.length, 0);
ok('a missing tools service is refused loudly, not silently', (() => {
	try {
		registerMeshTools({ tools: null, defineTool: (d) => d, settings });
		return false;
	} catch {
		return true;
	}
})());
ok('and a missing defineTool likewise', (() => {
	try {
		registerMeshTools({ tools: stubTools, defineTool: null, settings });
		return false;
	} catch {
		return true;
	}
})());

// apply() against a CORDIS-LIKE context: it must touch only what it declared. Any undeclared
// service read throws here exactly as it does in the harness, so this is the test that would
// have caught the real failure.
logs.length = 0;
effectDisposers.length = 0;
apply(cordisCtx({ tools: stubTools, agents: agentService }), applyConfig());
await new Promise((resolve) => setTimeout(resolve, 120)); // let the dynamic import settle
ok('apply() runs against a context that throws on undeclared services', true);
// The core lives in the profile tree on a real install and is ABSENT on CI. The strong claim is
// therefore guarded on an INDEPENDENT probe of that path — never on the outcome, which would make
// the assertion tautological. (Same discipline as DSH_MESH_LIVE_STORE.)
const corePresent = Boolean(
	process.env.DSH_HOME &&
		existsSync(join(process.env.DSH_HOME, 'profiles', 'node_modules', '@deepseek-ai', 'dsh-tools', 'package.json'))
);
if (corePresent) {
	eq('the core is present, so the profile-relative fallback resolves and all five tools register', handed.length, 5);
	ok('with no resolution warning', !logs.some((l) => l.includes('could not load @deepseek-ai/dsh-tools')));
} else {
	ok(
		'the core is absent (as on CI), so it warns and carries on rather than failing the plugin',
		logs.some((l) => l.includes('could not load @deepseek-ai/dsh-tools'))
	);
}
ok('and the listener was still mounted', effectDisposers.length >= 1);
for (const dispose of effectDisposers) {
	try {
		dispose();
	} catch {
		/* already released */
	}
}

// Tear down cleanly, and AWAIT it. On Windows, calling process.exit() while a server's async
// close is still in flight trips a libuv assertion (uv_async.c) and the process exits 1 —
// which CI would read as a failed suite even though every assertion passed.
receiveServer.closeAllConnections?.();
registryServer.closeAllConnections?.();
await Promise.all([
	new Promise((resolve) => receiveServer.close(resolve)),
	new Promise((resolve) => registryServer.close(resolve)),
]);
rmSync(fleetRoot, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
// Let the loop settle before forcing the exit. `deliverToAgent` dynamically imports
// @deepseek-ai/dsh-llm, which CANNOT resolve here (the suites have no core on their path) —
// that rejected resolution leaves an async handle in flight, and on Windows exiting while
// one is closing trips a libuv assertion that turns a green suite into exit code 1.
await new Promise((resolve) => setTimeout(resolve, 150));
process.exit(fail === 0 ? 0 : 1);
