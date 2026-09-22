// dsh-fleet-mesh — suite for the outbound half: envelope signing, delivery retries, the peer
// directory, and the registry client's canonical-JSON contract.
//
//   node harness\plugins\dsh-fleet-mesh\test\outbound.test.mjs
//
// The canonical-JSON assertion is the one that matters most: registration is signed with
// `json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=False)` on the
// registry side, and a mismatch there is a 401 with no hint about which byte was wrong.
import { generateKeyPairSync, createPrivateKey, createPublicKey, verify } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildSignedRequest, deliverTo, urlFromIdentity } from '../lib/outbound.mjs';
import { canonicalJson, registryPayload, createRegistry, REGISTRY_FIELDS } from '../lib/registry.mjs';
import { parseIdentity, listPeers, readPeer, addressable, PEER_NAME_RE } from '../lib/peers.mjs';
import { verifyPayload, publicKeyFromIdentity } from '../lib/crypto.mjs';

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
const group = (title) => console.log(`\n${title}`);

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });

// ----------------------------------------------------------------- outbound ----
group('outbound — the signed request');
const request = buildSignedRequest({
	privateKey: createPrivateKey(privPem),
	from: 'lily',
	to: 'ada',
	id: 'm-1',
	action: 'do',
	reply: 'yes',
	body: 'hello sister',
	now: 1_790_060_000_000,
});
eq('the timestamp is seconds, as the fleet sends it', request.headers['x-mesh-timestamp'], '1790060000');
ok('the body is the wire JSON', request.body.toString('utf8').startsWith('{"from":"lily","text":"[mesh]'));
ok(
	'and the signature verifies over "timestamp\\nbody"',
	verifyPayload(pubPem, request.headers['x-mesh-timestamp'], request.body, request.headers['x-mesh-signature'])
);
ok(
	'the timestamped signature does NOT verify over the bare body — the fallback is only for senders that omit one',
	!verify(null, request.body, createPublicKey(pubPem), Buffer.from(request.headers['x-mesh-signature'], 'base64'))
);
eq('the envelope carries the action and reply the sender chose', /\[action:do\]\[reply:yes\]/.test(request.envelope), true);
eq('urlFromIdentity reads a plain url', urlFromIdentity('transports:\n  hermes_webhook:\n    url: http://203.0.113.10:8752/mesh/receive\n'), 'http://203.0.113.10:8752/mesh/receive');
eq('and a quoted one', urlFromIdentity("    url: 'http://x/y'\n"), 'http://x/y');

// --------------------------------------------------------------- delivery ----
group('outbound — delivery, retries and the deadline');
const json = (status, body) => async () => ({ ok: status < 400, status, text: async () => JSON.stringify(body) });
const noSleep = async () => {};

eq('a 200 is a success', (await deliverTo({ url: 'http://x', request, fetchImpl: json(200, { status: 'ok' }), sleep: noSleep })).ok, true);
eq('a 401 is unauthorized, and is not retried', (await deliverTo({ url: 'http://x', request, fetchImpl: json(401, { error: 'unauthorized' }), sleep: noSleep })).code, 'unauthorized');
eq('a 403 carries the fleet’s own token', (await deliverTo({ url: 'http://x', request, fetchImpl: json(403, { error: 'loopback-blocked' }), sleep: noSleep })).code, 'loopback-blocked');
eq('a 503 falls through to http-503', (await deliverTo({ url: 'http://x', request, fetchImpl: json(503, {}), sleep: noSleep })).code, 'http-503');

let attempts = 0;
const flaky = async () => {
	attempts += 1;
	throw new Error('ECONNREFUSED');
};
const failed = await deliverTo({ url: 'http://x', request, fetchImpl: flaky, sleep: noSleep });
eq('a dead peer is retried exactly the fleet’s three times', attempts, 3);
eq('and the result is unreachable, never a silent success', failed.code, 'unreachable');
eq('an exhausted budget refuses rather than swallowing', (await deliverTo({ url: 'http://x', request, fetchImpl: json(500, {}), sleep: noSleep, timeoutMs: 0 })).code, 'unreachable');
eq('and says why', (await deliverTo({ url: 'http://x', request, fetchImpl: json(500, {}), sleep: noSleep, timeoutMs: 0 })).detail, 'delivery exceeded the total timeout budget');

// ------------------------------------------------------------------ peers ----
group('peers — the identity store');
const adaText = `id: ada\nname: ada\ndescription: "A peer fixture — nothing personal"\nrole: Reviewer\nplatform: hermes\ntransports:\n  hermes_webhook:\n    url: http://203.0.113.10:8752/mesh/receive\n    auth:\n      public_key: '${pubPem.trim()}'\n`;
const ada = parseIdentity(adaText, 'ada');
eq('parses name, role and platform', [ada.name, ada.role, ada.platform], ['ada', 'Reviewer', 'hermes']);
eq('parses the url', ada.url, 'http://203.0.113.10:8752/mesh/receive');
ok('and the public key', Boolean(ada.publicKey));
ok('so the peer is addressable', addressable(ada));
ok('a peer with no url is not addressable', !addressable({ url: null, publicKey: 'x' }));
eq('the name grammar refuses a traversal attempt', PEER_NAME_RE.test('../etc'), false);

// A real store is OPT-IN. A published plugin must not depend on the author's private
// infrastructure, and its tests must pass on someone else's machine.
group('peers — a real store (opt-in)');
const liveRoot = process.env.DSH_MESH_LIVE_STORE;
if (liveRoot) {
	const { peers, error } = await listPeers(liveRoot);
	ok(`read the store (${peers.length} identities)`, error === null && peers.length > 0);
	eq('every entry has a name', peers.filter((p) => !p.name).map((p) => p.name), []);
	eq('every entry has a url', peers.filter((p) => !p.url).map((p) => p.name), []);
	eq('every entry has a public key', peers.filter((p) => !p.publicKey).map((p) => p.name), []);
	eq('readPeer returns one by name', typeof (await readPeer(liveRoot, peers[0].name))?.name, 'string');
} else {
	console.log('  skip — set DSH_MESH_LIVE_STORE to a directory of <name>/identity.yaml entries');
}
eq('readPeer refuses a traversal name outright', await readPeer('X:\\nonexistent', '../ada'), null);
eq('and returns null for a name that is not there', await readPeer('X:\\nonexistent', 'nobody'), null);

// --------------------------------------------------------------- registry ----
group('registry — the canonical-JSON signing contract');
eq('compact, key-sorted, no spaces — byte-identical to json.dumps(sort_keys, separators)', canonicalJson({ url: 'u', name: 'n', public_key: 'k' }), '{"name":"n","public_key":"k","url":"u"}');
eq('non-ASCII is not escaped (ensure_ascii=False)', canonicalJson({ description: 'café ☕' }), '{"description":"café ☕"}');
eq('nested keys sort too', canonicalJson({ b: { d: 1, c: 2 }, a: 1 }), '{"a":1,"b":{"c":2,"d":1}}');
eq('only registry fields survive', Object.keys(registryPayload({ name: 'n', url: 'u', public_key: 'k', nonsense: 'x', role: '' })).sort(), ['name', 'public_key', 'url']);
eq('empty and null fields are dropped, not signed as blanks', registryPayload({ name: 'n', role: '', description: null }), { name: 'n' });
eq('the registry field list is the source’s own', REGISTRY_FIELDS, ['name', 'url', 'public_key', 'role', 'description', 'ttl']);

const registry = createRegistry({
	baseUrl: 'http://203.0.113.10:8646',
	fetchImpl: json(200, { ok: true, peer: { name: 'lily' } }),
	signJson: async (payload) => `sig:${canonicalJson(payload)}`,
});
eq('health hits /health', (await registry.health()).ok, true);
const registration = await registry.register({ name: 'lily', url: 'http://198.51.100.5:8760/mesh/receive', public_key: pubPem, role: 'Architect of Presence', junk: 1 });
eq('register succeeds', registration.ok, true);
eq('and refuses when a required field is missing', (await registry.register({ name: 'lily' })).code, 'missing-fields');
eq('and refuses with no signer configured', (await createRegistry({ baseUrl: 'http://x' }).register({ name: 'l', url: 'u', public_key: 'k' })).code, 'no-signer');

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
