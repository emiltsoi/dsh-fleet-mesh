// dsh-mesh — unit suite for the pure modules: envelope, crypto, policy, delivery.
//
//   node harness\plugins\dsh-mesh\test\mesh.test.mjs
//
// Everything here is pure, so it runs without a harness, a network or a key on disk.
// The route table — the part that needs a real signature and a stub web server — is
// in smoke.mjs.
import { generateKeyPairSync, createPrivateKey } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseEnvelope, buildEnvelope, envelopeProblems, wireBody } from '../lib/envelope.mjs';
import { isAllowed, inCidr4, normalizeIp } from '../lib/access.mjs';
import { loadPublicKey, publicPemOf, signPayload, verifyPayload, publicKeyFromIdentity } from '../lib/crypto.mjs';
import { defaultPolicy, initialState, decideDelivery, recordDelivery, beginTurn, auditLine, recordHumanInput } from '../lib/policy.mjs';
import { resolveAgent, deliverToAgent, renderPrompt } from '../lib/deliver.mjs';

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

// ---------------------------------------------------------------- envelope ----
group('envelope');
const canonical = '[mesh][v:1][from:ada][to:lily][id:m-1][action:info][reply:no] hello there';
eq('parses the canonical header', parseEnvelope(canonical), {
	v: '1',
	from: 'ada',
	to: 'lily',
	id: 'm-1',
	session: null,
	fromSession: null,
	action: 'info',
	reply: 'no',
	ref: null,
	body: 'hello there',
});
eq('tolerates missing action/reply (defaults info/no)', parseEnvelope('[mesh][from:x][to:y][id:z] hi'), {
	v: '1',
	from: 'x',
	to: 'y',
	id: 'z',
	session: null,
	fromSession: null,
	action: 'info',
	reply: 'no',
	ref: null,
	body: 'hi',
});
eq(
	'parses session + from_session + ref in canonical order',
	parseEnvelope('[mesh][from:a][to:b][id:c][session:review][from_session:main][action:do][reply:yes][ref:c-0] body')?.session,
	'review'
);
eq('reply: end is accepted (the schema enum omits it, the skill documents it)', envelopeProblems(parseEnvelope('[mesh][from:a][to:b][id:c][action:do][reply:end] x')), []);
eq('a non-envelope returns null', parseEnvelope('just a message'), null);
eq('a broadcast recipient is legal', envelopeProblems(parseEnvelope('[mesh][from:a][to:*][id:c][action:info][reply:no] x')), []);
eq('a bad action is reported', envelopeProblems(parseEnvelope('[mesh][from:a][to:b][id:c][action:shout][reply:no] x')), ['action']);
eq('a traversal-shaped sender is rejected by the name grammar', envelopeProblems(parseEnvelope('[mesh][from:../etc][to:b][id:c][action:info][reply:no] x')), ['from']);
eq(
	'build -> parse round-trips every token',
	parseEnvelope(buildEnvelope({ from: 'lily', to: 'ada', id: 'r-1', action: 'do', reply: 'yes', ref: 'm-1', body: 'answer' })),
	{
		v: '1',
		from: 'lily',
		to: 'ada',
		id: 'r-1',
		session: null,
		fromSession: null,
		action: 'do',
		reply: 'yes',
		ref: 'm-1',
		body: 'answer',
	}
);
eq('wireBody orders keys from,text (sort_keys parity with the sender)', wireBody('lily', 'X'), '{"from":"lily","text":"X"}');

// ------------------------------------------------------------------ crypto ----
group('crypto');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
ok('publicPemOf reproduces the SPKI PEM', publicPemOf(createPrivateKey(privPem)) === pubPem);

const body = Buffer.from('{"from":"ada","text":"[mesh][from:ada][to:lily][id:m-1][action:info][reply:no] hi"}');
const ts = '1790060000.5';
const sig = signPayload(createPrivateKey(privPem), ts, body);
ok('verifies the timestamped form', verifyPayload(pubPem, ts, body, sig));
ok('rejects a tampered body', !verifyPayload(pubPem, ts, Buffer.from(body.toString() + ' '), sig));
ok('rejects a wrong timestamp', !verifyPayload(pubPem, '1790060001.5', body, sig));
ok('rejects a truncated signature', !verifyPayload(pubPem, ts, body, sig.slice(0, 20)));
const bareSig = signPayload(createPrivateKey(privPem), '', body);
ok('accepts the timestamp-less form via the receiver fallback', verifyPayload(pubPem, '', body, bareSig));
ok('accepts a raw 32-byte base64 public key (the other framing mesh_core tolerates)', (() => {
	const der = Buffer.from(pubPem.split('\n').filter((l) => !l.startsWith('-----')).join(''), 'base64');
	return verifyPayload(der.subarray(12).toString('base64'), ts, body, sig);
})());
eq('an unreadable key is false, not a throw', verifyPayload('not a key', ts, body, sig), false);

const tmp = mkdtempSync(join(tmpdir(), 'dsh-mesh-'));
try {
	const block = join(tmp, 'block.yaml');
	writeFileSync(block, `id: ada\ntransports:\n  hermes_webhook:\n    auth:\n      public_key: |\n        -----BEGIN PUBLIC KEY-----\n        ${pubPem.split('\n')[1]}\n        -----END PUBLIC KEY-----\n`);
	eq('reads a block-scalar public key', publicKeyFromIdentity(readFileSync(block, 'utf8')), pubPem.trim());

	const quoted = join(tmp, 'quoted.yaml');
	writeFileSync(quoted, `auth:\n  public_key: '${pubPem.trim()}'\n`);
	eq('reads a quoted inline public key', publicKeyFromIdentity(readFileSync(quoted, 'utf8')), pubPem.trim());

	const live = join(tmp, 'live.yaml');
	writeFileSync(live, `id: ada\nname: ada\ntransports:\n  hermes_webhook:\n    auth:\n      public_key: '-----BEGIN PUBLIC KEY-----\n\n        ${pubPem.split('\n')[1]}\n\n        -----END PUBLIC KEY-----\n\n        '\nplatform: hermes\n`);
	ok('reads the real ada-shaped identity (blank lines and all)', Boolean(loadPublicKey(publicKeyFromIdentity(readFileSync(live, 'utf8')))));
} finally {
	rmSync(tmp, { recursive: true, force: true });
}

// ------------------------------------------------------------------ access ----
group('access — the source-address door');
const LAN = ['192.168.0.0/23']; // a fixture: the plugin itself ships no subnets
eq(
	'a /23 is exactly "192.168.0.* and 192.168.1.*"',
	[inCidr4('192.168.0.1', '192.168.0.0/23'), inCidr4('192.168.1.255', '192.168.0.0/23'), inCidr4('192.168.2.0', '192.168.0.0/23')],
	[true, true, false]
);
eq('a peer inside the configured subnet is admitted', isAllowed('192.168.1.34', LAN), true);
eq('an IPv4-mapped address is normalized first', normalizeIp('::ffff:192.168.1.34'), '192.168.1.34');
eq('and is then admitted', isAllowed('::ffff:192.168.1.34', LAN), true);
eq('loopback is always admitted', [isAllowed('127.0.0.1'), isAllowed('::1')], [true, true]);
eq('but with NO configured subnets, loopback is all there is', isAllowed('192.168.1.34'), false);
eq('other private space is refused', isAllowed('10.0.0.5', LAN), false);
eq('the subnet just outside is refused', isAllowed('192.168.2.1', LAN), false);
eq('a public address is refused', isAllowed('8.8.8.8', LAN), false);
eq('a public IPv6 peer is refused', isAllowed('2606:4700::1111', LAN), false);
eq('a link-local zone index does not confuse it', isAllowed('fe80::1%eth0', LAN), false);
eq('an empty address is refused', isAllowed(''), false);
eq('a custom allow list replaces the default', isAllowed('10.1.2.3', ['10.0.0.0/8']), true);
eq('a malformed CIDR admits nothing', isAllowed('192.168.1.1', ['192.168.1.0/99']), false);

// ------------------------------------------------------------------ policy ----
group('policy');
// The plugin ships an EMPTY wake list — who may wake an agent is a deployment's decision.
// The tests state their own fixture rather than inheriting one.
const policy = defaultPolicy({ wake: ['ada'] });
const env = (over = {}) => ({ ...parseEnvelope(canonical), ...over });
const t0 = 1_000_000;

eq('a wake-listed peer opening a new thread starts a turn', decideDelivery({ policy, envelope: env({ from: 'ada' }), state: initialState(), now: t0 }).mode, 'followup');
eq('a peer off the wake list never wakes', decideDelivery({ policy, envelope: env({ from: 'bob' }), state: initialState(), now: t0 }).mode, 'inject');
eq('a broadcast never wakes, even from a listed peer', decideDelivery({ policy, envelope: env({ from: 'ada', to: '*' }), state: initialState(), now: t0 }).mode, 'inject');
eq('a ref means same-thread, so it steers', decideDelivery({ policy, envelope: env({ from: 'ada', ref: 'm-0' }), state: initialState(), now: t0 }).mode, 'steer');
eq('action:do from a listed peer steers', decideDelivery({ policy, envelope: env({ from: 'ada', action: 'do' }), state: initialState(), now: t0 }).mode, 'steer');
eq('the wake budget downgrades a second new thread to inject', decideDelivery({ policy, envelope: env({ from: 'ada' }), state: { ...initialState(), lastWakeAt: t0 - 1000 }, now: t0 }).mode, 'inject');
eq('the budget has expired after the window', decideDelivery({ policy, envelope: env({ from: 'ada' }), state: { ...initialState(), lastWakeAt: t0 - policy.wakeBudgetMs - 1 }, now: t0 }).mode, 'followup');
eq('a duplicate is refused, never re-fired', decideDelivery({ policy, envelope: env({ from: 'ada' }), state: { ...initialState(), seen: new Set(['m-1']) }, now: t0 }).code, 'duplicate');
eq('the runaway guard stops a two-agent loop', decideDelivery({ policy, envelope: env({ from: 'ada' }), state: { ...initialState(), turnsWithoutHuman: policy.runawayLimit }, now: t0 }).code, 'runaway');
eq('the per-turn injection cap refuses', decideDelivery({ policy, envelope: env({ from: 'bob' }), state: { ...initialState(), injectedThisTurn: policy.maxInjectedPerTurn }, now: t0 }).code, 'cap');

let state = initialState(t0);
state = recordDelivery(state, { envelope: env({ from: 'ada' }), mode: 'followup', now: t0 });
eq('recording a wake sets the budget clock', state.lastWakeAt, t0);
eq('and counts a mesh-initiated turn', state.turnsWithoutHuman, 1);
state = recordDelivery(state, { envelope: env({ from: 'ada', id: 'm-2' }), mode: 'followup', now: t0 + 1, humanInput: true });
eq('human input resets the runaway counter', state.turnsWithoutHuman, 0);
state = recordDelivery(state, { envelope: env({ from: 'ada', id: 'm-3' }), mode: 'steer', now: t0 + 2 });
eq('steer counts against the per-turn cap', state.injectedThisTurn, 1);
eq('beginTurn clears the per-turn cap', beginTurn(state).injectedThisTurn, 0);
eq('a human message releases the runaway breaker', recordHumanInput({ ...state, turnsWithoutHuman: 4 }).turnsWithoutHuman, 0);
eq(
	'and the breaker is then passable again',
	decideDelivery({
		policy,
		envelope: env({ from: 'ada', id: 'fresh-a' }),
		// Budget also cleared, so this isolates the breaker rather than re-testing the
		// budget: with the budget spent the same envelope correctly becomes 'inject'.
		state: recordHumanInput({ ...state, turnsWithoutHuman: 4, lastWakeAt: t0 - policy.wakeBudgetMs - 1 }),
		now: t0,
	}).mode,
	'followup'
);
eq(
	'whereas without it the breaker latches shut',
	decideDelivery({ policy, envelope: env({ from: 'ada', id: 'fresh-b' }), state: { ...state, turnsWithoutHuman: 4 }, now: t0 }).code,
	'runaway'
);
ok('the dedupe set is bounded', (() => {
	let s = initialState(0);
	for (let i = 0; i < 700; i += 1) s = recordDelivery(s, { envelope: env({ id: `x-${i}` }), mode: 'inject', now: 0 });
	return s.seen.size <= 512;
})());
ok('the audit line names who, what and why', auditLine({ from: 'ada', id: 'm-1', mode: 'steer', action: 'do', reason: 'same thread' }).includes('from=ada'));

// ----------------------------------------------------------------- deliver ----
group('deliver');
const agentAt = (id, preset, createdAt) => ({ id, session: { header: { agentPreset: preset, createdAt } }, followup() {}, steer() {}, inject() {} });
const stubAgents = (list) => ({ list: () => list, get: (id) => list.find((a) => a.id === id) ?? null });

eq('picks the newest live session for the preset', (await resolveAgent({ agents: stubAgents([agentAt('old', 'lily', 1), agentAt('new', 'lily', 9), agentAt('e', 'echo', 99)]), preset: 'lily' })).agent.id, 'new');
eq('ignores other presets entirely', (await resolveAgent({ agents: stubAgents([agentAt('e', 'echo', 99)]), preset: 'lily' })).agent, null);
eq('an explicit sessionId wins', (await resolveAgent({ agents: stubAgents([agentAt('s1', 'lily', 1)]), preset: 'lily', sessionId: 's1' })).reason, 'live session');
eq('a cold session is resumed', (await resolveAgent({ agents: { get: () => null, resume: async ({ sessionId }) => ({ agent: { id: sessionId } }) }, preset: 'lily', sessionId: 's9' })).reason, 'resumed session');
eq('a missing agents service fails cleanly', (await resolveAgent({ agents: null, preset: 'lily' })).agent, null);

const calls = [];
const spyAgent = { id: 'a1', followup: (m) => calls.push(['followup', m]), steer: (m) => calls.push(['steer', m]), inject: (m) => calls.push(['inject', m]) };
const helper = (m) => m;
for (const mode of ['followup', 'steer', 'inject']) {
	await deliverToAgent({ agent: spyAgent, mode, envelope: env({ from: 'ada' }), createUserMessage: helper });
}
eq('each policy mode maps to the matching agent method', calls.map((c) => c[0]), ['followup', 'steer', 'inject']);
eq('the message is a plugin-sourced user message', calls[0][1].source, { kind: 'plugin', plugin: 'dsh-mesh', form: 'mesh-receive' });
ok('the rendered text is what the agent actually receives', calls[0][1].content[0].text.includes('hello there'));
ok('the prompt carries provenance and the reply expectation', renderPrompt(env({ from: 'ada' })).startsWith('[mesh from ada · id m-1 · action info · reply no]'));
eq('a missing method is reported, not thrown', (await deliverToAgent({ agent: { id: 'x' }, mode: 'steer', envelope: env(), createUserMessage: helper })).code, 'no-method');

// ------------------------------------------------- live fleet identities ----
// The parser is only correct if it survives the real files. Two of the framings in
// use — a `|` block scalar and a multi-line single-quoted scalar — both appear in
// the fleet today, and the quoted one is the trap: read only its first line and
// every peer verification fails while the code still looks right.
group('live fleet identities');
const FLEET_ROOT = 'X:\\.hermes\\fleet\\mesh\\agents';
try {
	const names = readdirSync(FLEET_ROOT).filter((n) => !n.includes('.'));
	const unreadable = [];
	const noKey = [];
	for (const peer of names) {
		let text;
		try {
			text = readFileSync(join(FLEET_ROOT, peer, 'identity.yaml'), 'utf8');
		} catch {
			noKey.push(peer); // a directory without an identity.yaml is not our concern
			continue;
		}
		const pem = publicKeyFromIdentity(text);
		if (!/public_key:/.test(text)) {
			noKey.push(peer); // an identity with no key at all (the registry's own row)
			continue;
		}
		if (!pem || !loadPublicKey(pem)) unreadable.push(peer);
	}
	eq('every fleet identity yields a loadable Ed25519 public key', unreadable, []);
	ok(`parsed ${names.length - noKey.length} identities (${names.length} directories scanned)`, true);
} catch {
	console.log('  skip X: is not reachable from here');
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
