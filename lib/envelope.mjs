// dsh-fleet-mesh — the bracketed mesh envelope.
//
// The grammar is taken from the RECEIVER'S OWN regex, not from SPEC.md (which still
// documents the retired HMAC scheme):
//   X:\CascadeProjects\hermes-mesh\hermes_mesh\adapter.py  ->  _envelope_regex()
//
//   [mesh][v:?][from][to][id][session?][from_session?][action?][reply?][ref?]<body>
//
// `action` and `reply` are OPTIONAL on receive (missing defaults to info/no — the
// receiver is deliberately tolerant) but REQUIRED on send; the skill calls that the
// "mesh-economy required-envelope rule". The body is everything after the header.
//
// Two deliberate deviations from the v1 JSON schema, both because the code and the
// skill are the authority over the schema:
//   * `reply: end` is a real value — terminal, closes the thread (SKILL.md, Thread
//     Lifecycle) — but the schema's enum lists only yes|no.
//   * `to: '*'` is a broadcast, and a broadcast must never wake anyone.

// `wireBody` emits the canonical wrap, so this module carries the one definition of what a
// signed mesh body looks like on the wire. pyjson.mjs owns the byte-level rules.
import { wrapJsonWireBody } from './pyjson.mjs';

/** Name/field grammar, from schemas/mesh-envelope-v1.json. */
export const NAME_RE = /^[A-Za-z0-9_.:-]{1,128}$/;

export const ACTIONS = ['do', 'info'];
export const REPLIES = ['yes', 'no', 'end'];

/** Mirrors adapter.py `_envelope_regex()`, group for group. */
const HEADER_RE =
	/^\s*\[mesh\](?:\[v:([^\]]+)\])?\[from:([^\]]+)\]\[to:([^\]]+)\]\[id:([^\]]+)\](?:\[session:([^\]]+)\])?(?:\[from_session:([^\]]+)\])?(?:\[action:([^\]]+)\])?(?:\[reply:([^\]]+)\])?(?:\[ref:([^\]]+)\])?[ \t]*/;

/**
 * Parse one envelope from a message body.
 * @param text - the `text` field of the wire JSON, or a raw envelope.
 * @returns the envelope, or null when it is not a mesh envelope at all.
 */
export function parseEnvelope(text) {
	if (typeof text !== 'string') return null;
	const m = HEADER_RE.exec(text);
	if (!m) return null;
	const [, v, from, to, id, session, fromSession, action, reply, ref] = m;
	return {
		v: v ?? '1',
		from,
		to,
		id,
		session: session ?? null,
		fromSession: fromSession ?? null,
		// Tolerant receive: the receiver defaults a missing action/reply rather than
		// rejecting, so a minimal peer is still understood.
		action: action ?? 'info',
		reply: reply ?? 'no',
		ref: ref ?? null,
		body: text.slice(m[0].length).replace(/^\r?\n/, ''),
	};
}

/**
 * Field-level validation, in the schema's terms.
 * @returns a list of offending field names; empty means valid.
 */
export function envelopeProblems(env) {
	const problems = [];
	if (!env || typeof env !== 'object') return ['envelope'];
	if (!NAME_RE.test(String(env.from ?? ''))) problems.push('from');
	// `*` is the one legal non-name recipient (broadcast).
	if (env.to !== '*' && !NAME_RE.test(String(env.to ?? ''))) problems.push('to');
	if (!NAME_RE.test(String(env.id ?? ''))) problems.push('id');
	if (!ACTIONS.includes(env.action)) problems.push('action');
	if (!REPLIES.includes(env.reply)) problems.push('reply');
	if (env.ref != null && !NAME_RE.test(String(env.ref))) problems.push('ref');
	return problems;
}

/**
 * Build an envelope in the canonical token order.
 *
 * The sender side REQUIRES action and reply — omitting them is how a tolerant
 * receiver silently downgrades a request to an acknowledgement.
 */
export function buildEnvelope({
	from,
	to,
	id,
	action = 'info',
	reply = 'no',
	ref = null,
	session = null,
	fromSession = null,
	body = '',
} = {}) {
	let head = `[mesh][v:1][from:${from}][to:${to}][id:${id}]`;
	if (session) head += `[session:${session}]`;
	if (fromSession) head += `[from_session:${fromSession}]`;
	head += `[action:${action}][reply:${reply}]`;
	if (ref) head += `[ref:${ref}]`;
	return body ? `${head} ${body}` : head;
}

/**
 * The wire JSON body for one envelope: exactly what gets signed and posted.
 *
 * This IS the canonical wrap — `json.dumps({"from":…, "text":…}, sort_keys=True)`, the fleet's
 * `wire_format="json"` default. It was previously built with `JSON.stringify`, which is
 * *structurally* the same object and *byte-wise* a different string: no spaces after `:` and `,`,
 * and no ASCII escaping. That worked only because a receiver verifies over the bytes it received
 * and never re-serializes — so the difference was invisible right up until a peer that DOES
 * re-serialize (the Phase-5 peers session_relay.py's docstring names) tried to verify us, or
 * anyone diffed our bytes against Python's. pyjson.mjs exists to close exactly that, and its
 * output is asserted against bytes Python itself produced.
 */
export function wireBody(from, envelopeText) {
	return wrapJsonWireBody(from, envelopeText);
}
