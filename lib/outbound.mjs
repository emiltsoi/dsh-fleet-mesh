// dsh-mesh — outbound: build the envelope, sign it, POST it, retry within one budget.
//
// The mirror of session_relay.py's send path, and the engine behind `mesh_send`. Two
// properties are copied deliberately from the fleet, because they are what make a mesh
// send honest rather than hopeful:
//
//   * ONE TOTAL DEADLINE, shared across attempts (default 10 s, 3 attempts, 1.0 s
//     backoff). A slow or dead peer cannot consume the budget linearly, and when the
//     budget is spent the result is `unreachable` — REFUSED, never swallowed. PLAN.md §5
//     is exactly this, and the fleet already behaves this way, so we match it.
//   * The signature covers `"{timestamp}\n{body}"`, while the POST carries the body
//     alone with the timestamp in `X-Mesh-Timestamp`. Rebuilding those bytes wrongly is
//     the single easiest way to make every peer return 401.
//
// In-process `fetch` is NOT gated by a shell egress proxy — a host plugin can reach a LAN
// address with no allow rule in place. So this POSTs to peers directly, and no ingress is
// needed on the outbound side.
import { signPayload } from './crypto.mjs';
import { buildEnvelope, wireBody } from './envelope.mjs';

/** Fleet parity: `_DELIVERY_RETRIES`, `_DELIVERY_BACKOFF`, `_DELIVERY_TIMEOUT`. */
export const DELIVERY_RETRIES = 3;
export const DELIVERY_BACKOFF_MS = 1_000;
export const DELIVERY_TIMEOUT_MS = 10_000;

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Build one signed request, byte-for-byte as the fleet's sender would.
 * @returns { envelope, body, headers } — `body` is the Buffer that gets POSTed AND the
 *   bytes the signature covers (with the timestamp prefixed).
 */
export function buildSignedRequest({
	privateKey,
	from,
	to,
	id,
	action = 'info',
	reply = 'no',
	ref = null,
	session = null,
	fromSession = null,
	body = '',
	now = Date.now(),
}) {
	const envelope = buildEnvelope({ from, to, id, action, reply, ref, session, fromSession, body });
	const raw = Buffer.from(wireBody(from, envelope), 'utf8');
	const timestamp = String(now / 1000);
	return {
		envelope,
		body: raw,
		headers: {
			'content-type': 'application/json',
			'x-mesh-timestamp': timestamp,
			'x-mesh-signature': signPayload(privateKey, timestamp, raw),
		},
	};
}

/**
 * POST one signed request, retrying inside a single total deadline.
 *
 * @returns { ok, code?, status?, body? } where `code` is one of the fleet's own failure
 *   tokens — `unreachable`, `unauthorized`, `loopback-blocked` — or `http-<status>`.
 */
export async function deliverTo({
	url,
	request,
	fetchImpl = fetch,
	retries = DELIVERY_RETRIES,
	timeoutMs = DELIVERY_TIMEOUT_MS,
	backoffMs = DELIVERY_BACKOFF_MS,
	sleep = defaultSleep,
	now = () => Date.now(),
}) {
	const deadline = now() + timeoutMs;
	let lastCode = 'unreachable';
	let lastDetail = 'no attempt was made';

	for (let attempt = 0; attempt < retries; attempt += 1) {
		const remaining = deadline - now();
		if (remaining <= 0) {
			lastCode = 'unreachable';
			lastDetail = 'delivery exceeded the total timeout budget';
			break;
		}
		// Equal share of what is left, so one slow peer cannot eat the whole budget.
		const attemptTimeout = Math.max(1, Math.floor(remaining / (retries - attempt)));
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), attemptTimeout);
		try {
			const response = await fetchImpl(url, {
				method: 'POST',
				headers: request.headers,
				body: request.body,
				signal: controller.signal,
			});
			clearTimeout(timer);
			const text = await response.text().catch(() => '');
			if (response.ok) return { ok: true, status: response.status, body: text };

			// The fleet answers 401 for a bad signature, 403 when its own policy refuses,
			// and carries its token in the JSON body when it has one.
			let token = null;
			try {
				token = JSON.parse(text)?.error ?? null;
			} catch {
				/* not JSON — fall back to the status */
			}
			if (response.status === 401) return { ok: false, code: token ?? 'unauthorized', status: 401, body: text };
			if (response.status === 403) return { ok: false, code: token ?? 'loopback-blocked', status: 403, body: text };
			lastCode = token ?? `http-${response.status}`;
			lastDetail = `peer answered ${response.status}`;
		} catch (error) {
			clearTimeout(timer);
			lastCode = 'unreachable';
			lastDetail = error?.name === 'AbortError' ? 'attempt timed out' : String(error?.message ?? error);
		}
		if (attempt < retries - 1) await sleep(backoffMs);
	}
	return { ok: false, code: lastCode, detail: lastDetail };
}

/** Resolve one peer's receive URL from an identity.yaml body. */
export function urlFromIdentity(yamlText) {
	const m = /^\s*url:\s*(\S+)\s*$/m.exec(String(yamlText ?? ''));
	return m ? m[1].replace(/^['"]|['"]$/g, '') : null;
}
