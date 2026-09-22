// dsh-fleet-mesh — the mesh-peer-registry client.
//
// Routes and payload shape are read from the registry's own source, not guessed:
//   X:\CascadeProjects\mesh-peer-registry\mesh_peer_registry\server.py
//     POST   /register              {name,url,public_key[,role,description,ttl]} + X-Mesh-Signature
//     GET    /peers  /peers/{name}
//     POST   /peers/{name}/refresh
//     DELETE /peers/{name}
//     GET    /health  /metrics
//
// THE SIGNING CONTRACT IS NOT THE MESSAGE CONTRACT. A mesh message signs
// `"{timestamp}\n{body}"`; a REGISTRATION signs the canonical JSON of the payload:
//
//   server.py  payload = {k: body[k] for k in REGISTRY_FIELDS if k in body}
//   crypto.py  canonicalize_json = json.dumps(payload, sort_keys=True,
//                                             separators=(",", ":"), ensure_ascii=False)
//
// So the bytes signed are the COMPACT, KEY-SORTED JSON of the registry-field subset —
// which in JS is exactly `JSON.stringify(payload, Object.keys(payload).sort())`, since
// JS emits no spaces and does not escape non-ASCII. Signing the pretty body, or the body
// with extra fields, produces a 401 with no hint as to why.
export const REGISTRY_FIELDS = ['name', 'url', 'public_key', 'role', 'description', 'ttl'];
export const REQUIRED_FIELDS = ['name', 'url', 'public_key'];

/**
 * The registry's canonical JSON: compact separators, keys sorted RECURSIVELY, no ASCII
 * escaping. Exported because it is the one thing here that must match another language
 * byte for byte.
 *
 * Written as an explicit walk rather than `JSON.stringify(value, keys.sort())`: a replacer
 * ARRAY is a property allowlist applied at every level, so it silently empties nested
 * objects (`{b:{c:2}}` -> `{"b":{}}`). Python's `sort_keys=True` sorts recursively, and a
 * mismatch there is a 401 with no hint about which byte was wrong.
 */
export function canonicalJson(value) {
	if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
	if (value !== null && typeof value === 'object') {
		const keys = Object.keys(value).sort();
		return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
	}
	const encoded = JSON.stringify(value);
	// `undefined` is not a JSON value; null is the deterministic stand-in, and
	// registryPayload already drops empty fields before this is reached.
	return encoded === undefined ? 'null' : encoded;
}

/** Keep only the fields the registry knows, so the signed bytes and the body agree. */
export function registryPayload(fields) {
	const payload = {};
	for (const key of REGISTRY_FIELDS) {
		if (fields?.[key] !== undefined && fields[key] !== null && fields[key] !== '') {
			payload[key] = fields[key];
		}
	}
	return payload;
}

async function requestJson({ baseUrl, path, method = 'GET', body, headers = {}, fetchImpl = fetch, timeoutMs = 5000 }) {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const response = await fetchImpl(`${baseUrl.replace(/\/+$/, '')}${path}`, {
			method,
			headers: body === undefined ? headers : { 'content-type': 'application/json', ...headers },
			body: body === undefined ? undefined : JSON.stringify(body),
			signal: controller.signal,
		});
		const text = await response.text().catch(() => '');
		let parsed = null;
		try {
			parsed = text ? JSON.parse(text) : null;
		} catch {
			/* a non-JSON body is reported as text below */
		}
		return { ok: response.ok, status: response.status, body: parsed, text };
	} catch (error) {
		return {
			ok: false,
			status: 0,
			body: null,
			text: '',
			code: error?.name === 'AbortError' ? 'timeout' : 'unreachable',
			detail: String(error?.message ?? error),
		};
	} finally {
		clearTimeout(timer);
	}
}

/**
 * Build a registry client.
 *
 * `signJson` is injected rather than imported so this module stays pure and testable —
 * the caller passes `(payload) => base64 signature`.
 */
export function createRegistry({ baseUrl, fetchImpl = fetch, timeoutMs = 5000, signJson }) {
	return {
		baseUrl,

		/** Is the registry up? The one call that proves reachability. */
		health: () => requestJson({ baseUrl, path: '/health', fetchImpl, timeoutMs }),

		/** Every registered peer. */
		peers: (limit = 0) => requestJson({ baseUrl, path: `/peers${limit > 0 ? `?limit=${limit}` : ''}`, fetchImpl, timeoutMs }),

		/** One registered peer. */
		peer: (name) => requestJson({ baseUrl, path: `/peers/${encodeURIComponent(name)}`, fetchImpl, timeoutMs }),

		/**
		 * Publish or update this agent's row.
		 *
		 * `privateKey` is required, and the signature covers the canonical payload — not
		 * the request body as serialized, which is why the body is built from the same
		 * object that was signed.
		 */
		register: async (fields) => {
			const payload = registryPayload(fields);
			const missing = REQUIRED_FIELDS.filter((key) => payload[key] === undefined);
			if (missing.length > 0) return { ok: false, status: 0, code: 'missing-fields', detail: missing.join(', ') };
			if (typeof signJson !== 'function') return { ok: false, status: 0, code: 'no-signer' };
			const signature = await signJson(payload);
			return requestJson({
				baseUrl,
				path: '/register',
				method: 'POST',
				body: payload,
				headers: { 'x-mesh-signature': signature },
				fetchImpl,
				timeoutMs,
			});
		},

		/** Withdraw this agent's row. */
		deregister: (name) => requestJson({ baseUrl, path: `/peers/${encodeURIComponent(name)}`, method: 'DELETE', fetchImpl, timeoutMs }),

		/** Ask the registry to re-read a peer's identity. */
		refresh: (name) => requestJson({ baseUrl, path: `/peers/${encodeURIComponent(name)}/refresh`, method: 'POST', fetchImpl, timeoutMs }),
	};
}
