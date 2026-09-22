// dsh-fleet-mesh — host half.
//
// The DSH substrate's peer in the hermes-mesh fleet. One port, one route, dispatch by
// the envelope's `[to:]` token — the fleet's other substrates bind a port per wife
// because each wife is a separate process; DSH is one process hosting many agents.
//
//   POST /mesh/receive   -> verify, then deliver as a prompt (Ed25519-signed)
//   GET  /mesh/health    -> { status, agents } so a sister can choose now or later
//
// WHY THERE IS NO CSRF GUARD HERE, UNLIKE THE PRESENCE PANEL'S WRITE ROUTE:
//   this endpoint is a server-to-server webhook. A peer's POST carries no
//   `sec-fetch-site` and no browser origin, and the presence plugin's same-origin
//   check would reject every legitimate sister. The authentication is the Ed25519
//   signature over the raw body, plus the replay window and the dedupe set — which
//   is stronger than an origin header, because it is cryptographic.
//
// WHY THIS BINDS ITS OWN LISTENER INSTEAD OF USING THE DSH WEB SERVER:
//   the obvious move is `ctx.webServer.register`, exactly as the presence panel does.
//   It does not work here, and the reason is measured, not assumed:
//     * the harness web server binds 127.0.0.1 ONLY (verified with a local socket
//       query: 127.0.0.1:43129, while the process's other listener is 0.0.0.0:43127,
//       which is the phone-pairing surface, not a route table for plugins);
//     * its host comes from `ctx.webStartup.host ?? '127.0.0.1'`, so it is loopback
//       by configuration, not by accident.
//   A peer's POST would therefore never complete a TCP connection. Widening that
//   server to 0.0.0.0 would expose the ENTIRE web surface — the GUI, the API and the
//   presence panel — to the LAN, which is a much larger act than opening one mesh
//   route. So dsh-fleet-mesh owns its listener and exposes only /mesh/*.
//
// SAFE BY DEFAULT: `host` defaults to 127.0.0.1, so installing this plugin opens
// nothing. Reaching the fleet is a deliberate `host: '0.0.0.0'` in the row's config —
// and even then the real door is the allow list in access.mjs (192.168.0.0/23, which
// IS the 192.168.0.* and 192.168.1.* networks), checked before anything else runs.
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isAllowed, DEFAULT_ALLOW } from './access.mjs';
import { createToolDescriptors, registerMeshTools } from './tools.mjs';
import { parseEnvelope, envelopeProblems } from './envelope.mjs';
import { publicKeyFromIdentity, verifyPayload } from './crypto.mjs';
import { defaultPolicy, initialState, decideDelivery, recordDelivery, recordHumanInput, auditLine } from './policy.mjs';
import { resolveAgent, deliverToAgent } from './deliver.mjs';

export const name = 'dsh-fleet-mesh';
// `tools` (to expose the mesh_* tools) and `agents` (to deliver an inbound envelope as a
// prompt). Both are DECLARED dependencies, not soft lookups — see the note on the tool
// surface below for why the soft version was worse than useless.
export const inject = ['tools', 'agents'];

const BASE = '/mesh';
const NO_STORE = { 'cache-control': 'no-store' };
const MAX_BODY_BYTES = 256 * 1024;
/** Replay window, matching the fleet's `replay_window_ttl: 300`. */
const REPLAY_WINDOW_MS = 300 * 1000;
/** Peer public keys change rarely; a minute bounds the blast radius of a rotation. */
const KEY_TTL_MS = 60 * 1000;
const AGENT_NAME_RE = /^[a-z0-9][a-z0-9_.-]*$/i;

function log(ctx, level, message) {
	try {
		const logger = ctx?.logger?.[level];
		if (typeof logger === 'function') logger.call(ctx.logger, `[dsh-fleet-mesh] ${message}`);
		else console[level === 'warn' ? 'warn' : 'log'](`[dsh-fleet-mesh] ${message}`);
	} catch {
		/* logging must never break the route */
	}
}

function sendJson(res, code, body) {
	try {
		res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', ...NO_STORE });
		res.end(JSON.stringify(body));
	} catch {
		/* socket already gone */
	}
}

/** Normalize the `agents:` config map into per-agent settings. */
export function normalizeConfig(config = {}) {
	const agents = {};
	const raw = config?.agents && typeof config.agents === 'object' ? config.agents : {};
	for (const [agentName, entry] of Object.entries(raw)) {
		if (!AGENT_NAME_RE.test(agentName)) continue;
		const overrides = {};
		if (Array.isArray(entry?.wake)) overrides.wake = entry.wake.map(String);
		if (Number.isFinite(entry?.maxInjectedPerTurn)) overrides.maxInjectedPerTurn = entry.maxInjectedPerTurn;
		if (Number.isFinite(entry?.wakeBudgetMs)) overrides.wakeBudgetMs = entry.wakeBudgetMs;
		if (Number.isFinite(entry?.runawayLimit)) overrides.runawayLimit = entry.runawayLimit;
		agents[agentName] = {
			preset: typeof entry?.preset === 'string' && entry.preset !== '' ? entry.preset : agentName,
			sessionId: typeof entry?.sessionId === 'string' && entry.sessionId !== '' ? entry.sessionId : null,
			keyPath: typeof entry?.keyPath === 'string' && entry.keyPath !== '' ? entry.keyPath : null,
			// Outbound identity: what we send AS, and the row mesh_register publishes.
			url: typeof entry?.url === 'string' && entry.url !== '' ? entry.url : null,
			role: typeof entry?.role === 'string' && entry.role !== '' ? entry.role : null,
			description: typeof entry?.description === 'string' && entry.description !== '' ? entry.description : null,
			policy: defaultPolicy(overrides),
		};
	}
	const fleetRoot =
		(typeof config?.fleetRoot === 'string' && config.fleetRoot.trim() !== '' && config.fleetRoot) ||
		process.env.MESH_FLEET_ROOT ||
		'X:\\.hermes\\fleet\\mesh\\agents';
	return {
		agents,
		fleetRoot: resolve(fleetRoot),
		publicBaseUrl: typeof config?.publicBaseUrl === 'string' ? config.publicBaseUrl : null,
		maxBodyBytes: Number.isFinite(config?.maxBodyBytes) ? config.maxBodyBytes : MAX_BODY_BYTES,
		replayWindowMs: Number.isFinite(config?.replayWindowMs) ? config.replayWindowMs : REPLAY_WINDOW_MS,
		// Named in the "unreachable" reply so a sender is told where to write instead of
		// retrying into a void. Deployment-specific (a vault path, a mailbox, a relay),
		// so it ships unset and the field is simply omitted until one is configured.
		durableRoute: typeof config?.durableRoute === 'string' && config.durableRoute !== '' ? config.durableRoute : null,
		// Which configured agent signs what we send and registers us. Null = the only (or
		// first) entry in the map, which is right for a single-agent deployment.
		self: typeof config?.self === 'string' && config.self !== '' ? config.self : null,
		// The registry's own default bind is 127.0.0.1:8646, so that is the honest default.
		registryUrl: typeof config?.registryUrl === 'string' && config.registryUrl !== '' ? config.registryUrl : 'http://127.0.0.1:8646',
		registryTimeoutMs: Number.isFinite(config?.registryTimeoutMs) ? config.registryTimeoutMs : 5000,
		// mesh_sync's cache: this deployment's OWN directory, never a shared store.
		cacheDir: resolve(
			typeof config?.cacheDir === 'string' && config.cacheDir !== ''
				? config.cacheDir
				: join(process.env.DSH_HOME ?? process.cwd(), 'mesh', 'peers')
		),
		// The source-address door. Node cannot bind a subnet, so the listener may sit on
		// 0.0.0.0 while only these networks are served at all.
		allow: Array.isArray(config?.allow) && config.allow.length > 0 ? config.allow.map(String) : DEFAULT_ALLOW,
		// Safe by default: loopback only. `0.0.0.0` is a deliberate act by the owner.
		host: typeof config?.host === 'string' && config.host !== '' ? config.host : '127.0.0.1',
		port: Number.isFinite(config?.port) ? config.port : 8760,
	};
}

/**
 * Resolve a core package specifier to an importable URL.
 *
 * A `link:`ed plugin resolves from its REALPATH, so it lives outside the profile's node_modules
 * tree: from `harness\plugins\dsh-fleet-mesh` Node walks up through `harness\plugins` and
 * `harness` and never reaches `harness\profiles`, where the core actually is. A normally
 * installed plugin sits under `profiles\web\node_modules\<name>` and its walk-up does reach
 * `profiles\node_modules` — which is why every other plugin in this profile can import the core
 * and this one could not.
 *
 * So: try the ordinary specifier first (correct wherever the plugin is installed normally), then
 * resolve it from the profile tree. Returns null when neither path reaches the package.
 */
function coreModuleUrl(spec) {
	try {
		return import.meta.resolve(spec);
	} catch {
		/* fall through to the anchored path */
	}
	const home = process.env.DSH_HOME;
	if (!home) return null;
	try {
		// Anchoring the require inside the profile's own directory makes the walk reach
		// `profiles\node_modules`, where the core is hoisted.
		const anchor = join(home, 'profiles', 'node_modules', '@deepseek-ai', 'dsh-tools', 'package.json');
		return pathToFileURL(createRequire(anchor).resolve(spec)).href;
	} catch {
		return null;
	}
}

/** Resolve the harness's `defineTool`. */
async function loadDefineTool() {
	const url = coreModuleUrl('@deepseek-ai/dsh-tools');
	if (url === null) throw new Error('@deepseek-ai/dsh-tools is not resolvable from this plugin or the profile tree');
	const module = await import(url);
	if (typeof module?.defineTool !== 'function') throw new Error('@deepseek-ai/dsh-tools exports no defineTool');
	return module.defineTool;
}

/** Read a request body with a hard ceiling, so a hostile peer cannot buffer us out. */
function readBody(req, limit) {
	return new Promise((resolvePromise, reject) => {
		const chunks = [];
		let size = 0;
		req.on('data', (chunk) => {
			size += chunk.length;
			if (size > limit) {
				reject(new Error('body too large'));
				req.destroy();
				return;
			}
			chunks.push(chunk);
		});
		req.on('end', () => resolvePromise(Buffer.concat(chunks)));
		req.on('error', reject);
	});
}

/**
 * Build the request handler. Exported so the smoke suite exercises the real code
 * path without opening a socket.
 */
export function createMeshHandler(ctx, settings) {
	const states = new Map();
	const keyCache = new Map();
	// The fallback must still mint a VALID user message — the bare identity it
	// replaced persisted a user/message with no role at all, which the
	// restore-time validator rejects, bricking the session on its next load
	// (seq 9307, 2026-09-22). `dshfm-` marks fallback-minted ids in the log.
	let createUserMessage = (message) => ({ ...message, role: 'user', id: message?.id ?? `dshfm-${randomUUID()}` });
	let llmResolved = false;

	/** Resolve the message helper once, with the same fallback dsh-cron uses. */
	async function messageHelper() {
		if (llmResolved) return createUserMessage;
		llmResolved = true;
		const url = coreModuleUrl('@deepseek-ai/dsh-llm');
		if (url === null) {
			log(ctx, 'warn', '@deepseek-ai/dsh-llm is not resolvable from this plugin or the profile tree, using the fallback');
			return createUserMessage;
		}
		try {
			const mod = await import(url);
			if (typeof mod?.createUserMessage === 'function') createUserMessage = mod.createUserMessage;
		} catch (error) {
			log(ctx, 'warn', `@deepseek-ai/dsh-llm failed to load, using the fallback: ${error?.message ?? error}`);
		}
		return createUserMessage;
	}

	/** A peer's public key from the fleet identity store, cached briefly. */
	async function peerPublicKey(from) {
		if (!AGENT_NAME_RE.test(from)) return null; // path-traversal guard before any join
		const cached = keyCache.get(from);
		const now = Date.now();
		if (cached && now - cached.at < KEY_TTL_MS) return cached.pem;
		try {
			const text = await readFile(join(settings.fleetRoot, from, 'identity.yaml'), 'utf8');
			const pem = publicKeyFromIdentity(text);
			if (pem) {
				keyCache.set(from, { pem, at: now });
				return pem;
			}
			return null;
		} catch {
			return null; // an unknown sender is a 401, never a crash
		}
	}

	async function receive(req, res) {
		const now = Date.now();
		let raw;
		try {
			raw = await readBody(req, settings.maxBodyBytes);
		} catch (error) {
			return sendJson(res, 413, { status: 'bad request', reason: String(error?.message ?? error) });
		}

		let wire;
		try {
			wire = JSON.parse(raw.toString('utf8'));
		} catch {
			return sendJson(res, 400, { status: 'bad request' });
		}

		const envelope = parseEnvelope(typeof wire?.text === 'string' ? wire.text : '');
		if (!envelope) return sendJson(res, 400, { status: 'bad request' });
		const problems = envelopeProblems(envelope);
		if (problems.length > 0) return sendJson(res, 400, { status: 'bad request', fields: problems });

		// The wire `from` and the envelope's `[from:]` must agree: one of them is the
		// key we look up, the other is what the recipient believes. Divergence is
		// either a bug or an attack, and neither should be resolved by guessing.
		if (wire.from !== envelope.from) return sendJson(res, 401, { status: 'unauthorized' });

		if (envelope.to !== '*' && !(envelope.to in settings.agents)) {
			return sendJson(res, 404, { status: 'no such recipient', to: envelope.to });
		}

		const publicKey = await peerPublicKey(envelope.from);
		if (!publicKey) {
			log(ctx, 'warn', `unauthorized: no cached public key for "${envelope.from}"`);
			return sendJson(res, 401, { status: 'unauthorized' });
		}

		const signature = req.headers?.['x-mesh-signature'] ?? '';
		const timestamp = req.headers?.['x-mesh-timestamp'] ?? '';
		// Verified against the RAW body bytes — never against re-serialized JSON,
		// which would reorder keys and break every signature.
		if (!verifyPayload(publicKey, timestamp, raw, signature)) {
			log(ctx, 'warn', `unauthorized: bad signature from "${envelope.from}"`);
			return sendJson(res, 401, { status: 'unauthorized' });
		}

		if (timestamp !== '') {
			const sentAt = Number(timestamp) * 1000;
			if (!Number.isFinite(sentAt) || Math.abs(now - sentAt) > settings.replayWindowMs) {
				return sendJson(res, 401, { status: 'unauthorized', reason: 'timestamp outside the replay window' });
			}
		}

		const target = envelope.to === '*' ? Object.keys(settings.agents)[0] : envelope.to;
		const agentConfig = settings.agents[target];
		if (!agentConfig) return sendJson(res, 404, { status: 'no such recipient', to: envelope.to });

		const state = states.get(target) ?? initialState(now);
		const decision = decideDelivery({ policy: agentConfig.policy, envelope, state, now });

		if (decision.mode === 'refuse') {
			states.set(target, recordDelivery(state, { envelope, mode: 'refuse', now }));
			// A duplicate is a SUCCESS from the sender's point of view — the message
			// was already delivered. Anything else here would invite a retry storm.
			const code = decision.code === 'duplicate' ? 200 : 429;
			return sendJson(res, code, { status: 'ok', delivered: false, code: decision.code });
		}

		const agents = ctx.agents;
		const resolved = await resolveAgent({
			agents,
			preset: agentConfig.preset,
			sessionId: agentConfig.sessionId,
		});
		if (!resolved.agent) {
			// Fail informatively, never swallow (PLAN.md §5): the sender must know
			// the message did not land, and must be told the durable alternative.
			log(ctx, 'warn', `undeliverable for "${target}": ${resolved.reason}`);
			return sendJson(res, 503, {
				status: 'unreachable',
				reason: resolved.reason,
				...(settings.durableRoute ? { durable: settings.durableRoute } : {}),
			});
		}

		const helper = await messageHelper();
		const result = await deliverToAgent({
			agent: resolved.agent,
			mode: decision.mode,
			envelope,
			createUserMessage: helper,
		});
		if (!result.ok) {
			log(ctx, 'warn', `delivery failed for "${target}": ${result.reason}`);
			return sendJson(res, 503, { status: 'unreachable', reason: result.reason });
		}

		states.set(target, recordDelivery(state, { envelope, mode: decision.mode, now }));
		log(ctx, 'info', auditLine({ from: envelope.from, id: envelope.id, mode: decision.mode, action: envelope.action, reason: decision.reason }));
		return sendJson(res, 200, { status: 'ok', delivered: true, mode: decision.mode, to: target });
	}

	async function route(req, res) {
		// The door comes FIRST — before JSON parsing, before the peer lookup, before any
		// signature work — so an unwanted caller cannot make this process do work.
		const peer = req.socket?.remoteAddress ?? '';
		if (!isAllowed(peer, settings.allow)) {
			log(ctx, 'warn', `refused ${peer || 'unknown source'} — outside ${settings.allow.join(', ')}`);
			return sendJson(res, 403, { status: 'forbidden', reason: 'source address is not in the allow list' });
		}

		const url = new URL(req.url ?? '/', 'http://localhost');
		const path = url.pathname.replace(/\/+$/, '') || '/';

		if (path === `${BASE}/health` && req.method === 'GET') {
			// Report whether delivery is actually POSSIBLE, not merely that the process is
			// alive — a sister asking "can I reach you?" deserves the useful answer, and
			// this is the courtesy endpoint PLAN.md §7.5 asks about. It is also the one
			// thing a smoke test cannot prove: that the agents service resolves inside the
			// real app process.
			const agents = ctx.agents;
			return sendJson(res, 200, {
				status: 'healthy',
				// Self-verifying: the one thing a restart can silently get wrong is the tool
				// registration (it depends on resolving the core, which a `link:`ed plugin
				// cannot do by bare specifier). `0` here means the tools did NOT register.
				tools: { registered: settings.toolsRegistered ?? 0, expected: 5 },
				agents: Object.entries(settings.agents).map(([agentName, entry]) => {
					const live =
						typeof agents?.list === 'function'
							? agents.list().filter((a) => a?.session?.header?.agentPreset === entry.preset).length
							: null;
					return {
						name: agentName,
						preset: entry.preset,
						wake: entry.policy.wake,
						delivery: {
							agentsService: agents ? 'ok' : 'unavailable',
							sessionsForPreset: live,
							sessionIdOverride: entry.sessionId,
						},
						delivered: states.get(agentName)?.lastAudit ?? null,
					};
				}),
				allow: settings.allow,
				publicBaseUrl: settings.publicBaseUrl,
			});
		}
		if (path === `${BASE}/receive` && req.method === 'POST') return receive(req, res);
		return sendJson(res, 404, { status: 'not found', path });
	}

	// The runaway guard's reset. `recordDelivery` counts mesh-INITIATED turns, and the
	// counter has to be cleared by a real person speaking — otherwise it only ever rises
	// and the guard latches shut after `runawayLimit` turns. Our own injections carry
	// `source.kind === 'plugin'`, so they cannot clear it; only the GUI (or any other
	// genuine user turn) can. A serial event body, so it is wrapped: a listener must never
	// fail the turn boundary.
	//
	// It lives HERE rather than in apply() because it shares the `states` map with the
	// route — they are one runtime, and splitting them once already meant the smoke suite
	// silently tested a build with no listener attached at all.
	ctx.effect(() => {
		if (typeof ctx.on !== 'function') return () => {};
		const off = ctx.on('session/event', (session, event) => {
			try {
				if (event?.type !== 'user/message') return;
				if (event.data?.source?.kind !== 'user') return;
				const preset = session?.header?.agentPreset;
				for (const [agentName, entry] of Object.entries(settings.agents)) {
					if (entry.preset !== preset) continue;
					const state = states.get(agentName);
					if (state) states.set(agentName, recordHumanInput(state));
				}
			} catch {
				/* never fail the boundary */
			}
		});
		return () => {
			try {
				off?.();
			} catch {
				/* already released */
			}
		};
	});

	return route;
}

export function apply(ctx, config = {}) {
	const settings = normalizeConfig(config);
	const handler = createMeshHandler(ctx, settings);

	// The tool surface.
	//
	// `tools` is a DECLARED dependency (see `inject`), not a soft lookup. An earlier version
	// tried `ctx.get('tools') ?? ctx.tools` to stay loadable without the service — but Cordis's
	// context proxy THROWS on reading an undeclared service ("cannot get property \"tools\"
	// without inject"), so the softness did the opposite of what it intended: the plugin failed
	// to apply and the harness's recovery removed it from the profile entirely.
	//
	// The core import stays DYNAMIC because the test suites import this module with no
	// @deepseek-ai/* on their resolution path; a static import would make the plugin untestable.
	ctx.effect(() => {
		const tools = ctx.tools;
		const logger = (level, message) => log(ctx, level, message);
		let disposers = [];
		let cancelled = false;
		loadDefineTool()
			.then((defineTool) => {
				if (cancelled) return;
				disposers = registerMeshTools({ tools, defineTool, settings, logger });
				// Shared with the health route so a restart can be verified without guessing.
				settings.toolsRegistered = disposers.length;
				log(ctx, 'info', `registered ${disposers.length} mesh tool(s)`);
			})
			.catch((error) => log(ctx, 'warn', `could not load @deepseek-ai/dsh-tools: ${error?.message ?? error}`));
		return () => {
			cancelled = true;
			for (const dispose of disposers) {
				try {
					dispose();
				} catch {
					/* already released */
				}
			}
			disposers = [];
		};
	});

	ctx.effect(() => {
		const server = createServer((req, res) => {
			Promise.resolve(handler(req, res)).catch((error) => {
				log(ctx, 'warn', `route failure: ${error?.message ?? error}`);
				if (!res.headersSent) sendJson(res, 500, { status: 'internal error' });
				else res.destroy();
			});
		});
		server.on('error', (error) => {
			log(ctx, 'warn', `listener failed on ${settings.host}:${settings.port}: ${error?.message ?? error}`);
		});
		server.listen(settings.port, settings.host, () => {
			const names = Object.keys(settings.agents);
			log(ctx, 'info', `listening on ${settings.host}:${settings.port}${BASE} — agents: ${names.length > 0 ? names.join(', ') : '(none configured)'}`);
		});
		return () => {
			try {
				server.close();
			} catch {
				/* already closed */
			}
		};
	});
}
