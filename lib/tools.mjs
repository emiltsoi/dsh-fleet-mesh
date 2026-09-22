// dsh-fleet-mesh — the agent-facing tools.
//
// Five descriptors in `defineTool`'s own shape ({ name, description, parameters, output,
// execute }) but built WITHOUT importing the core, so this module is testable standalone and
// `index.js` is the only place that touches @deepseek-ai/dsh-tools. That split is deliberate:
// a test that cannot import the plugin is not a test.
//
// The names mirror hermes-mesh exactly, so muscle memory transfers between substrates:
//   mesh_list  mesh_send  mesh_sync  mesh_register  mesh_deregister
//
// Everything here is a thin adapter over libraries that were built and tested first
// (outbound.mjs, peers.mjs, registry.mjs). If a tool needs logic, the logic belongs in the
// library, not here.
import { randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { loadPrivateKey, publicPemOf, signPayload } from './crypto.mjs';
import { buildSignedRequest, deliverTo } from './outbound.mjs';
import { listPeers, readPeer } from './peers.mjs';
import { canonicalJson, createRegistry } from './registry.mjs';

/** The configured outbound identity: the one agent whose key signs what we send. */
export function selfAgent(settings) {
	const names = Object.keys(settings.agents ?? {});
	const chosen = settings.self && names.includes(settings.self) ? settings.self : names[0];
	if (!chosen) return null;
	return { name: chosen, ...settings.agents[chosen] };
}

/** One registry client per call, wired to the configured signer. */
async function registryFor(settings, self) {
	const privateKey = loadPrivateKey(self.keyPath);
	return createRegistry({
		baseUrl: settings.registryUrl,
		timeoutMs: settings.registryTimeoutMs,
		// A REGISTRATION signs the canonical JSON of the registry-field subset — a different
		// contract from a message, which signs "{timestamp}\n{body}". Signing the pretty
		// body, or the body with extra fields, is a 401 with no hint about which byte moved.
		signJson: async (payload) => signPayload(privateKey, '', Buffer.from(canonicalJson(payload), 'utf8')),
	});
}

const text = (t) => [{ type: 'text', text: t }];

/**
 * Build the five tool descriptors.
 * @param settings - normalizeConfig() output
 * @param logger   - (level, message) => void; defaults to silence so tests need no logger
 */
export function createToolDescriptors(settings, logger = () => {}) {
	return [
		// ---------------------------------------------------------------- list ----
		{
			name: 'mesh_list',
			description:
				'List the mesh peers this agent can reach. Reads the local identity store, so it needs no registry and never touches the network. Read-only.',
			parameters: {
				reachableOnly: {
					type: 'boolean',
					description: 'Return only peers that are addressable (a receive URL and a public key). Default false.',
				},
			},
			output: {
				schema: {
					type: 'object',
					additionalProperties: false,
					properties: {
						count: { type: 'integer', required: true },
						peers: {
							type: 'array',
							required: true,
							items: {
								type: 'object',
								additionalProperties: true,
								properties: {},
							},
						},
						error: { type: 'string' },
					},
				},
				render: (_args, value) => {
					if (value.error) return text(value.error);
					if (value.count === 0) return text('No peers in the identity store.');
					const lines = value.peers.map((p) => {
						const role = p.role ? ` — ${p.role}` : '';
						const url = p.url ? `\n      ${p.url}` : '\n      (no receive URL — cannot be sent to)';
						return `  ${p.name}${role}${url}`;
					});
					return text(`${value.count} peer(s):\n${lines.join('\n')}`);
				},
			},
			async execute(args = {}) {
				const { peers, error } = await listPeers(settings.fleetRoot);
				if (error) return { count: 0, peers: [], error };
				const filtered = args.reachableOnly ? peers.filter((p) => p.url) : peers;
				return {
					count: filtered.length,
					peers: filtered.map((p) => ({
						name: p.name,
						role: p.role ?? null,
						platform: p.platform ?? null,
						url: p.url ?? null,
						reachable: Boolean(p.url),
						verified: Boolean(p.publicKey),
					})),
				};
			},
		},

		// ---------------------------------------------------------------- send ----
		{
			name: 'mesh_send',
			description:
				'Send a session-preserving message to another mesh peer. The envelope is Ed25519-signed and POSTed to the peer\'s own receive endpoint; on their side it arrives as a prompt with sender context. Returns whether it was DELIVERED — a failure is reported, never queued silently.',
			parameters: {
				agent: { type: 'string', required: true, description: 'Recipient peer name, as it appears in mesh_list.' },
				message: { type: 'string', required: true, description: 'The message body.' },
				action: {
					type: 'string',
					enum: ['do', 'info'],
					description: 'do = the recipient should act; info = acknowledgement only (default info).',
				},
				reply: {
					type: 'string',
					enum: ['yes', 'no', 'end'],
					description: 'yes = a reply is wanted; no = none wanted (default); end = terminal, closes the thread.',
				},
				ref: { type: 'string', description: 'The envelope id being replied to, when continuing an existing thread.' },
			},
			output: {
				schema: {
					type: 'object',
					additionalProperties: false,
					properties: {
						state: { type: 'string', required: true, description: 'delivered or error.' },
						status: { type: 'string', required: true },
						message_id: { type: 'string', required: true },
						to: { type: 'string' },
						detail: { type: 'string' },
					},
				},
				render: (_args, value) =>
					value.state === 'delivered'
						? text(`delivered to ${value.to} (id ${value.message_id})`)
						: text(`NOT delivered to ${value.to ?? '?'}: ${value.detail ?? value.status} (id ${value.message_id})`),
			},
			async execute(args) {
				const id = randomUUID();
				const self = selfAgent(settings);
				if (!self?.keyPath) {
					return { state: 'error', status: 'not-configured', message_id: id, detail: 'no outbound identity: set agents.<name>.keyPath' };
				}
				const peer = await readPeer(settings.fleetRoot, args.agent);
				if (!peer) {
					return { state: 'error', status: 'unknown-peer', message_id: id, to: args.agent, detail: `"${args.agent}" is not in the identity store` };
				}
				// Only the URL is needed to SEND — the peer's public key is what THEY use to
				// verify us, not the other way round.
				if (!peer.url) {
					return { state: 'error', status: 'unreachable', message_id: id, to: args.agent, detail: `"${args.agent}" has no receive URL` };
				}

				const request = buildSignedRequest({
					privateKey: loadPrivateKey(self.keyPath),
					from: self.name,
					to: peer.name,
					id,
					action: args.action ?? 'info',
					reply: args.reply ?? 'no',
					ref: args.ref ?? null,
					body: args.message,
				});
				const result = await deliverTo({ url: peer.url, request });
				if (result.ok) {
					logger('info', `mesh_send -> ${peer.name} (${id}) delivered`);
					return { state: 'delivered', status: 'delivered', message_id: id, to: peer.name };
				}
				logger('warn', `mesh_send -> ${peer.name} (${id}) failed: ${result.code} ${result.detail ?? ''}`);
				return {
					state: 'error',
					status: result.code ?? 'unreachable',
					message_id: id,
					to: peer.name,
					detail: result.detail ?? `peer answered ${result.status ?? 'nothing'}`,
				};
			},
		},

		// ---------------------------------------------------------------- sync ----
		{
			name: 'mesh_sync',
			description:
				'Fetch peer identities from the mesh registry and cache them locally. With no agent, syncs every registered peer. Writes only to this deployment\'s own cache directory, never to a shared store.',
			parameters: {
				agent: { type: 'string', description: 'One peer name; omit to sync all registered peers.' },
			},
			output: {
				schema: {
					type: 'object',
					additionalProperties: false,
					properties: {
						synced: { type: 'array', required: true, items: { type: 'string' } },
						failed: { type: 'array', required: true, items: { type: 'string' } },
						cacheDir: { type: 'string' },
						detail: { type: 'string' },
					},
				},
				render: (_args, value) =>
					text(
						`synced ${value.synced.length} peer(s)${value.failed.length ? `, ${value.failed.length} failed` : ''}` +
							`${value.cacheDir ? `\n  cached in ${value.cacheDir}` : ''}${value.detail ? `\n  ${value.detail}` : ''}`
					),
			},
			async execute(args = {}) {
				const self = selfAgent(settings);
				if (!self?.keyPath) return { synced: [], failed: [], detail: 'no outbound identity configured' };
				const registry = await registryFor(settings, self);

				const rows = args.agent
					? [(await registry.peer(args.agent)).body]
					: ((await registry.peers()).body?.peers ?? []);

				const synced = [];
				const failed = [];
				await mkdir(settings.cacheDir, { recursive: true });
				for (const row of rows) {
					const name = row?.name ?? row?.peer?.name;
					const peer = row?.peer ?? row;
					if (!name || !peer) {
						failed.push(String(args.agent ?? 'unknown'));
						continue;
					}
					try {
						await writeFile(join(settings.cacheDir, `${name}.json`), JSON.stringify(peer, null, 2), 'utf8');
						synced.push(name);
					} catch (error) {
						failed.push(`${name} (${error?.message ?? error})`);
					}
				}
				if (synced.length === 0 && failed.length === 0) {
					return { synced, failed, detail: 'the registry returned no peers' };
				}
				return { synced, failed, cacheDir: settings.cacheDir };
			},
		},

		// ------------------------------------------------------------ register ----
		{
			name: 'mesh_register',
			description:
				'Publish this agent\'s identity (name, receive URL and Ed25519 public key) to the mesh registry, so other peers can discover and verify it. The request is signed with this agent\'s own private key.',
			parameters: {
				ttl: { type: 'integer', description: 'Optional row lifetime in seconds.' },
			},
			output: {
				schema: {
					type: 'object',
					additionalProperties: false,
					properties: {
						state: { type: 'string', required: true },
						name: { type: 'string', required: true },
						url: { type: 'string' },
						detail: { type: 'string' },
					},
				},
				render: (_args, value) =>
					text(
						value.state === 'registered'
							? `registered ${value.name} -> ${value.url}`
							: `NOT registered: ${value.detail ?? value.state}`
					),
			},
			async execute(args = {}) {
				const self = selfAgent(settings);
				if (!self?.keyPath) return { state: 'error', name: '-', detail: 'no outbound identity configured' };
				if (!self.url) {
					return { state: 'error', name: self.name, detail: 'no receive URL: set agents.<name>.url' };
				}
				const registry = await registryFor(settings, self);
				const result = await registry.register({
					name: self.name,
					url: self.url,
					public_key: publicPemOf(loadPrivateKey(self.keyPath)),
					role: self.role ?? undefined,
					description: self.description ?? undefined,
					ttl: args.ttl ?? undefined,
				});
				if (result.ok) return { state: 'registered', name: self.name, url: self.url };
				return {
					state: 'error',
					name: self.name,
					url: self.url,
					detail: result.detail ?? result.body?.error ?? `registry answered ${result.status || result.code}`,
				};
			},
		},

		// ---------------------------------------------------------- deregister ----
		{
			name: 'mesh_deregister',
			description: 'Withdraw this agent\'s identity row from the mesh registry.',
			parameters: {
				agent: { type: 'string', description: 'Peer name to withdraw; defaults to this agent.' },
			},
			output: {
				schema: {
					type: 'object',
					additionalProperties: false,
					properties: {
						state: { type: 'string', required: true },
						name: { type: 'string', required: true },
						detail: { type: 'string' },
					},
				},
				render: (_args, value) => text(value.state === 'removed' ? `removed ${value.name} from the registry` : `NOT removed: ${value.detail ?? value.state}`),
			},
			async execute(args = {}) {
				const self = selfAgent(settings);
				if (!self?.keyPath) return { state: 'error', name: args.agent ?? '-', detail: 'no outbound identity configured' };
				const name = args.agent ?? self.name;
				const registry = await registryFor(settings, self);
				const result = await registry.deregister(name);
				if (result.ok) return { state: 'removed', name };
				return { state: 'error', name, detail: result.body?.error ?? `registry answered ${result.status || result.code}` };
			},
		},
	];
}

/**
 * Register the descriptors with the harness.
 *
 * `defineTool` is a PARAMETER rather than an import, and that is deliberate: the core lives
 * outside this plugin's resolution path under test, so an import here would make the wiring —
 * the one thing a restart depends on — impossible to test. The caller supplies the real one;
 * the tests supply a stub and assert that five tools land and that their disposers work.
 *
 * @returns the disposers, in registration order.
 */
export function registerMeshTools({ tools, defineTool, settings, logger }) {
	if (!tools || typeof tools.register !== 'function') {
		throw new TypeError('registerMeshTools: a tools service with a register() function is required');
	}
	if (typeof defineTool !== 'function') {
		throw new TypeError('registerMeshTools: defineTool is required');
	}
	const disposers = [];
	for (const descriptor of createToolDescriptors(settings, logger)) {
		disposers.push(tools.register(defineTool(descriptor)));
	}
	return disposers;
}
