// dsh-fleet-mesh — the peer directory: read the fleet's identity store.
//
// This is the substrate's equivalent of the fleet's "local vault cache". Runtimes verify
// from a cached identity, and the registry is NOT on the hot path — so reading the shared
// store directly is the honest mechanism, not a shortcut around one. It also means
// `mesh_list` and `mesh_send` work with no registry at all.
//
// The store lives on a share this box can read (`X:\.hermes\fleet\mesh\agents`), which is
// why discovery is possible before I am registered anywhere.
//
// Hand-rolled YAML, deliberately: the plugin contract for this profile is node: builtins
// only, and identity files are a flat, predictable shape. See crypto.mjs for the same
// reasoning applied to the public key specifically.
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { publicKeyFromIdentity } from './crypto.mjs';

/** The name grammar the envelope and the schema both enforce. */
export const PEER_NAME_RE = /^[a-z0-9][a-z0-9_.-]*$/i;

/** Pull one top-level scalar, tolerating quotes and a folded multi-line value. */
function scalar(text, key) {
	const m = new RegExp(`^\\s*${key}:\\s*(.*)$`, 'm').exec(text);
	if (!m) return null;
	const value = m[1].trim();
	if (value === '') return null;
	if (/^['"]/.test(value)) return value.replace(/^['"]|['"]$/g, '');
	return value;
}

/** Parse one identity.yaml into the fields the mesh actually uses. */
export function parseIdentity(text, fallbackName = null) {
	const name = scalar(text, 'name') ?? scalar(text, 'id') ?? fallbackName;
	const urlMatch = /^\s*url:\s*(\S+)\s*$/m.exec(text);
	return {
		name,
		id: scalar(text, 'id') ?? name,
		role: scalar(text, 'role'),
		description: scalar(text, 'description'),
		platform: scalar(text, 'platform'),
		url: urlMatch ? urlMatch[1].replace(/^['"]|['"]$/g, '') : null,
		publicKey: publicKeyFromIdentity(text),
	};
}

/**
 * Every peer the store knows, sorted by name.
 *
 * A directory without an identity.yaml is skipped rather than reported: the store also
 * holds non-agent entries, and `pilot.graduated-20260903` is a deliberate tombstone.
 */
export async function listPeers(fleetRoot) {
	let names;
	try {
		names = await readdir(fleetRoot);
	} catch (error) {
		return { peers: [], error: `cannot read the fleet store at ${fleetRoot}: ${error?.message ?? error}` };
	}
	const peers = [];
	for (const entry of names) {
		if (!PEER_NAME_RE.test(entry)) continue;
		const peer = await readPeer(fleetRoot, entry);
		if (peer) peers.push(peer);
	}
	peers.sort((a, b) => String(a.name).localeCompare(String(b.name)));
	return { peers, error: null };
}

/** One peer, or null when the store has no readable identity for that name. */
export async function readPeer(fleetRoot, name) {
	if (typeof name !== 'string' || !PEER_NAME_RE.test(name)) return null; // traversal guard before any join
	try {
		const text = await readFile(join(fleetRoot, name, 'identity.yaml'), 'utf8');
		const peer = parseIdentity(text, name);
		return peer.name ? peer : null;
	} catch {
		return null;
	}
}

/** Only the peers that are actually addressable — a URL and a key, or they cannot be sent to. */
export function addressable(peer) {
	return Boolean(peer?.url) && Boolean(peer?.publicKey);
}
