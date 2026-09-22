// dsh-mesh — Ed25519 signing and verification, in node: builtins only.
//
// This is a faithful reimplementation of mesh_core.crypto (the fleet's shared
// primitives) so the DSH substrate needs no Python and no dependency:
//   X:\CascadeProjects\mesh-peer-registry\mesh_core\crypto.py
//
// What matters, and why each detail is load-bearing:
//
//   key formats   private PKCS8 PEM, unencrypted; public SPKI PEM; signature is the
//                 raw 64-byte Ed25519 signature, base64-encoded. node:crypto exports
//                 exactly these framings for 'ed25519', so nothing has to be coerced.
//
//   signed bytes  session_relay.py L381
//                   signed_body = f"{timestamp}\n{wire_body}"   (when sign_timestamp)
//                 The POST carries wire_body ALONE; the timestamp rides in the
//                 X-Mesh-Timestamp header. So the receiver must rebuild the signed
//                 bytes from the HEADER plus the RAW body — never from re-serialized
//                 JSON, which would reorder keys and break every signature.
//
//   fallback      adapter.py L566 verifies the body alone when the timestamped form
//                 fails, for senders that never included a timestamp. We accept both
//                 on receive; we always SEND the timestamped form.
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

/** Load a PKCS8 Ed25519 private key from disk. */
export function loadPrivateKey(path) {
	return createPrivateKey(readFileSync(path, 'utf8'));
}

/** The SPKI public PEM for a private key — what identity.yaml carries. */
export function publicPemOf(privateKey) {
	return createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
}

/** base64(Ed25519(timestamp + "\n" + body)), or the body alone without a timestamp. */
export function signPayload(privateKey, timestamp, bodyBuffer) {
	// session_relay.py L381: with sign_timestamp ON the signed bytes are
	// "{timestamp}\n{body}"; with it OFF they are the body alone. Both must be
	// reachable here, because we verify both forms and sign whichever we send.
	const signed = timestamp
		? Buffer.concat([Buffer.from(`${timestamp}\n`, 'utf8'), bodyBuffer])
		: bodyBuffer;
	return sign(null, signed, privateKey).toString('base64');
}

/** The 12-byte SPKI header for an Ed25519 public key (OID 1.3.101.112). */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Accept a raw 32-byte key or a full 44-byte SPKI DER. */
function spkiFromDer(der) {
	if (der.length === 32) {
		return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, der]), format: 'der', type: 'spki' });
	}
	if (der.length === 44) return createPublicKey({ key: der, format: 'der', type: 'spki' });
	return null;
}

/**
 * Load a peer's public key from any framing the fleet tolerates.
 *
 * Deliberately WHITESPACE-INSENSITIVE. A YAML scalar folds its line breaks, so the
 * same PEM arrives with real newlines (a `|` block scalar) or with spaces (a quoted
 * scalar separated by blank lines) — and ada's live identity is the quoted form.
 * Rather than depend on which, every framing is reduced to base64 and rebuilt as DER.
 */
export function loadPublicKey(input) {
	const raw = String(input ?? '').trim();
	if (raw === '') return null;
	try {
		const base64 = raw.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
		if (base64 === '') return null;
		return spkiFromDer(Buffer.from(base64, 'base64'));
	} catch {
		return null;
	}
}

/**
 * Verify one inbound envelope signature.
 * @returns true when either the timestamped form or the bare-body form verifies.
 */
export function verifyPayload(publicKeyInput, timestamp, bodyBuffer, signatureB64) {
	const key = loadPublicKey(publicKeyInput);
	if (key === null) return false;
	let signature;
	try {
		signature = Buffer.from(String(signatureB64 ?? ''), 'base64');
	} catch {
		return false;
	}
	if (signature.length !== 64) return false;

	if (timestamp) {
		const signed = Buffer.concat([Buffer.from(`${timestamp}\n`, 'utf8'), bodyBuffer]);
		try {
			if (verify(null, signed, key, signature)) return true;
		} catch {
			/* fall through to the untimestamped form */
		}
	}
	// adapter.py L566: the compatibility path for senders that omit the timestamp.
	try {
		return verify(null, bodyBuffer, key, signature);
	} catch {
		return false;
	}
}

/**
 * Reduce any of the fleet's framings to a canonical SPKI PEM.
 *
 * The contract of publicKeyFromIdentity is "give me the PEM", not "give me whatever
 * YAML folding produced" — so the caller never has to care which scalar style the
 * peer's file happens to use.
 */
function canonicalPem(value) {
	const base64 = String(value ?? '').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
	if (base64 === '' || !/^[A-Za-z0-9+/=]+$/.test(base64)) return String(value ?? '').trim();
	return `-----BEGIN PUBLIC KEY-----\n${base64}\n-----END PUBLIC KEY-----`;
}

/**
 * Extract `auth.public_key` from an identity.yaml, as a canonical PEM.
 *
 * Deliberately hand-rolled: the plugin contract for this profile is node: builtins
 * only, and the fleet's identity files use one of exactly three shapes — a `|` block
 * scalar, a quoted inline scalar, or a quoted scalar spread over several lines. A
 * YAML dependency for that would be the tail wagging the dog.
 */
export function publicKeyFromIdentity(yamlText) {
	const scalar = extractPublicKeyScalar(yamlText);
	return scalar === null ? null : canonicalPem(scalar);
}

function extractPublicKeyScalar(yamlText) {
	const lines = String(yamlText ?? '').split(/\r?\n/);
	for (let i = 0; i < lines.length; i += 1) {
		const m = /^([ \t]*)public_key:[ \t]*(.*)$/.exec(lines[i]);
		if (!m) continue;
		const indent = m[1].length;
		const rest = m[2].trim();
		if (rest.startsWith("'") || rest.startsWith('"')) {
			// A QUOTED SCALAR, and the live fleet writes these across several lines —
			// ada's identity is exactly this shape. YAML folds the line breaks into
			// spaces. Reading only the first line yields "-----BEGIN PUBLIC KEY-----"
			// and fails every verification, so the continuation is handled explicitly.
			const quote = rest[0];
			let value = rest.slice(1);
			if (value.length > 1 && value.endsWith(quote)) return value.slice(0, -1);
			for (let j = i + 1; j < lines.length; j += 1) {
				const line = lines[j].trim();
				if (line.endsWith(quote)) return `${value} ${line.slice(0, -1)}`.trim();
				value += ` ${line}`;
			}
			return value.trim();
		}
		if (rest !== '' && !rest.startsWith('|') && !rest.startsWith('>')) {
			return rest;
		}
		const block = [];
		for (let j = i + 1; j < lines.length; j += 1) {
			const line = lines[j];
			if (line.trim() === '') {
				block.push('');
				continue;
			}
			const lead = line.length - line.trimStart().length;
			if (lead <= indent) break;
			block.push(line.trim());
		}
		const joined = block.join('\n').trim();
		return joined === '' ? null : joined;
	}
	return null;
}
