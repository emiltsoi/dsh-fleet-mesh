// dsh-mesh — the source-address allow list.
//
// Node can bind an address or all interfaces; it CANNOT bind a subnet. So "limit to
// 192.168.0.* and 192.168.1.*" is enforced here, in the request path, before any
// parsing or verification happens: the listener may sit on 0.0.0.0 while only these
// networks get past the door.
//
// `192.168.0.0/23` IS "192.168.0.* and 192.168.1.*" — a /23 spans 192.168.0.0 through
// 192.168.1.255. One rule, not two, so the two halves cannot drift apart.
//
// IPv4 only, deliberately. The fleet is IPv4 on the LAN, and a half-implemented IPv6
// matcher would be worse than an explicit refusal. Loopback is always admitted, in both
// families, so local testing and a same-host request keep working whatever the config
// says — the rule is about the LAN, not about this machine talking to itself.

/**
 * The default door: loopback only.
 *
 * EMPTY, deliberately — the same reasoning as the wake list. Which subnets may reach a
 * listener is a deployment's network decision, not a plugin's, so the plugin ships no
 * subnets at all. A deployment names its own, e.g. `allow: ['192.168.0.0/23']`.
 */
export const DEFAULT_ALLOW = [];

/** Always admitted, regardless of config. */
const LOOPBACK = new Set(['127.0.0.1', '::1']);

/**
 * Reduce a socket address to a comparable form.
 *
 * Node reports an IPv4 peer on a dual-stack socket as `::ffff:a.b.c.d`, so without
 * this the allow list would silently reject every legitimate LAN caller.
 */
export function normalizeIp(address) {
	if (typeof address !== 'string') return null;
	let ip = address.trim();
	if (ip === '') return null;
	const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
	if (mapped) return mapped[1];
	// A zone index (fe80::1%eth0) carries no meaning for these rules.
	const zone = ip.indexOf('%');
	if (zone !== -1) ip = ip.slice(0, zone);
	return ip;
}

/** Dotted-quad to a 32-bit unsigned integer, or null when it is not IPv4. */
export function ipv4ToInt(ip) {
	const parts = String(ip).split('.');
	if (parts.length !== 4) return null;
	let value = 0;
	for (const part of parts) {
		if (!/^\d{1,3}$/.test(part)) return null;
		const octet = Number(part);
		if (octet > 255) return null;
		value = value * 256 + octet;
	}
	return value >>> 0;
}

/** Whether an IPv4 address falls inside one CIDR. */
export function inCidr4(ip, cidr) {
	const [network, bitsRaw] = String(cidr).split('/');
	const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
	if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
	const address = ipv4ToInt(ip);
	const base = ipv4ToInt(network);
	if (address === null || base === null) return false;
	if (bits === 0) return true;
	const mask = (0xffffffff << (32 - bits)) >>> 0;
	return (address & mask) === (base & mask);
}

/**
 * The door.
 * @param address - `req.socket.remoteAddress`
 * @param allow   - CIDRs, e.g. ['192.168.0.0/23']
 * @returns whether this peer may be served at all.
 */
export function isAllowed(address, allow = DEFAULT_ALLOW) {
	const ip = normalizeIp(address);
	if (ip === null) return false;
	if (LOOPBACK.has(ip)) return true;
	// A non-loopback IPv6 peer has no rule that could admit it, and guessing would be
	// exactly the kind of half-implemented matcher this file refuses to be.
	if (ipv4ToInt(ip) === null) return false;
	return (Array.isArray(allow) ? allow : DEFAULT_ALLOW).some((cidr) => inCidr4(ip, cidr));
}
