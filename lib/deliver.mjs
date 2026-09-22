// dsh-fleet-mesh — turn an inbound envelope into a turn.
//
// PLAN.md §8 step 3. This is the payoff of Step 0's finding: the delivery matrix is
// the harness's own semantics, so this module is small. It chooses a session, picks
// one of three methods the agent already has, and hands over a message.
//
// WHY THE AGENT PATH AND NOT `session/prompt`:
//   * in-process — `ctx.agents` is a plain context service, so there is no token, no
//     loopback request and no Remote layer in the way;
//   * `session/prompt` is a thin wrapper over these very calls (session controller
//     L819-820: mode 'steer' -> agent.steer, else agent.followup);
//   * the one thing the controller adds that we lose is `hasPromptRequest(requestId)`,
//     its replay guard. That is exactly why dedupe lives in policy.mjs instead —
//     on this path it is ours to keep, not the core's.
//
// `createUserMessage` comes from @deepseek-ai/dsh-llm. It is imported dynamically and
// with an identity fallback, the same shape @goodandready/dsh-cron uses, so a core
// that renames the helper degrades instead of breaking the route.

/** How the peer's message presents itself in my log. */
export function renderPrompt(envelope) {
	// Provenance and the reply expectation, nothing more. A behavioural routing rule —
	// "answer a peer on the mesh, not in the operator's chat" — belongs in the agent's own
	// instructions, not in every message. A transport that rewrites behaviour is a
	// transport nobody can reason about.
	const header = `[mesh from ${envelope.from} · id ${envelope.id} · action ${envelope.action} · reply ${envelope.reply}]`;
	return envelope.body ? `${header}\n${envelope.body}` : header;
}

/**
 * Find the agent an inbound envelope belongs to.
 *
 * Resolution order (PLAN.md §7, decided 2026-09-22):
 *   1. an explicit sessionId, resumed when it is not live;
 *   2. otherwise the NEWEST live session whose preset matches.
 *
 * Deliberately not a dedicated mesh session, and deliberately not a pinned id: a
 * mesh message should land in the live conversation, and a pinned id goes stale the
 * moment the session is recreated.
 */
export async function resolveAgent({ agents, preset, sessionId = null }) {
	if (!agents) return { agent: null, reason: 'the agents service is unavailable' };

	if (sessionId) {
		const live = agents.get(sessionId);
		if (live) return { agent: live, reason: 'live session' };
		if (typeof agents.resume === 'function') {
			try {
				const handle = await agents.resume({ sessionId });
				const resumed = handle?.agent ?? handle ?? null;
				if (resumed) return { agent: resumed, reason: 'resumed session' };
			} catch (error) {
				return { agent: null, reason: `resume failed: ${error?.message ?? error}` };
			}
		}
		return { agent: null, reason: `session ${sessionId} is not live and could not be resumed` };
	}

	if (typeof agents.list !== 'function') return { agent: null, reason: 'the agents service has no list()' };
	const candidates = agents.list().filter((agent) => agent?.session?.header?.agentPreset === preset);
	if (candidates.length === 0) return { agent: null, reason: `no live session with preset "${preset}"` };
	candidates.sort((a, b) => (b.session.header.createdAt ?? 0) - (a.session.header.createdAt ?? 0));
	return { agent: candidates[0], reason: `newest live session with preset "${preset}"` };
}

/**
 * Hand one message to one agent through the chosen method.
 *
 * `method` is literally the name of an agent method, so the mapping from policy
 * decision to harness call is one word wide and cannot drift.
 */
export async function deliverToAgent({ agent, mode, envelope, createUserMessage }) {
	const method = agent?.[mode];
	if (typeof method !== 'function') return { ok: false, code: 'no-method', reason: `agent has no ${mode}()` };

	const message = createUserMessage({
		content: [{ type: 'text', text: renderPrompt(envelope) }],
		// The proven plugin-source shape (dsh-cron). Extra fields are avoided on
		// purpose: this object is validated, and the envelope id already rides in the
		// rendered text where a human reading the log can see it.
		source: { kind: 'plugin', plugin: 'dsh-fleet-mesh', form: 'mesh-receive' },
	});
	method.call(agent, message);
	return { ok: true, mode, agentId: agent.id };
}
