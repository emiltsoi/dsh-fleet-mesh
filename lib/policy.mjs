// dsh-mesh — the delivery policy, as pure logic.
//
// This is the whole of PLAN.md §4's matrix and §6's guards, in one pure function.
// No I/O, no Date.now() — `now` is always passed in — so every rule below is
// directly testable, the same discipline the presence framework's arbiter uses.
//
// The three delivery methods are the harness's own, and their semantics are not
// interchangeable (verified in @deepseek-ai/dsh-agent-loop):
//
//   agent.followup(msg)  -> inbox "next-turn", wakeDriver()   a whole turn, now or at the boundary
//   agent.steer(msg)     -> inbox "next-step", wakeDriver()   injected into the work in progress
//   agent.inject(msg)    -> inbox "next-step", NO wake        lands at my next step, never starts one
//
// The inbox is a durable projection over `agent/inbox/spliced` session events, so a
// queued mesh message survives a restart. That is why "queue" here is a real
// guarantee and not a promise held in plugin memory.
//
// THE WAKE RULE IS OURS TO ENFORCE. There is no fleet-side per-sender policy:
// adapter.py states that "Ed25519 signature verification at intake acts as an
// allowlist", so any correctly-signed registered peer can reach this endpoint. The
// wake list is the only thing standing between a chatty sister and a bill.

/** Delivery methods, in the order the harness defines them. */
export const MODES = ['followup', 'steer', 'inject'];

/** Defaults. Every one is overridable per agent from the plugin config. */
export function defaultPolicy(overrides = {}) {
	return {
		// Who may START a turn. Everyone else is still delivered — they simply wait for
		// the next step boundary instead of waking anyone.
		//
		// EMPTY BY DEFAULT, deliberately: who may wake an agent is a deployment's social
		// decision, not a plugin's, so the plugin ships no names at all. A deployment
		// fills this in from its own config.
		wake: [],
		// At most N mesh items injected into one turn — the same cap recall uses.
		maxInjectedPerTurn: 3,
		// At most one mesh-INITIATED turn per window.
		wakeBudgetMs: 5 * 60 * 1000,
		// Consecutive mesh-initiated turns with no human input between them. Two
		// agents must not be able to bill each other indefinitely.
		runawayLimit: 4,
		...overrides,
	};
}

/** Fresh per-session policy state. */
export function initialState(now = 0) {
	return {
		lastWakeAt: -Infinity,
		injectedThisTurn: 0,
		turnsWithoutHuman: 0,
		seen: new Set(),
		lastAudit: null,
		now,
	};
}

/**
 * Decide how one inbound envelope should be delivered.
 *
 * @param policy   - a defaultPolicy() object
 * @param envelope - a parsed envelope
 * @param state    - policy state for the target agent
 * @param now      - epoch ms
 * @returns { mode, code?, reason? } where mode is 'refuse' when a guard fires.
 */
export function decideDelivery({ policy, envelope, state, now }) {
	// Idempotency first: a redelivered envelope must never fire a second turn.
	// The fleet retries in-request (3 attempts, 10 s deadline), so a duplicate
	// arrival is expected, not theoretical.
	if (state.seen.has(envelope.id)) {
		return { mode: 'refuse', code: 'duplicate', reason: `envelope ${envelope.id} already delivered` };
	}

	if (state.turnsWithoutHuman >= policy.runawayLimit) {
		return {
			mode: 'refuse',
			code: 'runaway',
			reason: `${state.turnsWithoutHuman} consecutive mesh turns with no human input`,
		};
	}

	// A broadcast never wakes anyone, and neither does a peer off the wake list.
	// Both still get delivered — silently, at my next step boundary. Dropping them
	// would be the "swallowed message" failure PLAN.md §5 exists to prevent.
	const listed = policy.wake.includes(envelope.from);
	const broadcast = envelope.to === '*';
	if (broadcast || !listed) {
		if (state.injectedThisTurn >= policy.maxInjectedPerTurn) {
			return { mode: 'refuse', code: 'cap', reason: `more than ${policy.maxInjectedPerTurn} mesh items this turn` };
		}
		return { mode: 'inject', reason: broadcast ? 'broadcast never wakes' : `${envelope.from} is not on the wake list` };
	}

	// A wake-listed peer, mid-thread, or asking for action: join the work in
	// progress rather than starting a separate turn.
	if (envelope.action === 'do' || envelope.ref) {
		if (state.injectedThisTurn >= policy.maxInjectedPerTurn) {
			return { mode: 'refuse', code: 'cap', reason: `more than ${policy.maxInjectedPerTurn} mesh items this turn` };
		}
		return { mode: 'steer', reason: envelope.ref ? 'same thread' : 'action: do from a wake-listed peer' };
	}

	// A wake-listed peer opening a NEW thread — this is the one case that starts a
	// turn, so it is the one case the budget governs.
	if (now - state.lastWakeAt < policy.wakeBudgetMs) {
		return { mode: 'inject', reason: `wake budget spent ${Math.round((now - state.lastWakeAt) / 1000)}s ago` };
	}
	return { mode: 'followup', reason: 'new thread from a wake-listed peer' };
}

/**
 * Fold one delivery back into the state. Pure: returns a new state.
 *
 * `humanInput` is the caller's judgement that a real person spoke since the last
 * mesh turn — it is what stops the runaway counter, so it must come from the
 * session's own event stream, never from a mesh message.
 */
export function recordDelivery(state, { envelope, mode, now, humanInput = false }) {
	const seen = new Set(state.seen);
	seen.add(envelope.id);
	// Bound the dedupe set: it is per-process and only needs to outlive the
	// fleet's retry window, not the session.
	if (seen.size > 512) seen.delete(seen.values().next().value);

	const counted = mode === 'steer' || mode === 'inject';
	return {
		...state,
		seen,
		injectedThisTurn: counted ? state.injectedThisTurn + 1 : state.injectedThisTurn,
		lastWakeAt: mode === 'followup' ? now : state.lastWakeAt,
		turnsWithoutHuman: humanInput
			? 0
			: mode === 'followup'
				? state.turnsWithoutHuman + 1
				: state.turnsWithoutHuman,
		lastAudit: { at: now, from: envelope.from, id: envelope.id, mode, action: envelope.action },
	};
}

/** Reset the per-turn injection counter — called at each turn boundary. */
export function beginTurn(state) {
	return { ...state, injectedThisTurn: 0 };
}

/**
 * A real person spoke. This is what stops the runaway counter, and it MUST come from the
 * session's own event stream — never from a mesh message, or two agents could vouch for
 * each other in a loop.
 *
 * Without this call the counter only ever increments, and after `runawayLimit` mesh turns
 * the guard refuses a wake-listed peer FOREVER. The guard is a circuit breaker, not a
 * one-way latch.
 */
export function recordHumanInput(state) {
	return { ...state, turnsWithoutHuman: 0 };
}

/** One audit line per mesh-initiated turn. Evidence, not mood. */
export function auditLine({ from, id, mode, action, reason }) {
	return `mesh ${mode} from=${from} id=${id} action=${action}${reason ? ` (${reason})` : ''}`;
}
