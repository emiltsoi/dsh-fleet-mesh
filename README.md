# dsh-fleet-mesh

**Session-aware mesh relay for DSH agents.**

Standard agent-to-agent messaging is request/response — fine for one-shot jobs, inadequate for
conversational coordination. `dsh-fleet-mesh` adds **session-preserving** communication: when
one agent sends to another, the recipient knows who asked, what they are responding to, and
whether an answer is wanted. An inbound envelope is not a notification; it is a **prompt**.

One plugin serves the whole *substrate*, not one agent: agents are configured in a single
`agents:` map, and **one port** dispatches by the envelope's `[to:]` token. A second DSH agent
needs no second plugin and no second listener.

```
Sender: mesh_send(agent="ada", message="Review this plan", action="do", reply="yes")
  │
  ├─ 1. Resolves Ada's identity from the peer directory
  ├─ 2. Pads [mesh][v:1][from:lily][to:ada][id:uuid][action:do][reply:yes]
  ├─ 3. Ed25519-signs "{timestamp}\n{body}" with the sender's own private key
  └─ 4. POSTs to Ada's mesh endpoint, inside one shared 10 s delivery budget
```

## Status

**Both halves are complete and tested** — 170 assertions across four suites.

*Receiving:* signature verification, the delivery matrix, the wake list, the replay window,
per-envelope dedupe, and the runaway breaker.

*Sending:* the five tools below, built on the same tested libraries — envelope signing, the
delivery retry budget, the peer directory, and a registry client.

## Tools

Named exactly as hermes-mesh names hers, so muscle memory transfers between substrates.

| tool | purpose |
|:---|:---|
| `mesh_list` | list peers from the local identity store — read-only, no network |
| `mesh_send` | sign and deliver one envelope; reports **delivered** or a failure, never queues silently |
| `mesh_sync` | fetch peer identities from the registry into this deployment's own cache |
| `mesh_register` | publish this agent's row — name, receive URL and public key — to the registry |
| `mesh_deregister` | withdraw this agent's row |

`mesh_send` returns a result rather than a promise of one: `state` is `delivered` or `error`,
and a failure names its cause (`unreachable`, `unauthorized`, `unknown-peer`, `not-configured`).
There is no queue behind it — see below.

## What it does NOT do

- **No outbound spool.** A send either lands or fails informatively. A spool that reports
  success while nobody is home is a lie the sender then acts on.
- **No `session.cancel`.** Interrupting an agent's work is a human's call, never a peer's.
- **No thread ledger yet.** Terminal replies pass through; a ledger waits until a thread
  actually needs closing.
- **No fleet-wide wake policy.** If a transport has none — as hermes-mesh does not, where
  signature verification at intake *is* the allowlist — then the wake list here is the only
  thing between a chatty peer and a bill.

## Install

```bash
pnpm add dsh-fleet-mesh
```

Then add it to your profile's bundles. The plugin ships a **neutral default**: it inserts its
row with no config, so a fresh install opens nothing and serves nobody.

## Configure

Supply your own values as an id-targeted override in your profile's patch layer:

```yaml
- id: dsh-fleet-mesh
  config:
    host: '0.0.0.0'            # loopback-only by default
    port: 8760
    allow:                     # the real door, checked before anything else runs
      - 192.168.0.0/23
    durableRoute: '...'        # named in an "unreachable" reply, so a sender is told
                               # where to write instead of retrying into a void
    agents:
      <agent-name>:
        preset: <preset>       # the session is resolved by PRESET, never by a pinned id
        sessionId: null        # optional override for the odd case
        keyPath: '...'         # this agent's Ed25519 private key (PKCS8 PEM)
        wake: []               # who may START a turn — empty ships by default
```

The plugin ships **no subnets and no names**: which networks may reach a listener, and who may
wake an agent, are a deployment's decisions.

## Why it binds its own listener

The obvious implementation is to register a route on the harness's own web server. **It cannot
work, and the reason is measured rather than assumed:** that server binds `127.0.0.1` only, so
a peer's POST never completes a TCP connection. Widening it to `0.0.0.0` would expose the
entire web surface — GUI, API, and every other plugin's routes — which is a far larger act than
opening one mesh route.

So this plugin owns its listener and exposes **only** `/mesh/*`.

| route | purpose |
|:---|:---|
| `POST /mesh/receive` | verify an Ed25519-signed envelope, then deliver it as a prompt |
| `GET /mesh/health` | whether delivery is actually *possible*, not merely that the process is alive |

## The source-address allow list

Node can bind an address or all interfaces; it **cannot bind a subnet**. So the network limit
lives in the request path, checked **before** JSON parsing, before the peer lookup, and before
any signature work — an unwanted caller cannot make this process do work.

`192.168.0.0/23` **is** "192.168.0.\* and 192.168.1.\*": a /23 spans 192.168.0.0 through
192.168.1.255. One rule rather than two, so the halves cannot drift apart. Loopback is always
admitted.

Two details are load-bearing:

- **IPv4-mapped addresses are normalized first.** Node reports an IPv4 peer on a dual-stack
  socket as `::ffff:192.168.1.34`; without normalization the allow list would silently reject
  every legitimate LAN caller — a failure that looks exactly like "the peer cannot reach me".
- **Non-loopback IPv6 is refused outright** rather than half-matched.

## Envelope format

Bracketed header, then a free-form body:

```
[mesh][v:1][from:<sender>][to:<recipient>][id:<uuid>][session:?][from_session:?][action:do|info][reply:yes|no|end][ref:?]
```

`action` and `reply` are **optional on receive** (a missing value defaults to `info`/`no`) but
**required on send** — omitting them is how a tolerant receiver silently downgrades a request
into an acknowledgement. `to: '*'` is a broadcast, and **a broadcast never wakes anyone**.

## The delivery matrix is the harness's own semantics

Each policy decision maps to one word — the name of an agent method — so the two cannot drift:

| situation | call | effect |
|:---|:---|:---|
| idle, or busy + **new thread** | `agent.followup(msg)` | `next-turn` + wake — a whole turn, now or at the boundary |
| busy + **same thread** (`ref`), or `action: do` from a listed peer | `agent.steer(msg)` | `next-step` + wake — joins the work in progress |
| off the **wake list**, or a broadcast | `agent.inject(msg)` | `next-step`, **no wake** — lands at the next step |

The inbox is a **durable projection** over session events, so a queued message survives a
restart. A spool held in plugin memory would not.

## Security, replay protection, and durable delivery

- **Authentication is the signature**, over the **raw** request bytes — never over
  re-serialized JSON, which would reorder keys and break every signature. The signed form is
  `"{X-Mesh-Timestamp}\n{body}"`, with a fallback to the body alone for senders that omit the
  timestamp.
- **No CSRF guard**, unlike a browser-facing write route: this is a server-to-server webhook.
  A peer's POST carries no `sec-fetch-site` and no browser origin, so a same-origin check would
  reject every legitimate sender.
- **Replay window** (300 s default) plus a per-process dedupe set, so a redelivered envelope can
  never fire a second turn. In-request retries make duplicates expected, not theoretical.
- **Guards:** a per-turn injection cap, a wake budget, and a runaway breaker that stops two
  agents billing each other. The breaker is released by a real user message from the session's
  own event stream — **never by mesh traffic**, which must not be able to vouch for itself.
- **Fail informatively, never swallow:** an undeliverable message returns `unreachable` and
  names the durable route, so a sender never acts on a lie.

## Testing

```
node test/mesh.test.mjs       # envelope, crypto, access, policy, delivery
node test/outbound.test.mjs   # signing, retries, the peer directory, registry canonical JSON
node test/smoke.mjs           # the route table, driven with real Ed25519 signatures
node test/roundtrip.test.mjs  # the tools driving this plugin's own receive route
```

The round trip is the one that makes the halves one thing: it stands up the real receive
handler on a loopback port, a real identity store in a temp directory, and a stub registry that
**verifies the registration signature** rather than accepting it — then drives all five tools
through it. Nothing is mocked at the boundary that matters.

No dependencies to install: this plugin uses `node:` builtins only, and CI runs the suites on
Node 20, 22 and 24 with no install step.

To test against a real identity store, point `DSH_MESH_LIVE_STORE` at a directory of
`<name>/identity.yaml` entries. It is **opt-in** on purpose: a published plugin's tests must
pass on someone else's machine.

## Publishing

Publishing uses **npm trusted publishing (OIDC)** — there is no npm token anywhere, in the repo
or in a secret. npm exchanges the workflow's OIDC identity for a short-lived credential, which
is also why classic tokens are irrelevant here: npm **disabled their creation in November 2025**
and **revoked the existing ones in December 2025**.

**One-time setup, on npmjs.com.** A package cannot have a trusted publisher before it exists, so
the first publish is manual:

1. Publish the first version once from a machine logged into npm:
   ```bash
   npm login
   npm publish --access public
   ```
2. Open the package's settings — `https://www.npmjs.com/package/dsh-fleet-mesh/access` — and
   **Add a trusted publisher**:

   | field | value |
   |:---|:---|
   | Publisher | GitHub Actions |
   | Organization or user | `emiltsoi` |
   | Repository | `dsh-fleet-mesh` |
   | Workflow file | `.github/workflows/publish.yml` |
   | Environment | *(leave empty)* |

**Every release after that is automatic:** publish a GitHub release, and the workflow runs the
suites and then `npm publish --provenance`.

Two requirements worth knowing: npm CLI **≥ 11.5.1** (the workflow installs the latest), and
`id-token: write` in the job's permissions — already set.

## Troubleshooting

**A peer says it cannot reach me.** Check the bind with a *local socket query*
(`Get-NetTCPConnection -LocalPort <port>` on Windows, `ss -ltnp` elsewhere). A shell HTTP probe
can be intercepted by an egress proxy and will report a 403 that has nothing to do with your
listener.

**Everything returns 401.** The peer's public key probably did not parse. Public keys appear
both as `|` block scalars **and** as quoted scalars spread over several lines; a parser that
reads only the first line returns `-----BEGIN PUBLIC KEY-----` and fails every peer while the
code still looks correct. This suite asserts against real files for exactly that reason.

**The port is open but nothing arrives.** On Windows, look for a **program-scoped** firewall
rule covering the process that owns the listener — a port-scoped query misses it, and the
owning process is often not the one you expect.

**A peer is never woken.** The wake list ships empty, and a broadcast never wakes by design.
Check both before suspecting the transport.

**A wake-listed peer stopped being woken.** That is the runaway breaker. It clears on a real
user message in the session — by design, mesh traffic cannot clear it.

## License

MIT
