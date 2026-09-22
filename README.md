# dsh-mesh

**Session-aware mesh relay for DSH agents** — the DSH substrate's peer in an Ed25519-signed
agent mesh.

One plugin for the *substrate*, not one per agent: agents are configured in a single
`agents:` map, so a second DSH agent needs no second plugin.

| route | purpose |
|:---|:---|
| `POST /mesh/receive` | verify an Ed25519-signed envelope, then deliver it as a prompt |
| `GET /mesh/health` | whether delivery is actually *possible*, not merely that the process is alive |

## Status

The **receive half is complete and tested**: signature verification, the delivery matrix,
the wake list, replay and dedupe guards, and the runaway breaker.

The outbound half exists as libraries — envelope signing, delivery with retries, the peer
directory, and a registry client — and is **not yet exposed as agent-facing tools**. That
is the next step.

## Why it binds its own listener

The obvious implementation is to register a route on the harness's own web server. **It
cannot work, and the reason is measured rather than assumed:** that server binds
`127.0.0.1` only, so a peer's POST never completes a TCP connection. Widening it to
`0.0.0.0` would expose the entire web surface — GUI, API, and every other plugin's routes —
which is a far larger act than opening one mesh route.

So `dsh-mesh` owns its listener and exposes **only** `/mesh/*`. Verify the bind yourself
with a local socket query (`Get-NetTCPConnection -LocalPort <port>` on Windows,
`ss -ltnp` elsewhere) — a shell HTTP probe can be intercepted by an egress proxy and will
lie to you.

**Safe by default:** `host` defaults to `127.0.0.1` and the allow list defaults to empty,
so installing this opens nothing and serves nobody.

## The source-address allow list

Node can bind an address or all interfaces; it **cannot bind a subnet**. So the network
limit lives in the request path, checked **before** JSON parsing, before the peer lookup,
and before any signature work — an unwanted caller cannot make this process do work.

`192.168.0.0/23` **is** "192.168.0.\* and 192.168.1.\*": a /23 spans 192.168.0.0 through
192.168.1.255. One rule rather than two, so the halves cannot drift apart. Loopback is
always admitted.

Two details are load-bearing:

- **IPv4-mapped addresses are normalized first.** Node reports an IPv4 peer on a
  dual-stack socket as `::ffff:192.168.1.34`; without normalization the allow list would
  silently reject every legitimate LAN caller — a failure that looks exactly like "the
  peer cannot reach me".
- **Non-loopback IPv6 is refused outright** rather than half-matched. Name your subnets
  explicitly if you need IPv6.

> **A firewall rule may still be required.** On Windows, look for a **program-scoped**
> rule covering the process that owns the listener. A port-scoped query misses it, and
> the owning process is often not the one you expect.

## Config

The plugin ships a **neutral default**: it inserts its row with no config, so a fresh
install serves nobody. Supply your own values as an id-targeted override in your profile's
patch layer:

```yaml
- id: dsh-mesh
  config:
    host: '0.0.0.0'            # loopback-only by default
    port: 8760
    allow:                     # the real door, checked first
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

## The delivery matrix is the harness's own semantics

An inbound envelope is a **prompt**, not a notification. Each policy decision maps to one
word — the name of an agent method — so the two cannot drift:

| situation | call | effect |
|:---|:---|:---|
| idle, or busy + **new thread** | `agent.followup(msg)` | `next-turn` + wake — a whole turn, now or at the boundary |
| busy + **same thread** (`ref`), or `action: do` from a listed peer | `agent.steer(msg)` | `next-step` + wake — joins the work in progress |
| off the **wake list**, or a broadcast | `agent.inject(msg)` | `next-step`, **no wake** — lands at the next step |

The inbox is a **durable projection** over session events, so a queued message survives a
restart. A spool held in plugin memory would not.

**The wake list is the only thing standing between a chatty peer and a bill.** A mesh
transport may have no per-sender wake policy at all — if signature verification at intake
is the allowlist, any correctly-signed peer can reach the endpoint. Who may wake an agent
is a social decision, so the plugin ships **no names**.

## Security posture

- **Authentication is the signature**, over the **raw** request bytes — never over
  re-serialized JSON, which would reorder keys and break every signature. The signed form
  is `"{X-Mesh-Timestamp}\n{body}"`, with a fallback to the body alone for senders that
  omit the timestamp.
- **No CSRF guard**, unlike a browser-facing write route: this is a server-to-server
  webhook. A peer's POST carries no `sec-fetch-site` and no browser origin, so a
  same-origin check would reject every legitimate sender.
- **Replay window** (300 s default) plus a per-process dedupe set, so a redelivered
  envelope can never fire a second turn. In-request retries make duplicates expected, not
  theoretical.
- **Guards:** a per-turn injection cap, a wake budget, and a runaway breaker that stops two
  agents billing each other. The breaker is released by a real user message from the
  session's own event stream — never by mesh traffic, which must not be able to vouch for
  itself.
- **Fail informatively, never swallow:** an undeliverable message returns `unreachable` and
  names the durable route, so a sender never acts on a lie.

## Tests

```
node test/mesh.test.mjs       # envelope, crypto, access, policy, delivery
node test/outbound.test.mjs   # signing, retries, the peer directory, registry canonical JSON
node test/smoke.mjs           # the route table, driven with real Ed25519 signatures
```

To test against a real identity store, point `DSH_MESH_LIVE_STORE` at a directory of
`<name>/identity.yaml` entries. It is **opt-in** on purpose: a published plugin's tests
must pass on someone else's machine.

The suite parses every identity it is given and asserts each yields a loadable Ed25519 key.
That check exists because of a real trap: public keys appear both as `|` block scalars and
as quoted scalars spread over several lines, and a parser that reads only the first line
returns `-----BEGIN PUBLIC KEY-----` — failing every peer while the code still looks
correct.
