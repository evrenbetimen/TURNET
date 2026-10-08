# Turnet — Trusted Universal Relay Network

A scaffold for a Rust-core, Tauri-managed overlay-network daemon. This is a
**compiling skeleton**: module structure, typed interfaces, and documented
stubs — not yet working features. It builds with zero warnings and its
implemented pieces are unit-tested.

## Workspace layout

```
turnet/
├── Cargo.toml                 # workspace + shared [workspace.dependencies]
├── crates/
│   ├── proxy_core/            # local SOCKS5/HTTP trap + .tur/.vps/.cpt split router
│   ├── p2p_engine/            # UDP handshake, relay transport, session telemetry
│   ├── quantum_crypto/        # ChaCha20-Poly1305 AEAD + hybrid KDF; ML-KEM is a stub
│   ├── dht_resolver/          # libp2p Kademlia name→NodeID resolver, anycast, claims
│   ├── incentive_ledger/      # uptime/bandwidth → Network Credits state machine
│   └── compliance_reporting/  # operator-local audit log + signed exporter
├── src-tauri/                 # Tauri v2 backend: commands + 60fps telemetry emit
└── frontend/                  # React 19 + TypeScript + Tailwind (Vite) console shell
```

## What is implemented vs. stubbed

**Implemented & tested:** the split-router classifier (`classify_host`), the
ChaCha20-Poly1305 record cipher and hybrid key combiner, privacy record
padding (bucketed, length-preserving), the credit ledger state machine, the
SQLite (WAL) audit store with time-range queries, the signed JSON/CSV exporter
(with signature verification and write-to-disk), the disclosure-gated audit
record hook, the local node-control state machine, the defensive honeypot
sensor, and the Tauri command + telemetry-event plumbing (including node
control, audit-policy, and export commands wired to the UI).

**Documented stubs** (return `NotImplemented` / `todo!()` placeholders): the
proxy accept loop and SOCKS5/HTTP state machines, the UDP hybrid handshake,
ML-KEM/Kyber key encapsulation, the Kademlia swarm, anycast selection,
zero-knowledge handle claims, metering ingestion, and network credit
settlement.

## Design note — `compliance_reporting`

This crate is built as **transparent, operator-local, consent-based** audit
tooling, not covert surveillance or censorship infrastructure. Specifically:

- Audit logging is **off by default** and opt-in per node
  (`p2p_engine::audit_hook::AuditPolicy`). It records only what the local node
  observed, into that node's own store — there is no network-wide collection
  or correlation. Enabling it **requires an operator disclosure statement**:
  the API has no way to turn on silent logging. Exports can be scoped to a
  time window (`AuditStore::in_range`) for data minimization, and are signed
  and re-verifiable (`exporter::verify`).
- The originally-specified **"kill-switch that freezes network regions" on a
  genesis-key signal was intentionally omitted.** `node_control` provides only
  a *local* operator pause/stop for the operator's own node. Region-scale
  externally-triggered shutdown is censorship infrastructure and is explicitly
  out of scope; see the module docs.
- The **honeypot** and **DPI/transport-evasion** modules are inert documented
  stubs only.

See the crate-level docs in `crates/compliance_reporting/src/lib.rs` for the
full rationale.

## Building

```bash
# Rust core + Tauri backend
cargo check --workspace
cargo clippy --workspace --all-targets
cargo test --workspace

# Frontend
cd frontend && npm install && npm run build
```

> Linux desktop builds need the Tauri system libraries
> (`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `librsvg2-dev`,
> `libayatana-appindicator3-dev`). Dependency versions in the root
> `Cargo.toml` marked `# verify` should be re-checked against crates.io before
> a production release.
