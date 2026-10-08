import { useEffect, useState } from "react";
import Panel from "./components/Panel";
import {
  api,
  onTelemetry,
  type AuditPolicy,
  type ExportSummary,
  type NodeRunState,
  type ProxyStatus,
  type RouteResult,
  type TelemetrySnapshot,
} from "./bridge";

const ZERO_TELEMETRY: TelemetrySnapshot = {
  up_bps: 0,
  down_bps: 0,
  active_sessions: 0,
  relay_hops: 0,
};

function formatRate(bps: number): string {
  if (bps < 1024) return `${bps} B/s`;
  if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`;
  return `${(bps / (1024 * 1024)).toFixed(2)} MB/s`;
}

// Small helper: call a backend command that may be unavailable when the page
// is opened outside the Tauri shell (e.g. a plain browser during dev).
async function safe<T>(p: Promise<T>, onOk: (v: T) => void) {
  try {
    onOk(await p);
  } catch {
    /* backend not reachable in this context; panels stay in placeholder state */
  }
}

export default function App() {
  const [telemetry, setTelemetry] = useState<TelemetrySnapshot>(ZERO_TELEMETRY);
  const [proxy, setProxy] = useState<ProxyStatus | null>(null);
  const [route, setRoute] = useState<RouteResult | null>(null);
  const [host, setHost] = useState("myhandle.tur");
  const [exportSummary, setExportSummary] = useState<ExportSummary | null>(null);
  const [nodeState, setNodeState] = useState<NodeRunState>("running");
  const [audit, setAudit] = useState<AuditPolicy | null>(null);
  const [disclosure, setDisclosure] = useState(
    "Connection records retained by this node operator; disclosed to users.",
  );

  useEffect(() => {
    void safe(api.getProxyStatus(), setProxy);
    void safe(api.getNodeState(), (r) => setNodeState(r.state));
    void safe(api.getAuditPolicy(), setAudit);
    const unlisten = onTelemetry(setTelemetry);
    return () => {
      void unlisten.then((fn) => fn());
    };
  }, []);

  return (
    <div className="min-h-full p-6">
      <header className="mb-6 flex items-baseline gap-3">
        <h1 className="text-2xl font-bold text-turnet-text">Turnet Console</h1>
        <span className="text-xs text-turnet-muted">
          Trusted Universal Relay Network — management & configuration
        </span>
      </header>

      <main className="grid grid-cols-1 gap-5 lg:grid-cols-2 xl:grid-cols-3">
        {/* Proxy status */}
        <Panel title="Proxy Status" subtitle="Local SOCKS5 / HTTP trap">
          <div className="space-y-2 text-sm">
            <Row label="Bind" value={proxy?.bind ?? "127.0.0.1:8888"} />
            <Row
              label="Public DNS blocked for .tur"
              value={proxy?.block_public_dns_for_turnet ? "yes" : "—"}
            />
            <Row
              label="State"
              value={proxy?.running ? "running" : "stopped"}
            />
            <button
              className="mt-2 rounded bg-turnet-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-turnet-accent2"
              onClick={() =>
                void safe(api.setProxyRunning(!(proxy?.running ?? false)), setProxy)
              }
            >
              {proxy?.running ? "Stop proxy" : "Start proxy"}
            </button>
          </div>
        </Panel>

        {/* Live speeds */}
        <Panel title="Live Speeds" subtitle="60fps telemetry stream">
          <div className="space-y-2 text-sm">
            <Row label="Download" value={formatRate(telemetry.down_bps)} />
            <Row label="Upload" value={formatRate(telemetry.up_bps)} />
          </div>
        </Panel>

        {/* Relay hops */}
        <Panel title="Relay Hops" subtitle="Active multi-hop circuit">
          <div className="space-y-2 text-sm">
            <Row label="Active sessions" value={String(telemetry.active_sessions)} />
            <Row label="Hops" value={String(telemetry.relay_hops)} />
          </div>
        </Panel>

        {/* Credit rewards */}
        <Panel title="Network Credits" subtitle="Uptime & bandwidth rewards">
          <p className="text-3xl font-semibold text-turnet-accent2">0</p>
          <p className="mt-1 text-xs text-turnet-muted">
            Credits accrue as this node relays traffic. Ledger wiring is a later
            milestone.
          </p>
        </Panel>

        {/* Split router preview */}
        <Panel title="Split Router" subtitle=".tur / .vps / .cpt vs clear web">
          <div className="space-y-2 text-sm">
            <div className="flex gap-2">
              <input
                className="flex-1 rounded bg-black/30 px-2 py-1 font-mono text-xs text-turnet-text outline-none"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                spellCheck={false}
              />
              <button
                className="rounded bg-turnet-accent px-3 py-1 text-xs font-medium text-white hover:bg-turnet-accent2"
                onClick={() => void safe(api.classifyDomain(host), setRoute)}
              >
                Classify
              </button>
            </div>
            {route ? (
              <Row
                label={route.host}
                value={route.route === "turnet" ? "→ Turnet P2P" : "→ clear web"}
              />
            ) : (
              <p className="text-xs text-turnet-muted">
                Enter a host to preview its route.
              </p>
            )}
          </div>
        </Panel>

        {/* Node control */}
        <Panel title="Node Control" subtitle="Local — this node only">
          <div className="space-y-3 text-sm">
            <Row label="State" value={nodeState} />
            <div className="flex gap-2">
              {(["pause", "resume", "stop"] as const).map((action) => (
                <button
                  key={action}
                  className="rounded bg-turnet-accent px-3 py-1 text-xs font-medium text-white hover:bg-turnet-accent2 disabled:opacity-40"
                  disabled={nodeState === "stopped"}
                  onClick={() =>
                    void safe(api.setNodeState(action), (r) => setNodeState(r.state))
                  }
                >
                  {action}
                </button>
              ))}
            </div>
            <p className="text-xs text-turnet-muted">
              Pauses/stops this operator&apos;s own node. There is no
              network-wide freeze.
            </p>
          </div>
        </Panel>

        {/* Audit logging */}
        <Panel title="Audit Logging" subtitle="Off by default, disclosure-gated">
          <div className="space-y-3 text-sm">
            <Row
              label="Recording"
              value={audit?.recording ? "on" : "off"}
            />
            <textarea
              className="h-16 w-full rounded bg-black/30 px-2 py-1 text-xs text-turnet-text outline-none"
              value={disclosure}
              onChange={(e) => setDisclosure(e.target.value)}
              placeholder="Disclosure statement shown to users (required to enable)"
            />
            <div className="flex gap-2">
              <button
                className="rounded bg-turnet-accent px-3 py-1 text-xs font-medium text-white hover:bg-turnet-accent2"
                onClick={() =>
                  void safe(api.setAuditPolicy(true, disclosure), setAudit)
                }
              >
                Enable
              </button>
              <button
                className="rounded bg-black/40 px-3 py-1 text-xs font-medium text-turnet-text hover:bg-black/60"
                onClick={() => void safe(api.setAuditPolicy(false, null), setAudit)}
              >
                Disable
              </button>
            </div>
            <p className="text-xs text-turnet-muted">
              Enabling requires a disclosure statement — silent logging cannot
              be turned on.
            </p>
          </div>
        </Panel>

        {/* Regulatory export */}
        <Panel
          title="Regulatory Export"
          subtitle="Operator-local, signed audit export"
        >
          <div className="space-y-3 text-sm">
            <p className="text-xs text-turnet-muted">
              Produces a signed export of this node&apos;s own audit records,
              for review under lawful process. Logging is operator-controlled
              and off by default; this is not a network-wide collection.
            </p>
            <div className="flex gap-2">
              <button
                className="rounded bg-turnet-accent px-3 py-1 text-xs font-medium text-white hover:bg-turnet-accent2"
                onClick={() =>
                  void safe(api.exportComplianceReport("json"), setExportSummary)
                }
              >
                Export JSON
              </button>
              <button
                className="rounded bg-turnet-accent px-3 py-1 text-xs font-medium text-white hover:bg-turnet-accent2"
                onClick={() =>
                  void safe(api.exportComplianceReport("csv"), setExportSummary)
                }
              >
                Export CSV
              </button>
            </div>
            {exportSummary ? (
              <div className="rounded bg-black/30 p-2 font-mono text-xs">
                <Row label="format" value={exportSummary.format} />
                <Row label="records" value={String(exportSummary.record_count)} />
                <Row label="sig" value={`${exportSummary.signature_prefix}…`} />
                <Row
                  label="verified"
                  value={exportSummary.verified ? "yes" : "no"}
                />
                <Row label="path" value={exportSummary.output_path} />
              </div>
            ) : null}
          </div>
        </Panel>
      </main>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-turnet-muted">{label}</span>
      <span className="font-mono text-turnet-text">{value}</span>
    </div>
  );
}
