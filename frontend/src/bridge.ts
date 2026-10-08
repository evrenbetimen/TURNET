// Type-safe bridge to the Rust backend.
//
// Every function here mirrors a `#[tauri::command]` in `src-tauri`, and every
// payload type mirrors the corresponding Rust `serde` DTO. Keeping these in
// one file makes the Rust <-> TypeScript contract easy to audit.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

// --- payload types (mirror the Rust DTOs) ---

export interface ProxyStatus {
  running: boolean;
  bind: string;
  block_public_dns_for_turnet: boolean;
}

export interface RouteResult {
  host: string;
  route: "clear-web" | "turnet";
}

export interface ExportSummary {
  format: string;
  record_count: number;
  signature_prefix: string;
  note: string;
}

export interface TelemetrySnapshot {
  up_bps: number;
  down_bps: number;
  active_sessions: number;
  relay_hops: number;
}

// Event name must match `TELEMETRY_EVENT` in the Rust backend.
export const TELEMETRY_EVENT = "turnet://telemetry";

// --- command wrappers ---

export const api = {
  getProxyStatus(): Promise<ProxyStatus> {
    return invoke<ProxyStatus>("get_proxy_status");
  },

  setProxyRunning(running: boolean): Promise<ProxyStatus> {
    return invoke<ProxyStatus>("set_proxy_running", { running });
  },

  classifyDomain(host: string): Promise<RouteResult> {
    return invoke<RouteResult>("classify_domain", { host });
  },

  getCreditBalance(nodeId: number): Promise<number> {
    return invoke<number>("get_credit_balance", { nodeId });
  },

  exportComplianceReport(format: "json" | "csv"): Promise<ExportSummary> {
    return invoke<ExportSummary>("export_compliance_report", { format });
  },
};

// Subscribe to the 60fps telemetry stream. Returns an unlisten function.
export function onTelemetry(
  handler: (snapshot: TelemetrySnapshot) => void,
): Promise<UnlistenFn> {
  return listen<TelemetrySnapshot>(TELEMETRY_EVENT, (event) => {
    handler(event.payload);
  });
}
