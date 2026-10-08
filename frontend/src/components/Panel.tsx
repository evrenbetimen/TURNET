import type { ReactNode } from "react";

interface PanelProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
}

// A titled card used for every dashboard panel.
export default function Panel({ title, subtitle, children }: PanelProps) {
  return (
    <section className="rounded-xl bg-turnet-panel border border-white/5 p-5 shadow-lg">
      <header className="mb-4">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-turnet-accent2">
          {title}
        </h2>
        {subtitle ? (
          <p className="mt-1 text-xs text-turnet-muted">{subtitle}</p>
        ) : null}
      </header>
      {children}
    </section>
  );
}
