/**
 * Mesh dependency summary — table showing connections and bilateral status.
 *
 * Problems (unilateral connections) are shown first with actionable messages
 * telling the developer exactly what's missing and where to fix it.
 */

import { useMemo } from 'react';
import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import type { EnrichedLatticeService } from '../types';
import { useLatticeStyles } from '../styles';

const { SectionBox } = CommonComponents;

interface MeshSummaryProps {
  services: EnrichedLatticeService[];
  focusService?: string;
}

interface MeshConnection {
  from: string;
  to: string;
  bilateral: boolean;
  missing?: 'inbound' | 'outbound';
}

function buildConnections(
  services: EnrichedLatticeService[],
  focusService?: string,
): MeshConnection[] {
  const svcMap = new Map<string, EnrichedLatticeService>();
  for (const svc of services) {
    svcMap.set(`${svc.metadata.namespace}/${svc.metadata.name}`, svc);
  }

  const connections: MeshConnection[] = [];
  const seen = new Set<string>();

  for (const svc of services) {
    const fromKey = `${svc.metadata.namespace}/${svc.metadata.name}`;

    for (const dep of svc.outboundDeps) {
      const toNs = dep.namespace ?? svc.metadata.namespace;
      const toKey = `${toNs}/${dep.name}`;
      if (!svcMap.has(toKey)) continue;

      const dedupKey = [fromKey, toKey].sort().join('::');
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      const target = svcMap.get(toKey)!;
      const targetAllowsInbound = target.inboundDeps.some((d) => {
        const dNs = d.namespace ?? target.metadata.namespace;
        return `${dNs}/${d.name}` === fromKey;
      });

      connections.push({
        from: fromKey,
        to: toKey,
        bilateral: targetAllowsInbound,
        missing: targetAllowsInbound ? undefined : 'inbound',
      });
    }
  }

  if (focusService) {
    return connections.filter((c) => c.from === focusService || c.to === focusService);
  }
  return connections;
}

export default function MeshSummary({ services, focusService }: MeshSummaryProps) {
  const s = useLatticeStyles();

  const connections = useMemo(
    () => buildConnections(services, focusService),
    [services, focusService],
  );

  const problems = useMemo(() => connections.filter((c) => !c.bilateral), [connections]);
  const healthy = useMemo(() => connections.filter((c) => c.bilateral), [connections]);

  if (connections.length === 0) {
    return (
      <SectionBox title="Mesh Dependencies">
        <p style={{ color: s.textSecondary, padding: 12 }}>No mesh dependencies declared</p>
      </SectionBox>
    );
  }

  return (
    <SectionBox title="Mesh Dependencies">
      <div style={{ marginBottom: 12, fontSize: 13, color: s.textSecondary }}>
        {connections.length} connection{connections.length !== 1 ? 's' : ''}
        {problems.length > 0 ? (
          <span style={{ color: s.warningColor, marginLeft: 8 }}>
            {problems.length} unilateral (policy gap)
          </span>
        ) : (
          <span style={{ color: s.successColor, marginLeft: 8 }}>all bilateral</span>
        )}
      </div>

      {problems.length > 0 && (
        <ConnectionTable
          label="Unilateral - action required"
          labelColor={s.warningColor}
          connections={problems}
          s={s}
          showIssue
        />
      )}

      {healthy.length > 0 && (
        <ConnectionTable
          label={problems.length > 0 ? 'Bilateral' : undefined}
          labelColor={s.successColor}
          connections={healthy}
          s={s}
        />
      )}
    </SectionBox>
  );
}

function ConnectionTable({
  label,
  labelColor,
  connections,
  s,
  showIssue,
}: {
  label?: string;
  labelColor: string;
  connections: MeshConnection[];
  s: ReturnType<typeof useLatticeStyles>;
  showIssue?: boolean;
}) {
  return (
    <div style={{ marginBottom: 16 }}>
      {label && (
        <div style={{
          fontSize: 12,
          fontWeight: 600,
          color: labelColor,
          marginBottom: 6,
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
        }}>
          {label}
        </div>
      )}
      <table style={s.table} role="table">
        <thead>
          <tr style={s.bodyRow}>
            <th style={s.th}>Source</th>
            <th style={{ ...s.th, textAlign: 'center' }}>Direction</th>
            <th style={s.th}>Target</th>
            <th style={s.th}>{showIssue ? 'Issue' : 'Status'}</th>
          </tr>
        </thead>
        <tbody>
          {connections.map((c) => (
            <tr key={`${c.from}-${c.to}`} style={s.bodyRow}>
              <td style={s.td}><code>{c.from}</code></td>
              <td style={{ ...s.td, textAlign: 'center' }}>{c.bilateral ? '\u2194' : '\u2192'}</td>
              <td style={s.td}><code>{c.to}</code></td>
              <td style={{ ...s.td, color: showIssue ? s.warningColor : s.successColor }}>
                {showIssue && c.missing === 'inbound'
                  ? `${c.to} needs inbound rule for ${c.from}`
                  : showIssue
                    ? `${c.from} needs outbound rule for ${c.to}`
                    : 'Bilateral'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
