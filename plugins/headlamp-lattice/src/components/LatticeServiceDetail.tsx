import { useParams } from 'react-router-dom';
import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import type { ContainerSpec, ResourceSpec, EnrichedLatticeService } from '../types';
import { useLatticeStyles } from '../styles';
import { useLatticeServiceGet, useLatticeServiceList } from '../LatticeService';
import PhaseIcon from './PhaseIcon';
import MeshSummary from './MeshSummary';

const { SectionBox } = CommonComponents;

export default function LatticeServiceDetail() {
  const { namespace, name } = useParams<{ namespace: string; name: string }>();
  const [service, error] = useLatticeServiceGet(namespace!, name!);
  const [allServices] = useLatticeServiceList();
  const s = useLatticeStyles();

  if (error) {
    return (
      <SectionBox title="LatticeService">
        <p role="alert" style={{ color: s.errorColor }}>Failed to load: {String(error)}</p>
      </SectionBox>
    );
  }

  if (!service) {
    return <SectionBox title="LatticeService"><p>Loading...</p></SectionBox>;
  }

  const svc: EnrichedLatticeService = service;

  return (
    <div>
      <HeaderSection svc={svc} s={s} />
      <ContainersSection svc={svc} s={s} />
      {allServices && (
        <MeshSummary
          services={allServices}
          focusService={`${svc.metadata.namespace}/${svc.metadata.name}`}
        />
      )}
      {Object.keys(svc.resources).length > 0 && <ResourcesSection svc={svc} s={s} />}
      {svc.spec?.ingress?.routes && <IngressSection svc={svc} s={s} />}
      {svc.status?.conditions && svc.status.conditions.length > 0 && (
        <ConditionsSection svc={svc} s={s} />
      )}
    </div>
  );
}

type Styles = ReturnType<typeof useLatticeStyles>;

// ---------------------------------------------------------------------------
// Sections — each one owns a SectionBox, receives shared styles
// ---------------------------------------------------------------------------

function HeaderSection({ svc, s }: { svc: EnrichedLatticeService; s: Styles }) {
  return (
    <SectionBox
      title={
        <span style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span>{svc.metadata.namespace}/{svc.metadata.name}</span>
          <PhaseIcon phase={svc.phase} />
        </span>
      }
    >
      {svc.status?.message && (
        <p style={{
          color: svc.phase === 'Failed' ? s.errorColor : s.textSecondary,
          marginBottom: 16,
        }}>
          {svc.status.message}
        </p>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
        <InfoCard label="Replicas" value={String(svc.replicas)} s={s} />
        <InfoCard
          label="Strategy"
          value={capitalize(svc.spec?.deploy?.strategy ?? 'Rolling')}
          s={s}
        />
        <InfoCard
          label="Autoscaling"
          value={svc.spec?.autoscaling ? `max ${svc.spec.autoscaling.max}` : 'Disabled'}
          s={s}
        />
      </div>
    </SectionBox>
  );
}

function ContainersSection({ svc, s }: { svc: EnrichedLatticeService; s: Styles }) {
  return (
    <SectionBox title="Containers">
      <table style={s.table} role="table">
        <thead>
          <tr style={s.bodyRow}>
            <th style={s.th}>Name</th>
            <th style={s.th}>Image</th>
            <th style={s.th}>CPU (req/lim)</th>
            <th style={s.th}>Memory (req/lim)</th>
            <th style={s.th}>Probes</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(svc.containers).map(([cName, c]: [string, ContainerSpec]) => (
            <tr key={cName} style={s.bodyRow}>
              <td style={s.td}><code style={{ color: s.infoColor }}>{cName}</code></td>
              <td style={s.td}>
                <code style={{ fontSize: 12, color: s.textSecondary }}>{c.image}</code>
              </td>
              <td style={s.td}>
                {c.resources?.requests?.cpu ?? '-'} / {c.resources?.limits?.cpu ?? '-'}
              </td>
              <td style={s.td}>
                {c.resources?.requests?.memory ?? '-'} / {c.resources?.limits?.memory ?? '-'}
              </td>
              <td style={s.td}>
                {probeLabel(c)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </SectionBox>
  );
}

function ResourcesSection({ svc, s }: { svc: EnrichedLatticeService; s: Styles }) {
  return (
    <SectionBox title="Resources">
      <table style={s.table} role="table">
        <thead>
          <tr style={s.bodyRow}>
            <th style={s.th}>Name</th>
            <th style={s.th}>Type</th>
            <th style={s.th}>Direction</th>
            <th style={s.th}>Target</th>
            <th style={s.th}>Details</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(svc.resources).map(([rName, r]: [string, ResourceSpec]) => (
            <tr key={rName} style={s.bodyRow}>
              <td style={s.td}><code style={{ color: s.infoColor }}>{rName}</code></td>
              <td style={s.td}><TypeBadge type={r.type} /></td>
              <td style={s.td}><DirectionLabel direction={r.direction ?? 'outbound'} color={s.textSecondary} /></td>
              <td style={s.td}>{r.namespace ? `${r.namespace}/` : ''}{r.id ?? rName}</td>
              <td style={s.td}><ResourceDetails resource={r} color={s.textSecondary} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </SectionBox>
  );
}

function IngressSection({ svc, s }: { svc: EnrichedLatticeService; s: Styles }) {
  return (
    <SectionBox title="Ingress Routes">
      <table style={s.table} role="table">
        <thead>
          <tr style={s.bodyRow}>
            <th style={s.th}>Name</th>
            <th style={s.th}>Kind</th>
            <th style={s.th}>Hosts</th>
            <th style={s.th}>Port</th>
            <th style={s.th}>TLS</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(svc.spec.ingress!.routes).map(([rName, r]) => (
            <tr key={rName} style={s.bodyRow}>
              <td style={s.td}><code style={{ color: s.infoColor }}>{rName}</code></td>
              <td style={s.td}>{r.kind}</td>
              <td style={s.td}>{r.hosts?.join(', ') ?? '-'}</td>
              <td style={s.td}>{r.port ?? r.listenPort ?? '-'}</td>
              <td style={s.td}>{r.tls ? 'Yes' : 'No'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </SectionBox>
  );
}

function ConditionsSection({ svc, s }: { svc: EnrichedLatticeService; s: Styles }) {
  return (
    <SectionBox title="Conditions">
      <table style={s.table} role="table">
        <thead>
          <tr style={s.bodyRow}>
            <th style={s.th}>Type</th>
            <th style={s.th}>Status</th>
            <th style={s.th}>Reason</th>
            <th style={s.th}>Message</th>
            <th style={s.th}>Last Transition</th>
          </tr>
        </thead>
        <tbody>
          {svc.status!.conditions.map((c, i) => (
            <tr key={i} style={s.bodyRow}>
              <td style={s.td}>{c.type}</td>
              <td style={s.td}>
                <span style={{ color: c.status === 'True' ? s.successColor : s.errorColor }}>
                  {c.status}
                </span>
              </td>
              <td style={s.td}>{c.reason ?? '-'}</td>
              <td style={s.td}>{c.message ?? '-'}</td>
              <td style={s.td}>{c.lastTransitionTime ?? '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </SectionBox>
  );
}

// ---------------------------------------------------------------------------
// Small reusable components
// ---------------------------------------------------------------------------

function InfoCard({ label, value, s }: { label: string; value: string; s: Styles }) {
  return (
    <div style={{
      padding: '12px 16px',
      background: s.bgDefault,
      borderRadius: 6,
      border: `1px solid ${s.borderColor}`,
    }}>
      <div style={{ fontSize: 11, color: s.textSecondary, marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 500, color: s.textPrimary }}>{value}</div>
    </div>
  );
}

const TYPE_COLORS: Record<string, string> = {
  service: '#2196f3',
  'external-service': '#9c27b0',
  volume: '#795548',
  secret: '#f44336',
  gpu: '#ff9800',
};

function TypeBadge({ type }: { type: string }) {
  const color = TYPE_COLORS[type] ?? '#9e9e9e';
  return (
    <span style={{
      background: `${color}33`,
      color,
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: 12,
      fontWeight: 500,
    }}>
      {type}
    </span>
  );
}

const DIRECTION_ARROWS: Record<string, string> = {
  outbound: '\u2192',
  inbound: '\u2190',
  both: '\u2194',
};

function DirectionLabel({ direction, color }: { direction: string; color: string }) {
  return (
    <span style={{ fontSize: 12, color }}>
      {DIRECTION_ARROWS[direction] ?? '?'} {direction}
    </span>
  );
}

function ResourceDetails({ resource, color }: { resource: ResourceSpec; color: string }) {
  const p = resource.params;
  if (!p || typeof p !== 'object') return <span style={{ color }}>-</span>;

  if (resource.type === 'secret') {
    const sp = p as { provider?: string; keys?: string[] };
    return <span style={{ color }}>provider: {sp.provider}{sp.keys ? `, keys: ${sp.keys.join(', ')}` : ''}</span>;
  }
  if (resource.type === 'gpu') {
    const gp = p as { count?: number; model?: string; memory?: string };
    return <span style={{ color }}>{gp.count}x {gp.model ?? 'GPU'}{gp.memory ? ` (${gp.memory})` : ''}</span>;
  }
  if (resource.type === 'volume') {
    const vp = p as { size?: string; storageClass?: string };
    return <span style={{ color }}>{vp.size ?? 'shared'}{vp.storageClass ? ` (${vp.storageClass})` : ''}</span>;
  }
  if (resource.type === 'external-service') {
    const ep = p as { endpoints?: Record<string, string> };
    return <span style={{ color }}>{Object.entries(ep.endpoints ?? {}).map(([k, v]) => `${k}: ${v}`).join(', ')}</span>;
  }

  return <span style={{ color }}>-</span>;
}

function probeLabel(c: ContainerSpec): string {
  const probes = [
    c.livenessProbe && 'L',
    c.readinessProbe && 'R',
    c.startupProbe && 'S',
  ].filter(Boolean);
  return probes.length > 0 ? probes.join(' ') : '-';
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}
