import { useParams } from 'react-router-dom';
import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';

const { SectionBox } = CommonComponents;
import { useLatticeServiceGet, useLatticeServiceList } from '../LatticeService';
import PhaseIcon from './PhaseIcon';
import MeshGraph from './MeshGraph';

/** Detail view for a single LatticeService */
export default function LatticeServiceDetail() {
  const { namespace, name } = useParams<{ namespace: string; name: string }>();
  const [service, error] = useLatticeServiceGet(namespace!, name!);
  const [allServices] = useLatticeServiceList();

  if (error) {
    return (
      <SectionBox title="LatticeService">
        <p style={{ color: '#f44336' }}>Failed to load: {String(error)}</p>
      </SectionBox>
    );
  }

  if (!service) {
    return <SectionBox title="LatticeService"><p>Loading...</p></SectionBox>;
  }

  const svc = service as any;

  return (
    <div>
      {/* Header */}
      <SectionBox
        title={
          <span style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span>{svc.metadata.namespace}/{svc.metadata.name}</span>
            <PhaseIcon phase={svc.phase} />
          </span>
        }
      >
        {svc.status?.message && (
          <p style={{ color: svc.phase === 'Failed' ? '#f44336' : '#aaa', marginBottom: 16 }}>
            {svc.status.message}
          </p>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
          <InfoCard label="Replicas" value={String(svc.replicas)} />
          <InfoCard
            label="Strategy"
            value={capitalize(svc.spec?.deploy?.strategy ?? 'Rolling')}
          />
          <InfoCard
            label="Autoscaling"
            value={
              svc.spec?.autoscaling
                ? `max ${svc.spec.autoscaling.max}`
                : 'Disabled'
            }
          />
        </div>
      </SectionBox>

      {/* Containers */}
      <SectionBox title="Containers">
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #444', textAlign: 'left' }}>
              <th style={th}>Name</th>
              <th style={th}>Image</th>
              <th style={th}>CPU (req/lim)</th>
              <th style={th}>Memory (req/lim)</th>
              <th style={th}>Probes</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(svc.containers).map(([cName, c]: [string, any]) => (
              <tr key={cName} style={{ borderBottom: '1px solid #333' }}>
                <td style={td}><code style={{ color: '#90caf9' }}>{cName}</code></td>
                <td style={td}><code style={{ fontSize: 12, color: '#ccc' }}>{c.image}</code></td>
                <td style={td}>
                  {c.resources?.requests?.cpu ?? '-'} / {c.resources?.limits?.cpu ?? '-'}
                </td>
                <td style={td}>
                  {c.resources?.requests?.memory ?? '-'} / {c.resources?.limits?.memory ?? '-'}
                </td>
                <td style={td}>
                  {[
                    c.liveness_probe && 'L',
                    c.readiness_probe && 'R',
                    c.startup_probe && 'S',
                  ]
                    .filter(Boolean)
                    .join(' ') || '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </SectionBox>

      {/* Mesh Dependencies */}
      {allServices && (
        <MeshGraph
          services={allServices}
          focusService={`${svc.metadata.namespace}/${svc.metadata.name}`}
        />
      )}

      {/* Resource Dependencies Table */}
      {Object.keys(svc.resources).length > 0 && (
        <SectionBox title="Resources">
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #444', textAlign: 'left' }}>
                <th style={th}>Name</th>
                <th style={th}>Type</th>
                <th style={th}>Direction</th>
                <th style={th}>Target</th>
                <th style={th}>Details</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(svc.resources).map(([rName, r]: [string, any]) => (
                <tr key={rName} style={{ borderBottom: '1px solid #333' }}>
                  <td style={td}><code style={{ color: '#90caf9' }}>{rName}</code></td>
                  <td style={td}>
                    <TypeBadge type={r.type} />
                  </td>
                  <td style={td}>
                    <DirectionBadge direction={r.direction ?? 'outbound'} />
                  </td>
                  <td style={td}>
                    {r.namespace ? `${r.namespace}/` : ''}
                    {r.id ?? rName}
                  </td>
                  <td style={td}>
                    <ResourceDetails resource={r} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </SectionBox>
      )}

      {/* Ingress */}
      {svc.spec?.ingress?.routes && (
        <SectionBox title="Ingress Routes">
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #444', textAlign: 'left' }}>
                <th style={th}>Name</th>
                <th style={th}>Kind</th>
                <th style={th}>Hosts</th>
                <th style={th}>Port</th>
                <th style={th}>TLS</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(svc.spec.ingress.routes).map(([rName, r]: [string, any]) => (
                <tr key={rName} style={{ borderBottom: '1px solid #333' }}>
                  <td style={td}><code style={{ color: '#90caf9' }}>{rName}</code></td>
                  <td style={td}>{r.kind}</td>
                  <td style={td}>{r.hosts?.join(', ') ?? '-'}</td>
                  <td style={td}>{r.port ?? r.listen_port ?? '-'}</td>
                  <td style={td}>{r.tls ? 'Yes' : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </SectionBox>
      )}

      {/* Conditions */}
      {svc.status?.conditions?.length > 0 && (
        <SectionBox title="Conditions">
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #444', textAlign: 'left' }}>
                <th style={th}>Type</th>
                <th style={th}>Status</th>
                <th style={th}>Reason</th>
                <th style={th}>Message</th>
                <th style={th}>Last Transition</th>
              </tr>
            </thead>
            <tbody>
              {svc.status.conditions.map((c: any, i: number) => (
                <tr key={i} style={{ borderBottom: '1px solid #333' }}>
                  <td style={td}>{c.type}</td>
                  <td style={td}>
                    <span style={{ color: c.status === 'True' ? '#4caf50' : '#f44336' }}>
                      {c.status}
                    </span>
                  </td>
                  <td style={td}>{c.reason ?? '-'}</td>
                  <td style={td}>{c.message ?? '-'}</td>
                  <td style={td}>{c.lastTransitionTime ?? '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </SectionBox>
      )}
    </div>
  );
}

// Helper components

function InfoCard({ label, value }: { label: string; value: string }) {
  return (
    <div style={{
      padding: '12px 16px',
      background: 'rgba(255, 255, 255, 0.06)',
      borderRadius: 6,
      border: '1px solid rgba(255, 255, 255, 0.1)',
    }}>
      <div style={{ fontSize: 11, color: '#999', marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 500, color: '#e0e0e0' }}>{value}</div>
    </div>
  );
}

function TypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    service: '#2196f3',
    'external-service': '#9c27b0',
    volume: '#795548',
    secret: '#f44336',
    gpu: '#ff9800',
  };
  const color = colors[type] ?? '#9e9e9e';
  return (
    <span
      style={{
        background: `${color}33`,
        color,
        padding: '2px 8px',
        borderRadius: 4,
        fontSize: 12,
        fontWeight: 500,
      }}
    >
      {type}
    </span>
  );
}

function DirectionBadge({ direction }: { direction: string }) {
  const arrows: Record<string, string> = {
    outbound: '\u2192',
    inbound: '\u2190',
    both: '\u2194',
  };
  return (
    <span style={{ fontSize: 12, color: '#ccc' }}>
      {arrows[direction] ?? '?'} {direction}
    </span>
  );
}

function ResourceDetails({ resource }: { resource: any }) {
  const p = resource.params;
  if (!p || typeof p !== 'object') return <span style={{ color: '#888' }}>-</span>;

  const style = { color: '#ccc' } as const;

  if (resource.type === 'secret') {
    return <span style={style}>provider: {p.provider}{p.keys ? `, keys: ${p.keys.join(', ')}` : ''}</span>;
  }
  if (resource.type === 'gpu') {
    return <span style={style}>{p.count}x {p.model ?? 'GPU'}{p.memory ? ` (${p.memory})` : ''}</span>;
  }
  if (resource.type === 'volume') {
    return <span style={style}>{p.size ?? 'shared'}{p.storage_class ? ` (${p.storage_class})` : ''}</span>;
  }
  if (resource.type === 'external-service') {
    const eps = Object.entries(p.endpoints ?? {});
    return <span style={style}>{eps.map(([k, v]) => `${k}: ${v}`).join(', ')}</span>;
  }

  return <span style={{ color: '#888' }}>-</span>;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}

const th = { padding: '8px 12px', color: '#aaa', fontWeight: 600, fontSize: 13 } as const;
const td = { padding: '8px 12px', color: '#ddd', fontSize: 13 } as const;
