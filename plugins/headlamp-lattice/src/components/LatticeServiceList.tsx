import { useMemo, useState } from 'react';
import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';

const { SectionBox, Link } = CommonComponents;
import { useLatticeServiceList } from '../LatticeService';
import PhaseIcon from './PhaseIcon';

/** Filterable list of all LatticeServices across namespaces */
export default function LatticeServiceList() {
  const [services, error] = useLatticeServiceList();
  const [search, setSearch] = useState('');
  const [phaseFilter, setPhaseFilter] = useState<string | null>(null);
  const [nsFilter, setNsFilter] = useState<string | null>(null);

  const namespaces = useMemo(() => {
    if (!services) return [];
    const ns = new Set(services.map((s: any) => s.metadata.namespace));
    return Array.from(ns).sort() as string[];
  }, [services]);

  const phases = useMemo(() => {
    if (!services) return [];
    const p = new Set(services.map((s: any) => s.phase));
    return Array.from(p).sort() as string[];
  }, [services]);

  const filtered = useMemo(() => {
    if (!services) return [];
    return services.filter((svc: any) => {
      const name: string = svc.metadata.name;
      const ns: string = svc.metadata.namespace;
      if (search && !name.toLowerCase().includes(search.toLowerCase())) return false;
      if (phaseFilter && svc.phase !== phaseFilter) return false;
      if (nsFilter && ns !== nsFilter) return false;
      return true;
    });
  }, [services, search, phaseFilter, nsFilter]);

  if (error) {
    return (
      <SectionBox title="Lattice Services">
        <p style={{ color: '#f44336' }}>Failed to load LatticeServices: {String(error)}</p>
      </SectionBox>
    );
  }

  if (!services) {
    return <SectionBox title="Lattice Services"><p>Loading...</p></SectionBox>;
  }

  return (
    <SectionBox title="Lattice Services">
      {/* Filters */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
        <input
          type="text"
          placeholder="Search by name..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{
            padding: '6px 12px',
            border: '1px solid #ccc',
            borderRadius: 4,
            minWidth: 200,
          }}
        />
        <select
          value={nsFilter ?? ''}
          onChange={(e) => setNsFilter(e.target.value || null)}
          style={{ padding: '6px 12px', border: '1px solid #ccc', borderRadius: 4 }}
        >
          <option value="">All Namespaces</option>
          {namespaces.map((ns) => (
            <option key={ns} value={ns}>{ns}</option>
          ))}
        </select>
        <select
          value={phaseFilter ?? ''}
          onChange={(e) => setPhaseFilter(e.target.value || null)}
          style={{ padding: '6px 12px', border: '1px solid #ccc', borderRadius: 4 }}
        >
          <option value="">All Phases</option>
          {phases.map((p) => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
        <span style={{ alignSelf: 'center', color: '#666' }}>
          {filtered.length} / {services.length} services
        </span>
      </div>

      {/* Table */}
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '2px solid #e0e0e0', textAlign: 'left' }}>
            <th style={{ padding: '8px 12px' }}>Name</th>
            <th style={{ padding: '8px 12px' }}>Namespace</th>
            <th style={{ padding: '8px 12px' }}>Phase</th>
            <th style={{ padding: '8px 12px' }}>Replicas</th>
            <th style={{ padding: '8px 12px' }}>Containers</th>
            <th style={{ padding: '8px 12px' }}>Mesh Deps</th>
            <th style={{ padding: '8px 12px' }}>Secrets</th>
            <th style={{ padding: '8px 12px' }}>GPUs</th>
            <th style={{ padding: '8px 12px' }}>Age</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((svc: any) => {
            const outbound = svc.outboundDeps?.length ?? 0;
            const inbound = svc.inboundDeps?.length ?? 0;
            const secretCount = svc.secrets?.length ?? 0;
            const gpuCount = svc.gpus?.reduce((sum: number, g: any) => sum + g.count, 0) ?? 0;
            const containerCount = Object.keys(svc.containers ?? {}).length;
            const created = svc.metadata.creationTimestamp;
            const age = created ? timeSince(new Date(created)) : '-';

            return (
              <tr
                key={`${svc.metadata.namespace}/${svc.metadata.name}`}
                style={{ borderBottom: '1px solid #f0f0f0' }}
              >
                <td style={{ padding: '8px 12px' }}>
                  <Link
                    routeName="LatticeServiceDetail"
                    params={{
                      namespace: svc.metadata.namespace,
                      name: svc.metadata.name,
                    }}
                  >
                    {svc.metadata.name}
                  </Link>
                </td>
                <td style={{ padding: '8px 12px' }}>{svc.metadata.namespace}</td>
                <td style={{ padding: '8px 12px' }}><PhaseIcon phase={svc.phase} /></td>
                <td style={{ padding: '8px 12px' }}>{svc.replicas}</td>
                <td style={{ padding: '8px 12px' }}>{containerCount}</td>
                <td style={{ padding: '8px 12px' }}>
                  {outbound > 0 || inbound > 0
                    ? `${outbound} out / ${inbound} in`
                    : '-'}
                </td>
                <td style={{ padding: '8px 12px' }}>{secretCount || '-'}</td>
                <td style={{ padding: '8px 12px' }}>{gpuCount || '-'}</td>
                <td style={{ padding: '8px 12px' }}>{age}</td>
              </tr>
            );
          })}
          {filtered.length === 0 && (
            <tr>
              <td colSpan={9} style={{ padding: '24px', textAlign: 'center', color: '#999' }}>
                No LatticeServices found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </SectionBox>
  );
}

function timeSince(date: Date): string {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  return `${days}d`;
}
