import { useMemo, useState } from 'react';
import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import type { EnrichedLatticeService } from '../types';
import { useLatticeStyles } from '../styles';
import { useLatticeServiceList } from '../LatticeService';
import PhaseIcon from './PhaseIcon';

const { SectionBox, Link } = CommonComponents;

export default function LatticeServiceList() {
  const [services, error] = useLatticeServiceList();
  const [search, setSearch] = useState('');
  const [phaseFilter, setPhaseFilter] = useState<string | null>(null);
  const [nsFilter, setNsFilter] = useState<string | null>(null);
  const s = useLatticeStyles();

  const namespaces = useMemo(() => {
    if (!services) return [];
    return [...new Set(services.map((svc) => svc.metadata.namespace))].sort();
  }, [services]);

  const phases = useMemo(() => {
    if (!services) return [];
    return [...new Set(services.map((svc) => svc.phase))].sort();
  }, [services]);

  const filtered = useMemo(() => {
    if (!services) return [];
    return services.filter((svc) => {
      if (search && !svc.metadata.name.toLowerCase().includes(search.toLowerCase())) return false;
      if (phaseFilter && svc.phase !== phaseFilter) return false;
      if (nsFilter && svc.metadata.namespace !== nsFilter) return false;
      return true;
    });
  }, [services, search, phaseFilter, nsFilter]);

  if (error) {
    return (
      <SectionBox title="Lattice Services">
        <p role="alert" style={{ color: s.errorColor }}>
          Failed to load LatticeServices: {String(error)}
        </p>
      </SectionBox>
    );
  }

  if (!services) {
    return <SectionBox title="Lattice Services"><p>Loading...</p></SectionBox>;
  }

  return (
    <SectionBox title="Lattice Services">
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
        <input
          type="text"
          placeholder="Search by name..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search services by name"
          style={{ ...s.input, minWidth: 200 }}
        />
        <select
          value={nsFilter ?? ''}
          onChange={(e) => setNsFilter(e.target.value || null)}
          aria-label="Filter by namespace"
          style={s.input}
        >
          <option value="">All Namespaces</option>
          {namespaces.map((ns) => <option key={ns} value={ns}>{ns}</option>)}
        </select>
        <select
          value={phaseFilter ?? ''}
          onChange={(e) => setPhaseFilter(e.target.value || null)}
          aria-label="Filter by phase"
          style={s.input}
        >
          <option value="">All Phases</option>
          {phases.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        <span style={{ alignSelf: 'center', color: s.textSecondary }}>
          {filtered.length} / {services.length} services
        </span>
      </div>

      <table style={s.table} role="table">
        <thead>
          <tr style={s.headerRow}>
            <th style={s.th}>Name</th>
            <th style={s.th}>Namespace</th>
            <th style={s.th}>Phase</th>
            <th style={s.th}>Replicas</th>
            <th style={s.th}>Containers</th>
            <th style={s.th}>Mesh Deps</th>
            <th style={s.th}>Secrets</th>
            <th style={s.th}>GPUs</th>
            <th style={s.th}>Age</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((svc: EnrichedLatticeService) => (
            <ServiceRow key={`${svc.metadata.namespace}/${svc.metadata.name}`} svc={svc} s={s} />
          ))}
          {filtered.length === 0 && (
            <tr>
              <td colSpan={9} style={{ padding: 24, textAlign: 'center', color: s.textSecondary }}>
                No LatticeServices found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </SectionBox>
  );
}

function ServiceRow({ svc, s }: { svc: EnrichedLatticeService; s: ReturnType<typeof useLatticeStyles> }) {
  const outbound = svc.outboundDeps.length;
  const inbound = svc.inboundDeps.length;
  const gpuCount = svc.gpus.reduce((sum, g) => sum + g.count, 0);

  return (
    <tr style={s.bodyRow}>
      <td style={s.td}>
        <Link
          routeName="LatticeServiceDetail"
          params={{ namespace: svc.metadata.namespace, name: svc.metadata.name }}
        >
          {svc.metadata.name}
        </Link>
      </td>
      <td style={s.td}>{svc.metadata.namespace}</td>
      <td style={s.td}><PhaseIcon phase={svc.phase} /></td>
      <td style={s.td}>{svc.replicas}</td>
      <td style={s.td}>{Object.keys(svc.containers).length}</td>
      <td style={s.td}>
        {outbound > 0 || inbound > 0 ? `${outbound} out / ${inbound} in` : '-'}
      </td>
      <td style={s.td}>{svc.secrets.length || '-'}</td>
      <td style={s.td}>{gpuCount || '-'}</td>
      <td style={{ ...s.td, color: s.textSecondary }}>{timeSince(svc.metadata.creationTimestamp)}</td>
    </tr>
  );
}

function timeSince(timestamp: string): string {
  if (!timestamp) return '-';
  const seconds = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}
