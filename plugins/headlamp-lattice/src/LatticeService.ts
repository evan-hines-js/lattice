/**
 * Data layer for LatticeService CRD (lattice.dev/v1alpha1).
 *
 * Read-only: this module only issues GET requests against the K8s API.
 * Write operations go through kubectl / CLI — never through this plugin.
 *
 * Uses polling (5s) with full error recovery. Each successful fetch clears
 * any prior error state so transient failures don't stick in the UI.
 */

import { ApiProxy } from '@kinvolk/headlamp-plugin/lib';
import { useEffect, useRef, useState } from 'react';
import type {
  LatticeServiceCRD,
  EnrichedLatticeService,
  ResourceSpec,
  ContainerSpec,
  ServicePhase,
} from './types';

const API_BASE = '/apis/lattice.dev/v1alpha1';
const POLL_INTERVAL_MS = 5000;

// ---------------------------------------------------------------------------
// Enrichment — derive convenience fields from raw CRD
// ---------------------------------------------------------------------------

function enrich(svc: LatticeServiceCRD): EnrichedLatticeService {
  const resources: Record<string, ResourceSpec> = svc.spec?.workload?.resources ?? {};
  const containers: Record<string, ContainerSpec> = svc.spec?.workload?.containers ?? {};

  const outboundDeps = [];
  const inboundDeps = [];
  const secrets = [];
  const gpus = [];

  for (const [name, r] of Object.entries(resources)) {
    const dir = r.direction ?? 'outbound';

    if (r.type === 'service') {
      if (dir === 'outbound' || dir === 'both') {
        outboundDeps.push({ name: r.id ?? name, namespace: r.namespace });
      }
      if (dir === 'inbound' || dir === 'both') {
        inboundDeps.push({ name: r.id ?? name, namespace: r.namespace });
      }
    } else if (r.type === 'secret') {
      const p = r.params as { provider?: string; keys?: string[] };
      secrets.push({ name, provider: p?.provider ?? 'unknown', keys: p?.keys });
    } else if (r.type === 'gpu') {
      const p = r.params as { count?: number; model?: string };
      gpus.push({ name, count: p?.count ?? 0, model: p?.model });
    }
  }

  return {
    ...svc,
    phase: (svc.status?.phase as ServicePhase) ?? 'Unknown',
    replicas: svc.spec?.replicas ?? 1,
    containers,
    resources,
    outboundDeps,
    inboundDeps,
    secrets,
    gpus,
  };
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/** List all LatticeServices across namespaces. Polls every 5s. */
export function useLatticeServiceList() {
  const [services, setServices] = useState<EnrichedLatticeService[] | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const prevHash = useRef('');

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const resp = await ApiProxy.request(`${API_BASE}/latticeservices`);
        if (cancelled) return;
        const items: LatticeServiceCRD[] = (resp as any).items ?? [];
        const enriched = items.map(enrich);

        // Only update state if data actually changed
        const hash = stableHash(enriched);
        if (hash !== prevHash.current) {
          prevHash.current = hash;
          setServices(enriched);
        }
        setError(null);
      } catch (err) {
        if (!cancelled) setError(err as Error);
      }
    }

    poll();
    const id = setInterval(poll, POLL_INTERVAL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  return [services, error] as const;
}

/** Get a single LatticeService by namespace/name. Polls every 5s. */
export function useLatticeServiceGet(namespace: string, name: string) {
  const [service, setService] = useState<EnrichedLatticeService | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const prevHash = useRef('');

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const resp = await ApiProxy.request(
          `${API_BASE}/namespaces/${namespace}/latticeservices/${name}`,
        );
        if (cancelled) return;
        const enriched = enrich(resp as LatticeServiceCRD);

        const hash = stableHash(enriched);
        if (hash !== prevHash.current) {
          prevHash.current = hash;
          setService(enriched);
        }
        setError(null);
      } catch (err) {
        if (!cancelled) setError(err as Error);
      }
    }

    poll();
    const id = setInterval(poll, POLL_INTERVAL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, [namespace, name]);

  return [service, error] as const;
}

// ---------------------------------------------------------------------------
// Stable hash — sorted keys so JSON key ordering doesn't cause false diffs
// ---------------------------------------------------------------------------

function sortedReplacer(_key: string, value: unknown): unknown {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)),
    );
  }
  return value;
}

function stableHash(obj: unknown): string {
  const str = JSON.stringify(obj, sortedReplacer);
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h + str.charCodeAt(i)) | 0;
  }
  return String(h);
}
