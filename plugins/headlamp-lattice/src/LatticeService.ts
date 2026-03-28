import { ApiProxy } from '@kinvolk/headlamp-plugin/lib';
import { useEffect, useRef, useState } from 'react';

const API_BASE = '/apis/lattice.dev/v1alpha1';

interface LatticeServiceItem {
  metadata: {
    name: string;
    namespace: string;
    creationTimestamp: string;
    [key: string]: any;
  };
  spec: any;
  status?: any;
}

function extractHelpers(svc: LatticeServiceItem) {
  const resources = svc.spec?.workload?.resources ?? {};

  return {
    ...svc,
    phase: svc.status?.phase ?? 'Unknown',
    replicas: svc.spec?.replicas ?? 1,
    containers: svc.spec?.workload?.containers ?? {},
    resources,

    outboundDeps: Object.entries(resources)
      .filter(([_, r]: [string, any]) => {
        const dir = r.direction ?? 'outbound';
        return r.type === 'service' && (dir === 'outbound' || dir === 'both');
      })
      .map(([name, r]: [string, any]) => ({
        name: r.id ?? name,
        namespace: r.namespace,
      })),

    inboundDeps: Object.entries(resources)
      .filter(([_, r]: [string, any]) => {
        const dir = r.direction ?? 'outbound';
        return r.type === 'service' && (dir === 'inbound' || dir === 'both');
      })
      .map(([name, r]: [string, any]) => ({
        name: r.id ?? name,
        namespace: r.namespace,
      })),

    secrets: Object.entries(resources)
      .filter(([_, r]: [string, any]) => r.type === 'secret')
      .map(([name, r]: [string, any]) => ({
        name,
        provider: r.params?.provider ?? 'unknown',
        keys: r.params?.keys,
      })),

    gpus: Object.entries(resources)
      .filter(([_, r]: [string, any]) => r.type === 'gpu')
      .map(([name, r]: [string, any]) => ({
        name,
        count: r.params?.count ?? 0,
        model: r.params?.model,
      })),
  };
}

/** Hook to list all LatticeServices across namespaces */
export function useLatticeServiceList() {
  const [services, setServices] = useState<any[] | null>(null);
  const [error, setError] = useState<any>(null);
  const hashRef = useRef<string>('');

  useEffect(() => {
    let cancelled = false;

    async function doFetch() {
      try {
        const response = await ApiProxy.request(`${API_BASE}/latticeservices`);
        if (cancelled) return;
        const items = (response as any).items ?? [];
        const processed = items.map(extractHelpers);
        // Only update state if data actually changed
        const hash = stableHash(processed);
        if (hash !== hashRef.current) {
          hashRef.current = hash;
          setServices(processed);
        }
      } catch (err) {
        if (!cancelled) setError(err);
      }
    }

    doFetch();
    const interval = setInterval(doFetch, 5000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return [services, error] as const;
}

/** Hook to get a single LatticeService */
export function useLatticeServiceGet(namespace: string, name: string) {
  const [service, setService] = useState<any | null>(null);
  const [error, setError] = useState<any>(null);
  const hashRef = useRef<string>('');

  useEffect(() => {
    let cancelled = false;

    async function doFetch() {
      try {
        const response = await ApiProxy.request(
          `${API_BASE}/namespaces/${namespace}/latticeservices/${name}`
        );
        if (cancelled) return;
        const processed = extractHelpers(response as any);
        const hash = stableHash(processed);
        if (hash !== hashRef.current) {
          hashRef.current = hash;
          setService(processed);
        }
      } catch (err) {
        if (!cancelled) setError(err);
      }
    }

    doFetch();
    const interval = setInterval(doFetch, 5000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [namespace, name]);

  return [service, error] as const;
}

/** Quick stable hash of JSON-serializable data for change detection */
function stableHash(obj: any): string {
  const str = JSON.stringify(obj);
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h + str.charCodeAt(i)) | 0;
  }
  return String(h);
}
