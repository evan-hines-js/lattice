import { useMemo, useRef, useEffect, useState, useCallback, type MouseEvent } from 'react';
import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';

const { SectionBox } = CommonComponents;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface MeshNode {
  id: string;
  name: string;
  namespace: string;
  phase: string;
  edgeCount: number;
  x: number;
  y: number;
  vx: number;
  vy: number;
  pinned: boolean;
}

interface MeshEdge {
  from: string;
  to: string;
  bilateral: boolean;
}

type FilterMode = 'all' | 'problems' | 'namespace';

interface MeshGraphProps {
  services: any[];
  focusService?: string;
  onNodeClick?: (namespace: string, name: string) => void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PHASE_COLORS: Record<string, string> = {
  Ready: '#4caf50',
  Pending: '#ff9800',
  Compiling: '#2196f3',
  Failed: '#f44336',
};

const MIN_RADIUS = 18;
const MAX_RADIUS = 36;
const FOCUS_RADIUS = 28; // focused node is always prominent
const WIDTH = 1100;
const HEIGHT = 700;

// Force simulation
const REPULSION = 0.6;       // multiplier on repulsive force
const ATTRACTION = 0.08;     // multiplier on spring force (weaker = more spread)
const CENTER_GRAVITY = 0.003; // pull toward center
const DAMPING = 0.55;        // velocity damping per tick (lower = settles faster)
const MIN_VELOCITY = 0.05;

// ---------------------------------------------------------------------------
// Graph building (no layout — just topology)
// ---------------------------------------------------------------------------

function buildTopology(
  services: any[],
  focusService?: string,
  filterMode: FilterMode = 'all',
  filterNs?: string,
) {
  if (!services || services.length === 0) return { nodes: [] as MeshNode[], edges: [] as MeshEdge[] };

  const svcMap = new Map<string, any>();
  for (const svc of services) {
    svcMap.set(`${svc.metadata.namespace}/${svc.metadata.name}`, svc);
  }

  // Build all edges
  const allEdges: MeshEdge[] = [];
  const edgeDedup = new Set<string>();

  for (const svc of services) {
    const fromKey = `${svc.metadata.namespace}/${svc.metadata.name}`;
    for (const dep of svc.outboundDeps ?? []) {
      const toNs = dep.namespace ?? svc.metadata.namespace;
      const toKey = `${toNs}/${dep.name}`;
      if (!svcMap.has(toKey)) continue;

      const dedupKey = [fromKey, toKey].sort().join('::');
      if (edgeDedup.has(dedupKey)) {
        const existing = allEdges.find(
          (e) => [e.from, e.to].sort().join('::') === dedupKey,
        );
        if (existing) existing.bilateral = true;
        continue;
      }
      edgeDedup.add(dedupKey);

      const target = svcMap.get(toKey);
      const isBilateral = (target?.inboundDeps ?? []).some((d: any) => {
        const dNs = d.namespace ?? target.metadata.namespace;
        return `${dNs}/${d.name}` === fromKey;
      });

      allEdges.push({ from: fromKey, to: toKey, bilateral: isBilateral });
    }
  }

  // Count edges per node
  const edgeCounts = new Map<string, number>();
  for (const e of allEdges) {
    edgeCounts.set(e.from, (edgeCounts.get(e.from) ?? 0) + 1);
    edgeCounts.set(e.to, (edgeCounts.get(e.to) ?? 0) + 1);
  }

  // Determine included nodes
  let includedIds = new Set<string>();

  if (focusService) {
    includedIds.add(focusService);
    for (const e of allEdges) {
      if (e.from === focusService || e.to === focusService) {
        includedIds.add(e.from);
        includedIds.add(e.to);
      }
    }
  } else {
    for (const svc of services) {
      const key = `${svc.metadata.namespace}/${svc.metadata.name}`;
      if ((edgeCounts.get(key) ?? 0) > 0) includedIds.add(key);
    }
  }

  if (filterMode === 'problems') {
    const problemNodes = new Set<string>();
    for (const e of allEdges) {
      if (!e.bilateral) {
        problemNodes.add(e.from);
        problemNodes.add(e.to);
      }
    }
    for (const svc of services) {
      if (svc.phase === 'Failed') {
        problemNodes.add(`${svc.metadata.namespace}/${svc.metadata.name}`);
      }
    }
    includedIds = new Set([...includedIds].filter((id) => problemNodes.has(id)));
  } else if (filterMode === 'namespace' && filterNs) {
    includedIds = new Set(
      [...includedIds].filter((id) => id.startsWith(filterNs + '/')),
    );
  }

  // Build node list with circular initial positions
  const nodeList: MeshNode[] = [];
  const ids = Array.from(includedIds);
  for (let i = 0; i < ids.length; i++) {
    const id = ids[i];
    const svc = svcMap.get(id);
    if (!svc) continue;
    const angle = (2 * Math.PI * i) / ids.length - Math.PI / 2;
    const rx = WIDTH * 0.3;
    const ry = HEIGHT * 0.3;
    nodeList.push({
      id,
      name: svc.metadata.name,
      namespace: svc.metadata.namespace,
      phase: svc.phase,
      edgeCount: edgeCounts.get(id) ?? 0,
      x: WIDTH / 2 + rx * Math.cos(angle),
      y: HEIGHT / 2 + ry * Math.sin(angle),
      vx: 0,
      vy: 0,
      pinned: false,
    });
  }

  const edges = allEdges.filter(
    (e) => includedIds.has(e.from) && includedIds.has(e.to),
  );

  return { nodes: nodeList, edges };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function nodeRadius(edgeCount: number, maxEdges: number): number {
  if (maxEdges <= 1) return MIN_RADIUS;
  const t = edgeCount / maxEdges;
  return MIN_RADIUS + t * (MAX_RADIUS - MIN_RADIUS);
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function MeshGraph({
  services,
  focusService,
  onNodeClick,
}: MeshGraphProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const nodesRef = useRef<MeshNode[]>([]);
  const edgesRef = useRef<MeshEdge[]>([]);
  const maxEdgesRef = useRef(1);
  const animRef = useRef<number>(0);
  const dragRef = useRef<{ nodeId: string; offsetX: number; offsetY: number; dragged: boolean } | null>(null);
  const settledRef = useRef(false);
  const needsDrawRef = useRef(false);

  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const hoveredRef = useRef<string | null>(null);
  const [filterMode, setFilterMode] = useState<FilterMode>('all');
  const [filterNs, setFilterNs] = useState<string | undefined>();
  const [stats, setStats] = useState({ total: 0, edges: 0, unilateral: 0, failed: 0 });

  const namespaces = useMemo(() => {
    if (!services) return [];
    const ns = new Set(services.map((s: any) => s.metadata.namespace as string));
    return Array.from(ns).sort();
  }, [services]);

  // Wake the simulation (called on drag, topology change)
  const wakeSimulation = useCallback(() => {
    settledRef.current = false;
    if (animRef.current === 0) {
      animRef.current = requestAnimationFrame(tick);
    }
  }, []);

  // Redraw without simulating (called on hover change)
  const requestDraw = useCallback(() => {
    needsDrawRef.current = true;
    if (animRef.current === 0) {
      animRef.current = requestAnimationFrame(drawOnly);
    }
  }, []);

  function drawOnly() {
    animRef.current = 0;
    needsDrawRef.current = false;
    draw(nodesRef.current, edgesRef.current, maxEdgesRef.current);
  }

  // Rebuild topology when data/filters change
  useEffect(() => {
    const { nodes, edges } = buildTopology(services, focusService, filterMode, filterNs);
    nodesRef.current = nodes;
    edgesRef.current = edges;
    maxEdgesRef.current = Math.max(1, ...nodes.map((n) => n.edgeCount));

    setStats({
      total: nodes.length,
      edges: edges.length,
      unilateral: edges.filter((e) => !e.bilateral).length,
      failed: nodes.filter((n) => n.phase === 'Failed').length,
    });

    settledRef.current = false;
    animRef.current = requestAnimationFrame(tick);
  }, [services, focusService, filterMode, filterNs]);

  // Simulation tick
  function tick() {
    animRef.current = 0;

    const nodes = nodesRef.current;
    const edges = edgesRef.current;
    const maxE = maxEdgesRef.current;
    let totalMovement = 0;

    if (nodes.length > 1 && !settledRef.current) {
      const idealDist = Math.min(WIDTH, HEIGHT) / Math.sqrt(nodes.length + 1);
      const nodeMap = new Map(nodes.map((n) => [n.id, n]));

      // Repulsion
      for (let i = 0; i < nodes.length; i++) {
        if (nodes[i].pinned) continue;
        let fx = 0;
        let fy = 0;
        for (let j = 0; j < nodes.length; j++) {
          if (i === j) continue;
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
          const force = REPULSION * (idealDist * idealDist) / dist;
          fx += (dx / dist) * force;
          fy += (dy / dist) * force;
        }

        // Center gravity
        fx += (WIDTH / 2 - nodes[i].x) * CENTER_GRAVITY * idealDist;
        fy += (HEIGHT / 2 - nodes[i].y) * CENTER_GRAVITY * idealDist;

        nodes[i].vx += fx;
        nodes[i].vy += fy;
      }

      // Attraction along edges
      for (const edge of edges) {
        const a = nodeMap.get(edge.from);
        const b = nodeMap.get(edge.to);
        if (!a || !b) continue;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const force = ATTRACTION * (dist - idealDist) / dist;
        const fx = dx * force;
        const fy = dy * force;
        if (!a.pinned) { a.vx += fx; a.vy += fy; }
        if (!b.pinned) { b.vx -= fx; b.vy -= fy; }
      }

      // Apply velocity
      const pad = MAX_RADIUS + 40;
      for (const node of nodes) {
        if (node.pinned) { node.vx = 0; node.vy = 0; continue; }
        node.vx *= DAMPING;
        node.vy *= DAMPING;
        if (Math.abs(node.vx) < MIN_VELOCITY) node.vx = 0;
        if (Math.abs(node.vy) < MIN_VELOCITY) node.vy = 0;
        node.x += node.vx;
        node.y += node.vy;
        node.x = Math.max(pad, Math.min(WIDTH - pad, node.x));
        node.y = Math.max(pad, Math.min(HEIGHT - pad, node.y));
        totalMovement += Math.abs(node.vx) + Math.abs(node.vy);
      }

      // Check if settled
      if (totalMovement < MIN_VELOCITY * nodes.length) {
        settledRef.current = true;
      }
    }

    draw(nodes, edges, maxE);

    // Keep ticking only if not settled
    if (!settledRef.current) {
      animRef.current = requestAnimationFrame(tick);
    }
  }

  // Cleanup animation on unmount
  useEffect(() => {
    return () => {
      if (animRef.current) cancelAnimationFrame(animRef.current);
    };
  }, []);

  // Draw function
  const draw = useCallback(
    (nodes: MeshNode[], edges: MeshEdge[], maxE: number) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const dpr = window.devicePixelRatio || 1;
      canvas.width = WIDTH * dpr;
      canvas.height = HEIGHT * dpr;
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, WIDTH, HEIGHT);

      const nodeMap = new Map(nodes.map((n) => [n.id, n]));
      const activeId = hoveredRef.current;
      const highlighted = new Set<string>();
      if (activeId) {
        highlighted.add(activeId);
        for (const edge of edges) {
          if (edge.from === activeId || edge.to === activeId) {
            highlighted.add(edge.from);
            highlighted.add(edge.to);
          }
        }
      }

      // Edges
      for (const edge of edges) {
        const from = nodeMap.get(edge.from);
        const to = nodeMap.get(edge.to);
        if (!from || !to) continue;

        const dimmed =
          activeId && !highlighted.has(edge.from) && !highlighted.has(edge.to);

        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);

        if (edge.bilateral) {
          ctx.strokeStyle = dimmed ? 'rgba(76, 175, 80, 0.12)' : '#4caf50';
          ctx.setLineDash([]);
          ctx.lineWidth = 1.5;
        } else {
          ctx.strokeStyle = dimmed ? 'rgba(255, 152, 0, 0.12)' : '#ff9800';
          ctx.setLineDash([6, 4]);
          ctx.lineWidth = 2.5;
        }
        ctx.stroke();
        ctx.setLineDash([]);

        // Arrow
        const toFocus = focusService && to.id === focusService;
        const r = toFocus ? FOCUS_RADIUS : nodeRadius(to.edgeCount, maxE);
        const angle = Math.atan2(to.y - from.y, to.x - from.x);
        const ax = to.x - r * Math.cos(angle);
        const ay = to.y - r * Math.sin(angle);
        const sz = 8;

        ctx.beginPath();
        ctx.moveTo(ax, ay);
        ctx.lineTo(ax - sz * Math.cos(angle - 0.4), ay - sz * Math.sin(angle - 0.4));
        ctx.lineTo(ax - sz * Math.cos(angle + 0.4), ay - sz * Math.sin(angle + 0.4));
        ctx.closePath();
        ctx.fillStyle = edge.bilateral
          ? dimmed ? 'rgba(76, 175, 80, 0.12)' : '#4caf50'
          : dimmed ? 'rgba(255, 152, 0, 0.12)' : '#ff9800';
        ctx.fill();
      }

      // Nodes
      for (const node of nodes) {
        const dimmed = activeId && !highlighted.has(node.id);
        const isActive = node.id === activeId;
        const isFocus = node.id === focusService;
        const color = PHASE_COLORS[node.phase] ?? '#9e9e9e';
        const r = isFocus ? FOCUS_RADIUS : nodeRadius(node.edgeCount, maxE);

        // Glow for focused node
        if (isFocus) {
          ctx.shadowColor = color;
          ctx.shadowBlur = 16;
        }

        ctx.beginPath();
        ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
        ctx.fillStyle = dimmed ? `${color}22` : isFocus ? color : `${color}cc`;
        ctx.fill();

        ctx.shadowColor = 'transparent';
        ctx.shadowBlur = 0;

        // Ring
        if (isFocus) {
          ctx.strokeStyle = '#fff';
          ctx.lineWidth = 3;
          ctx.stroke();
        } else if (isActive) {
          ctx.strokeStyle = color;
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        // Label
        ctx.textAlign = 'center';
        if (isFocus) {
          // Name inside the node
          ctx.fillStyle = '#fff';
          ctx.font = 'bold 11px sans-serif';
          ctx.fillText(node.name, node.x, node.y + 4);
        } else {
          ctx.fillStyle = dimmed ? '#555' : '#e0e0e0';
          ctx.font = `${r > 22 ? 12 : 10}px sans-serif`;
          ctx.fillText(node.name, node.x, node.y + r + 15);
          if (node.namespace !== 'default') {
            ctx.fillStyle = dimmed ? '#444' : '#888';
            ctx.font = '9px sans-serif';
            ctx.fillText(node.namespace, node.x, node.y + r + 27);
          }
        }
      }

      // Legend
      const ly = HEIGHT - 16;
      ctx.font = '10px sans-serif';
      ctx.textAlign = 'left';

      ctx.fillStyle = '#4caf50';
      ctx.fillRect(8, ly - 4, 14, 2);
      ctx.fillStyle = '#888';
      ctx.fillText('bilateral', 26, ly);

      ctx.strokeStyle = '#ff9800';
      ctx.setLineDash([4, 3]);
      ctx.beginPath();
      ctx.moveTo(90, ly - 3);
      ctx.lineTo(104, ly - 3);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = '#888';
      ctx.fillText('unilateral', 108, ly);

      ctx.fillStyle = '#666';
      ctx.fillText('drag to rearrange', WIDTH - 130, ly);
    },
    [focusService],
  );

  // Hit testing
  const findHit = useCallback(
    (clientX: number, clientY: number) => {
      const canvas = canvasRef.current;
      if (!canvas) return null;
      const rect = canvas.getBoundingClientRect();
      const x = clientX - rect.left;
      const y = clientY - rect.top;
      const maxE = maxEdgesRef.current;
      return nodesRef.current.find((n) => {
        const r = nodeRadius(n.edgeCount, maxE);
        return Math.sqrt((n.x - x) ** 2 + (n.y - y) ** 2) <= r;
      }) ?? null;
    },
    [],
  );

  // Mouse handlers
  const handleMouseDown = useCallback(
    (e: MouseEvent<HTMLCanvasElement>) => {
      const hit = findHit(e.clientX, e.clientY);
      if (!hit) return;
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      dragRef.current = {
        nodeId: hit.id,
        offsetX: e.clientX - rect.left - hit.x,
        offsetY: e.clientY - rect.top - hit.y,
        dragged: false,
      };
    },
    [findHit],
  );

  const handleMouseMove = useCallback(
    (e: MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();

      // Dragging
      if (dragRef.current) {
        dragRef.current.dragged = true;
        const node = nodesRef.current.find((n) => n.id === dragRef.current!.nodeId);
        if (node) {
          node.pinned = true;
          const pad = MAX_RADIUS + 40;
          node.x = Math.max(pad, Math.min(WIDTH - pad, e.clientX - rect.left - dragRef.current.offsetX));
          node.y = Math.max(pad, Math.min(HEIGHT - pad, e.clientY - rect.top - dragRef.current.offsetY));
          node.vx = 0;
          node.vy = 0;
        }
        wakeSimulation();
        canvas.style.cursor = 'grabbing';
        return;
      }

      // Hover — just redraw, don't restart simulation
      const hit = findHit(e.clientX, e.clientY);
      const newId = hit?.id ?? null;
      if (newId !== hoveredRef.current) {
        hoveredRef.current = newId;
        setHoveredNode(newId);
        requestDraw();
      }
      canvas.style.cursor = hit ? 'grab' : 'default';
    },
    [findHit, wakeSimulation, requestDraw],
  );

  const handleMouseUp = useCallback(() => {
    // If we clicked without dragging, unpin the node (toggle)
    if (dragRef.current && !dragRef.current.dragged) {
      const node = nodesRef.current.find((n) => n.id === dragRef.current!.nodeId);
      if (node && node.pinned) {
        node.pinned = false;
        wakeSimulation();
      }
    }
    dragRef.current = null;
  }, [wakeSimulation]);

  const handleDoubleClick = useCallback(
    (e: MouseEvent<HTMLCanvasElement>) => {
      const hit = findHit(e.clientX, e.clientY);
      if (hit) {
        hit.pinned = false;
        wakeSimulation();
      }
    },
    [findHit, wakeSimulation],
  );

  const handleClick = useCallback(
    (e: MouseEvent<HTMLCanvasElement>) => {
      if (!onNodeClick) return;
      // Don't navigate if we just finished dragging
      if (dragRef.current) return;
      const hit = findHit(e.clientX, e.clientY);
      if (hit) onNodeClick(hit.namespace, hit.name);
    },
    [findHit, onNodeClick],
  );

  if (
    !services ||
    services.length === 0 ||
    (stats.total === 0 && filterMode === 'all')
  ) {
    return (
      <SectionBox title="Mesh Dependencies">
        <p style={{ color: '#999', padding: 12 }}>
          No services with mesh dependencies
        </p>
      </SectionBox>
    );
  }

  return (
    <SectionBox title="Mesh Dependencies">
      {/* Toolbar */}
      {!focusService && (
        <div
          style={{
            display: 'flex',
            gap: 8,
            alignItems: 'center',
            marginBottom: 8,
            flexWrap: 'wrap',
            fontSize: 12,
          }}
        >
          <FilterButton
            active={filterMode === 'all'}
            onClick={() => setFilterMode('all')}
            label="All"
          />
          <FilterButton
            active={filterMode === 'problems'}
            onClick={() => setFilterMode('problems')}
            label={`Problems${stats.unilateral + stats.failed > 0 ? ` (${stats.unilateral + stats.failed})` : ''}`}
            alert={stats.unilateral + stats.failed > 0}
          />
          <select
            value={filterMode === 'namespace' ? filterNs ?? '' : ''}
            onChange={(e) => {
              if (e.target.value) {
                setFilterMode('namespace');
                setFilterNs(e.target.value);
              } else {
                setFilterMode('all');
                setFilterNs(undefined);
              }
            }}
            style={{
              padding: '3px 8px',
              border: `1px solid ${filterMode === 'namespace' ? '#90caf9' : '#555'}`,
              borderRadius: 4,
              background: filterMode === 'namespace' ? '#1e3a5f' : 'transparent',
              color: '#ccc',
              fontSize: 12,
            }}
          >
            <option value="">Namespace...</option>
            {namespaces.map((ns) => (
              <option key={ns} value={ns}>
                {ns}
              </option>
            ))}
          </select>

          <span style={{ marginLeft: 'auto', color: '#888' }}>
            {stats.total} services, {stats.edges} connections
            {stats.unilateral > 0 && (
              <span style={{ color: '#ff9800', marginLeft: 8 }}>
                {stats.unilateral} unilateral
              </span>
            )}
            {stats.failed > 0 && (
              <span style={{ color: '#f44336', marginLeft: 8 }}>
                {stats.failed} failed
              </span>
            )}
          </span>
        </div>
      )}

      {stats.total === 0 ? (
        <p style={{ color: '#999', padding: 12 }}>
          No services match this filter
        </p>
      ) : (
        <canvas
          ref={canvasRef}
          width={WIDTH}
          height={HEIGHT}
          style={{ width: WIDTH, height: HEIGHT, display: 'block' }}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={() => {
            dragRef.current = null;
            hoveredRef.current = null;
            setHoveredNode(null);
            requestDraw();
          }}
          onClick={handleClick}
          onDoubleClick={handleDoubleClick}
        />
      )}
    </SectionBox>
  );
}

// ---------------------------------------------------------------------------
// Filter button
// ---------------------------------------------------------------------------

function FilterButton({
  active,
  onClick,
  label,
  alert,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  alert?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '3px 10px',
        border: `1px solid ${active ? '#90caf9' : '#555'}`,
        borderRadius: 4,
        background: active ? '#1e3a5f' : 'transparent',
        color: alert && !active ? '#ff9800' : active ? '#90caf9' : '#ccc',
        cursor: 'pointer',
        fontSize: 12,
      }}
    >
      {label}
    </button>
  );
}
