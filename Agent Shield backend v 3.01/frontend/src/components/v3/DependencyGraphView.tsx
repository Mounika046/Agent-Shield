import { useEffect, useMemo, useRef, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import type { DependencyGraphEntry } from './chatTypes.js';
import styles from './ChatPage.module.css';

type DependencyGraphViewProps = {
  graph: DependencyGraphEntry;
};

type GraphNode = {
  id: string;
  label: string;
  version: string;
  group: 'root' | 'dep';
};

type GraphLink = {
  source: string;
  target: string;
};

const ROOT_NODE_COLOR = '#14b8a6';
const DEP_NODE_COLOR = '#64748b';

export function DependencyGraphView({ graph }: DependencyGraphViewProps) {
  const graphRef = useRef<any>(null);
  const shellRef = useRef<HTMLDivElement | null>(null);
  const [width, setWidth] = useState(880);

  const graphData = useMemo(() => {
    const rootId = `${graph.package}@${graph.version}`;
    const nodes: GraphNode[] = [
      {
        id: rootId,
        label: graph.package,
        version: graph.version,
        group: 'root',
      },
    ];
    const links: GraphLink[] = [];

    for (const dependency of graph.dependencies.slice(0, 10)) {
      const dependencyId = `${dependency.name}@${dependency.version || 'unknown'}`;
      nodes.push({
        id: dependencyId,
        label: dependency.name,
        version: dependency.version || 'unknown',
        group: 'dep',
      });
      links.push({ source: rootId, target: dependencyId });
    }

    return { nodes, links };
  }, [graph]);

  useEffect(() => {
    const element = shellRef.current;
    if (!element || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      setWidth(Math.max(320, Math.floor(entry.contentRect.width)));
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const instance = graphRef.current;
    if (!instance) return;
    const timer = window.setTimeout(() => {
      try {
        instance.zoomToFit(400, 135);
      } catch {
        // ignore initial layout timing issues from the graph library
      }
    }, 300);
    return () => window.clearTimeout(timer);
  }, [graphData]);

  return (
    <div ref={shellRef} className={styles.forceGraphShell}>
      <ForceGraph2D
        ref={graphRef}
        graphData={graphData}
        width={width}
        height={420}
        backgroundColor="rgba(255,255,255,0)"
        cooldownTicks={120}
        nodeLabel={(node: GraphNode) => `${node.label}@${node.version}`}
        nodeAutoColorBy="group"
        linkColor={() => 'rgba(100, 116, 139, 0.45)'}
        linkWidth={1.6}
        linkDirectionalArrowLength={4}
        linkDirectionalArrowRelPos={1}
        d3AlphaDecay={0.045}
        d3VelocityDecay={0.28}
        nodeCanvasObject={(node: GraphNode, ctx, globalScale) => {
          const radius = node.group === 'root' ? 10 : 6;
          const fontSize = node.group === 'root' ? 13 / globalScale : 11 / globalScale;
          const color = node.group === 'root' ? ROOT_NODE_COLOR : DEP_NODE_COLOR;

          ctx.beginPath();
          ctx.arc(node.x ?? 0, node.y ?? 0, radius, 0, 2 * Math.PI, false);
          ctx.fillStyle = color;
          ctx.fill();

          ctx.font = `600 ${fontSize}px Inter, system-ui, sans-serif`;
          ctx.fillStyle = '#0f172a';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'top';
          ctx.fillText(node.label, node.x ?? 0, (node.y ?? 0) + radius + 4 / globalScale);
        }}
      />
    </div>
  );
}
