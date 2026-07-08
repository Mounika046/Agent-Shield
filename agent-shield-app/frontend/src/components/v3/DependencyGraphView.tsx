import { useMemo } from 'react';
import type { DependencyGraphEntry } from './chatTypes.js';
import styles from './ChatPage.module.css';

type DependencyGraphViewProps = {
  graph: DependencyGraphEntry;
};

type PositionedDependency = {
  name: string;
  version: string;
  x: number;
  y: number;
};

export function DependencyGraphView({ graph }: DependencyGraphViewProps) {
  const dependencies = useMemo<PositionedDependency[]>(() => {
    const items = graph.dependencies.slice(0, 10);
    const radiusX = 330;
    const radiusY = 145;
    return items.map((dependency, index) => {
      const angle = (Math.PI * 2 * index) / Math.max(items.length, 1) - Math.PI / 2;
      return {
        ...dependency,
        version: dependency.version || 'unknown',
        x: 450 + Math.cos(angle) * radiusX,
        y: 210 + Math.sin(angle) * radiusY,
      };
    });
  }, [graph]);

  return (
    <div className={styles.forceGraphShell}>
      <svg
        className={styles.dependencyGraphSvg}
        viewBox="0 0 900 420"
        role="img"
        aria-label={`Direct dependency graph for ${graph.package} ${graph.version}`}
      >
        <g className={styles.graphLinks}>
          {dependencies.map((dependency) => (
            <line key={`${dependency.name}-${dependency.version}`} x1="450" y1="210" x2={dependency.x} y2={dependency.y} />
          ))}
        </g>

        {dependencies.map((dependency) => (
          <g key={`${dependency.name}-${dependency.version}`} className={styles.graphNode} transform={`translate(${dependency.x} ${dependency.y})`}>
            <title>{dependency.name}@{dependency.version}</title>
            <circle r="9" />
            <text y="22" textAnchor="middle">{dependency.name}</text>
            <text y="36" textAnchor="middle" className={styles.graphNodeVersion}>{dependency.version}</text>
          </g>
        ))}

        <g className={`${styles.graphNode} ${styles.graphRootNode}`} transform="translate(450 210)">
          <title>{graph.package}@{graph.version}</title>
          <circle r="15" />
          <text y="28" textAnchor="middle">{graph.package}</text>
          <text y="43" textAnchor="middle" className={styles.graphNodeVersion}>{graph.version}</text>
        </g>
      </svg>
    </div>
  );
}
