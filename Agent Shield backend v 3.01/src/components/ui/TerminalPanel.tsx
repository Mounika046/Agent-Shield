import clsx from 'clsx'
import type { TerminalLogLine } from '../../lib/types'

interface TerminalPanelProps {
  logs: TerminalLogLine[]
  compact?: boolean
}

export const TerminalPanel = ({ logs, compact = false }: TerminalPanelProps) => (
  <div className={clsx('terminal', compact && 'terminal-compact')}>
    <div className="terminal-head">
      <span className="dot dot-red" />
      <span className="dot dot-yellow" />
      <span className="dot dot-green" />
      <p>Scan Execution Log</p>
    </div>
    <div className="terminal-body">
      {logs.length === 0 && <p className="terminal-empty">No log events yet.</p>}
      {logs.map((log) => (
        <p key={log.id} className={clsx('terminal-line', `log-${log.level}`)}>
          <span>[{new Date(log.timestamp).toLocaleTimeString()}]</span> {log.message}
        </p>
      ))}
    </div>
  </div>
)
