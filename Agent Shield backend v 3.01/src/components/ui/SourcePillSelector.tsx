import clsx from 'clsx'
import type { ScanSource } from '../../lib/types'

interface SourcePillSelectorProps {
  sources: ScanSource[]
  selectedIds: string[]
  onToggle: (sourceId: string) => void
  emptyMessage?: string
}

export const SourcePillSelector = ({
  sources,
  selectedIds,
  onToggle,
  emptyMessage = 'No sources available yet.',
}: SourcePillSelectorProps) => {
  const selectedSet = new Set(selectedIds)

  if (!sources.length) {
    return <p className="helper-text">{emptyMessage}</p>
  }

  return (
    <div className="source-pill-wrap">
      {sources.map((source) => {
        const isSelected = selectedSet.has(source.id)
        return (
          <button
            key={source.id}
            type="button"
            className={clsx('source-pill', isSelected && 'source-pill-selected')}
            onClick={() => onToggle(source.id)}
            aria-pressed={isSelected}
            title={source.url}
          >
            <span>{source.name}</span>
            <small>{source.vendor}</small>
          </button>
        )
      })}
    </div>
  )
}
