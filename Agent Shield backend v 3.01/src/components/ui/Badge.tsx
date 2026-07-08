import clsx from 'clsx'
import type { PropsWithChildren } from 'react'

interface BadgeProps {
  tone?: 'default' | 'success' | 'warning' | 'danger' | 'info'
}

export const Badge = ({ tone = 'default', children }: PropsWithChildren<BadgeProps>) => (
  <span className={clsx('badge', `badge-${tone}`)}>{children}</span>
)
