import clsx from 'clsx'
import type { HTMLAttributes, PropsWithChildren } from 'react'

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  title?: string
  subtitle?: string
}

export const Card = ({ title, subtitle, className, children, ...props }: PropsWithChildren<CardProps>) => (
  <section className={clsx('card', className)} {...props}>
    {(title || subtitle) && (
      <header className="card-header">
        {title && <h3>{title}</h3>}
        {subtitle && <p>{subtitle}</p>}
      </header>
    )}
    {children}
  </section>
)
