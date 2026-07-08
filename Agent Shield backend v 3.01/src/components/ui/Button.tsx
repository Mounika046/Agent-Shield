import clsx from 'clsx'
import type { ButtonHTMLAttributes } from 'react'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger'
type Size = 'sm' | 'md'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: Size
}

export const buttonClass = (variant: Variant = 'primary', size: Size = 'md', className?: string) =>
  clsx('btn', `btn-${variant}`, `btn-${size}`, className)

export const Button = ({ variant = 'primary', size = 'md', className, ...props }: ButtonProps) => (
  <button className={buttonClass(variant, size, className)} {...props} />
)
