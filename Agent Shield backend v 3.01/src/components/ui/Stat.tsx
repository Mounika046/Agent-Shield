interface StatProps {
  label: string
  value: string | number
  hint?: string
}

export const Stat = ({ label, value, hint }: StatProps) => (
  <article className="stat">
    <p className="stat-label">{label}</p>
    <p className="stat-value">{value}</p>
    {hint && <p className="stat-hint">{hint}</p>}
  </article>
)
