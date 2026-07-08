import type { PropsWithChildren } from 'react'

export const Table = ({ children }: PropsWithChildren) => (
  <div className="table-wrap">
    <table className="table">{children}</table>
  </div>
)
