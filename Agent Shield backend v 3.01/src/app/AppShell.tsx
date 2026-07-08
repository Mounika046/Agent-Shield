import { Activity, Bell, Layers, Radar, Search, ShieldAlert } from 'lucide-react'
import { Link, NavLink, Outlet } from 'react-router-dom'
import { buttonClass } from '../components/ui/Button'

const navSections = [
  {
    title: 'Security Tools',
    links: [
      { to: '/', label: 'Dashboard', icon: Activity },
      { to: '/asset-classes', label: 'Asset Classes', icon: Layers },
      { to: '/scan-center', label: 'Scan Center', icon: Radar },
      { to: '/runs', label: 'Run History', icon: ShieldAlert },
    ],
  },
]

export const AppShell = () => (
  <div className="app-shell">
    <aside className="sidebar">
      <div className="sidebar-brand">
        <span className="brand-icon">
          <ShieldAlert size={18} />
        </span>
        <div>
          <p>AgentShield</p>
          <small>CVE Command Center</small>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navSections.map((section) => (
          <div key={section.title} className="sidebar-section">
            <p className="sidebar-section-title">{section.title}</p>
            {section.links.map((link) => {
              const Icon = link.icon
              return (
                <NavLink
                  key={link.to}
                  to={link.to}
                  end={link.to === '/'}
                  className={({ isActive }) => (isActive ? 'sidebar-link active' : 'sidebar-link')}
                >
                  <Icon size={16} />
                  <span>{link.label}</span>
                </NavLink>
              )
            })}
          </div>
        ))}
      </nav>

      <div className="sidebar-profile">
        <span className="profile-avatar">A</span>
        <div>
          <p>Admin</p>
          <small>Security Team</small>
        </div>
      </div>
    </aside>

    <main className="content-pane">
      <header className="topbar">
        <label className="topbar-search">
          <Search size={16} />
          <input type="search" placeholder="Search assets, classes, runs..." />
        </label>
        <div className="topbar-actions">
          <button className="icon-btn" type="button" aria-label="Notifications">
            <Bell size={16} />
          </button>
          <Link className={buttonClass('primary', 'sm')} to="/scan-center">
            Start Scan
          </Link>
        </div>
      </header>
      <div className="content-body">
        <Outlet />
      </div>
    </main>
  </div>
)
