import React, { useState } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Cpu,
  LayoutDashboard,
  LogOut,
  Menu,
  Settings,
  Shield,
  Upload,
  X,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext.tsx';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { to: '/monitoring', label: 'Threat Monitoring', icon: Activity },
  { to: '/analysis', label: 'Traffic Analysis', icon: BarChart3 },
  { to: '/model', label: 'Model Performance', icon: Cpu },
  { to: '/alerts', label: 'Alert Management', icon: AlertTriangle },
  { to: '/settings', label: 'Settings', icon: Settings },
];

function getBreadcrumb(pathname: string): string {
  if (pathname === '/') return 'Overview / Security Dashboard';
  if (pathname.startsWith('/monitoring/')) return 'Threat Monitoring / Event Inspection';
  if (pathname === '/monitoring') return 'Threat Monitoring / Network Events';
  if (pathname === '/analysis') return 'Traffic Analysis / CSV & Flow Inspection';
  if (pathname === '/model') return 'Model Performance / Random Forest Evaluation';
  if (pathname === '/alerts') return 'Alert Management / Incident Queue';
  if (pathname === '/settings') return 'Settings / Policy & Access Control';
  return 'NetShield AI';
}

export function Layout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const sidebarContent = (
    <div className="flex flex-col h-full bg-neutral-950 text-white">
      <div className="px-6 h-16 flex items-center justify-between border-b border-neutral-800">
        <div className="flex items-center gap-2.5 min-w-0">
          <Shield className="w-5 h-5 text-white shrink-0" strokeWidth={1.75} />
          <span className="font-semibold tracking-tight text-base whitespace-nowrap truncate">
            NetShield AI
          </span>
        </div>
        <button
          type="button"
          onClick={() => setMobileOpen(false)}
          className="lg:hidden p-1.5 text-neutral-400 hover:text-white cursor-pointer"
          aria-label="Close navigation menu"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      <nav className="flex-1 px-3 py-5 space-y-1 overflow-y-auto" aria-label="Primary">
        {NAV_ITEMS.map(({ to, label, icon: Icon, exact }) => (
          <NavLink
            key={to}
            to={to}
            end={exact}
            onClick={() => setMobileOpen(false)}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 text-sm font-medium transition-colors whitespace-nowrap ${
                isActive
                  ? 'bg-white text-neutral-950'
                  : 'text-neutral-400 hover:text-white hover:bg-neutral-900'
              }`
            }
          >
            <Icon className="w-4 h-4 shrink-0" strokeWidth={1.75} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-neutral-800">
        <div className="mb-3 px-2">
          <p className="text-sm font-medium text-white truncate">{user?.username}</p>
          <p className="text-xs text-neutral-400 truncate mt-0.5">
            {user?.role ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : 'Analyst'} · Detection-Only
          </p>
        </div>
        <button
          type="button"
          onClick={handleLogout}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium text-neutral-300 border border-neutral-800 hover:bg-neutral-900 hover:text-white transition-colors cursor-pointer whitespace-nowrap"
        >
          <LogOut className="w-3.5 h-3.5 shrink-0" />
          <span>Sign Out</span>
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-white text-neutral-950 flex">
      {/* Desktop Fixed Sidebar */}
      <aside className="hidden lg:block w-60 shrink-0 border-r border-neutral-200 sticky top-0 h-screen">
        {sidebarContent}
      </aside>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="w-64 h-full shrink-0">{sidebarContent}</div>
          <div
            className="flex-1 bg-black/50"
            onClick={() => setMobileOpen(false)}
            aria-hidden="true"
          />
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-16 px-4 sm:px-8 border-b border-neutral-200 bg-white sticky top-0 z-30 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              className="lg:hidden p-2 -ml-2 text-neutral-700 hover:text-neutral-950 cursor-pointer"
              aria-label="Open navigation menu"
            >
              <Menu className="w-5 h-5" />
            </button>
            <p className="text-sm font-medium text-neutral-600 truncate">
              {getBreadcrumb(location.pathname)}
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => navigate('/analysis')}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium bg-neutral-950 text-white hover:bg-neutral-800 transition-colors cursor-pointer whitespace-nowrap shrink-0"
            >
              <Upload className="w-3.5 h-3.5 shrink-0" />
              <span>Analyze Traffic</span>
            </button>
          </div>
        </header>

        <main className="flex-1 px-4 sm:px-8 py-8 max-w-[1440px] w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
