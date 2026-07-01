import { Link } from 'react-router-dom';
import { NAV_LABELS } from '@/lib/copy';
import { useDashboard } from '@/context/DashboardContext';

export function DashboardNav() {
  const { derived } = useDashboard();

  const links = [
    { to: '/ips', label: NAV_LABELS.systems, count: derived.ips.length },
    { to: '/cves', label: NAV_LABELS.issues, count: derived.cves.length },
    { to: '/solutions', label: NAV_LABELS.fixes, count: derived.solutions.length },
    { to: '/vendors', label: NAV_LABELS.providers, count: derived.vendors.length },
  ] as const;

  return (
    <nav className="dashboard-footer-nav" aria-label="Explore dashboard sections">
      {links.map((link) => (
        <Link key={link.to} to={link.to} className="dashboard-footer-nav__item">
          <span className="dashboard-footer-nav__label">{link.label}</span>
          <span className="dashboard-footer-nav__count">{link.count}</span>
        </Link>
      ))}
    </nav>
  );
}
