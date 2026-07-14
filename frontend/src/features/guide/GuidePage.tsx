import { useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { Card } from "@/components/Card";
import { PageHeader } from "@/components/PageHeader";
import { GLOSSARY_SECTIONS } from "@/lib/glossary";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";

export function GuidePage() {
  const location = useLocation();

  useEffect(() => {
    if (!location.hash) return;
    const target = document.querySelector(location.hash);
    target?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [location.hash]);

  return (
    <div className="page guide-page">
      <PageHeader
        eyebrow="Reference"
        title="Metric & data guide"
        subtitle={HELP_TEXT.guidePage}
        action={
          <Link to="/" className="view-all-link">
            ← Back to overview
          </Link>
        }
      />

      <section id="getting-started">
        <Card title="Getting started">
          <p className="guide-page__intro">
            Suggested path for a first visit — also available as a dismissible tip strip on Home
            (re-open anytime from <strong>Tips</strong> in the top bar).
          </p>
          <ol className="guide-start-list">
            <li>
              <Link to="/">Overview</Link> — posture bar for urgency, then optional AI brief on the same page.
            </li>
            <li>
              <Link to="/cves">{NAV_LABELS.issues}</Link> — open a CVE for scores, assets, and remediations.
            </li>
            <li>
              <Link to="/solutions">{NAV_LABELS.fixes}</Link> — track what you are fixing.
            </li>
            <li>
              Use the floating <strong>Analyze</strong> button only when you want a deeper write-up on selected
              CVEs (not required for daily triage).
            </li>
          </ol>
        </Card>
      </section>

      <Card title="Quick lookup">
        <p className="guide-page__intro">
          Jump to a topic below. Metrics on the home page link to their related screens; use this
          page when you need to know what KEV, EPSS, CVSS, or remediation statuses mean.
        </p>
        <nav className="guide-toc" aria-label="Guide sections">
          {GLOSSARY_SECTIONS.map((section) => (
            <div key={section.id} className="guide-toc__group">
              <a href={`#${section.id}`} className="guide-toc__section">
                {section.title}
              </a>
              <ul className="guide-toc__terms">
                {section.entries.map((entry) => (
                  <li key={entry.id}>
                    <a href={`#${entry.id}`}>{entry.term}</a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
      </Card>

      {GLOSSARY_SECTIONS.map((section) => (
        <section key={section.id} id={section.id} className="guide-section">
          <header className="guide-section__header">
            <h2 className="guide-section__title">{section.title}</h2>
            <p className="guide-section__desc">{section.description}</p>
          </header>

          <div className="guide-terms">
            {section.entries.map((entry) => (
              <article key={entry.id} id={entry.id} className="guide-term">
                <h3 className="guide-term__title">{entry.term}</h3>
                <p className="guide-term__summary">{entry.summary}</p>
                <p className="guide-term__detail">{entry.detail}</p>
              </article>
            ))}
          </div>
        </section>
      ))}

      <Card title="Related pages">
        <ul className="guide-related">
          <li>
            <Link to="/">Overview</Link> — posture, optional AI brief, severity, and priority queue
          </li>
          <li>
            <Link to="/cves">{NAV_LABELS.issues}</Link> — filter by KEV, EPSS, and severity
          </li>
          <li>
            <Link to="/solutions">{NAV_LABELS.fixes}</Link> — update remediation status
          </li>
          <li>
            <Link to="/analytics">{NAV_LABELS.analytics}</Link> — geography, ports, and scan breakdowns
          </li>
          <li>
            <Link to="/settings">{NAV_LABELS.settings}</Link> — data source and status labels
          </li>
        </ul>
      </Card>
    </div>
  );
}
