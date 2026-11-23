import { CheckResult, Severity } from '../checks/types.js';
import { allFindings, computeScore } from './score.js';

export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const COLORS: Record<Severity, string> = {
  critical: '#b42318',
  high: '#d9480f',
  medium: '#b08800',
  low: '#2f6fb3',
  info: '#6b7280',
};

export function renderHtml(results: CheckResult[], orgLabel: string, generatedAt: Date = new Date()): string {
  const { score, grade, counts } = computeScore(results);
  const findings = allFindings(results);

  const findingHtml = findings
    .map(
      (f) => `
    <article class="finding">
      <div class="sev" style="background:${COLORS[f.severity]}">${f.severity.toUpperCase()}</div>
      <h3>${escapeHtml(f.title)}</h3>
      <p>${escapeHtml(f.detail)}</p>
      <p><strong>Fix:</strong> ${escapeHtml(f.recommendation)}</p>
      ${
        f.affected && f.affected.length > 0
          ? `<details><summary>${f.affected.length} affected</summary><ul>${f.affected
              .map((a) => `<li>${escapeHtml(a)}</li>`)
              .join('')}</ul></details>`
          : ''
      }
    </article>`
    )
    .join('');

  const checkRows = results
    .map(
      (r) =>
        `<tr><td>${escapeHtml(r.name)}</td><td class="${r.status}">${r.status}</td><td>${
          r.skippedReason ? escapeHtml(r.skippedReason) : r.findings.length
        }</td></tr>`
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>OrgShield report: ${escapeHtml(orgLabel)}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1f2937; }
  .score { display: flex; gap: 2rem; align-items: center; padding: 1.5rem; border: 1px solid #e5e7eb; border-radius: 12px; }
  .grade { font-size: 4rem; font-weight: 700; }
  .finding { border: 1px solid #e5e7eb; border-radius: 10px; padding: 1rem 1.25rem; margin: 1rem 0; }
  .sev { display: inline-block; color: #fff; font-size: .75rem; font-weight: 700; padding: .15rem .5rem; border-radius: 4px; }
  table { border-collapse: collapse; width: 100%; } td, th { border-bottom: 1px solid #e5e7eb; padding: .5rem; text-align: left; }
  .failed { color: #b42318; } .passed { color: #067647; } .skipped { color: #6b7280; }
</style>
</head>
<body>
  <h1>OrgShield security report</h1>
  <p>Org: <strong>${escapeHtml(orgLabel)}</strong> · Generated ${generatedAt.toISOString()}</p>
  <section class="score">
    <div class="grade">${grade}</div>
    <div>
      <div><strong>Score:</strong> ${score}/100</div>
      <div>Critical ${counts.critical} · High ${counts.high} · Medium ${counts.medium} · Low ${counts.low} · Info ${counts.info}</div>
    </div>
  </section>
  <h2>Checks</h2>
  <table><thead><tr><th>Check</th><th>Status</th><th>Findings</th></tr></thead><tbody>${checkRows}</tbody></table>
  <h2>Findings</h2>
  ${findingHtml || '<p>No findings. Nice work.</p>'}
</body>
</html>`;
}
