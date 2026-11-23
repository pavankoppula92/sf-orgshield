import { CheckResult, Finding, SEVERITY_ORDER, Severity } from '../checks/types.js';

export const PENALTY: Record<Severity, number> = {
  critical: 20,
  high: 10,
  medium: 5,
  low: 2,
  info: 0,
};

export interface Score {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  counts: Record<Severity, number>;
}

export function allFindings(results: CheckResult[]): Finding[] {
  return results
    .flatMap((r) => r.findings)
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

export function computeScore(results: CheckResult[]): Score {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let score = 100;
  for (const f of allFindings(results)) {
    counts[f.severity] += 1;
    score -= PENALTY[f.severity];
  }
  score = Math.max(0, score);
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
  return { score, grade, counts };
}
