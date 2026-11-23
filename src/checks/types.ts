export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export interface Finding {
  checkId: string;
  severity: Severity;
  title: string;
  detail: string;
  recommendation: string;
  affected?: string[];
}

export interface CheckResult {
  checkId: string;
  name: string;
  status: 'passed' | 'failed' | 'skipped';
  findings: Finding[];
  skippedReason?: string;
}

/** Minimal query interface so checks can be unit-tested without a live org. */
export interface QueryRunner {
  query<T extends Record<string, unknown>>(soql: string): Promise<T[]>;
}

export interface CheckContext {
  /** Days without use/login before something counts as stale. */
  staleDays: number;
  /** How many holders of a privileged permission are acceptable before it is flagged. */
  maxPrivilegedUsers: number;
  /** Objects whose organization-wide defaults are reviewed. */
  sharingObjects: string[];
}

export interface SecurityCheck {
  id: string;
  name: string;
  description: string;
  run(q: QueryRunner, ctx: CheckContext): Promise<Finding[]>;
}

export const DEFAULT_CONTEXT: CheckContext = {
  staleDays: 90,
  maxPrivilegedUsers: 5,
  sharingObjects: ['Account', 'Contact', 'Opportunity', 'Case', 'Lead'],
};

export function severityAtLeast(s: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(s) <= SEVERITY_ORDER.indexOf(threshold);
}
