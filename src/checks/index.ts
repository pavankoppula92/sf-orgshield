import { connectedAppsCheck } from './connectedApps.js';
import { dormantAdminsCheck } from './dormantAdmins.js';
import { guestAccessCheck } from './guestAccess.js';
import { privilegedPermissionsCheck } from './privilegedPermissions.js';
import { sharingDefaultsCheck } from './sharingDefaults.js';
import { CheckContext, CheckResult, QueryRunner, SecurityCheck } from './types.js';

export const ALL_CHECKS: SecurityCheck[] = [
  privilegedPermissionsCheck,
  dormantAdminsCheck,
  connectedAppsCheck,
  guestAccessCheck,
  sharingDefaultsCheck,
];

/** Runs every check; a check that errors is reported as skipped instead of failing the whole scan. */
export async function runChecks(q: QueryRunner, ctx: CheckContext, checks: SecurityCheck[] = ALL_CHECKS): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  for (const check of checks) {
    try {
      const findings = await check.run(q, ctx);
      const failed = findings.some((f) => f.severity !== 'info');
      results.push({ checkId: check.id, name: check.name, status: failed ? 'failed' : 'passed', findings });
    } catch (err) {
      results.push({
        checkId: check.id,
        name: check.name,
        status: 'skipped',
        findings: [],
        skippedReason: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return results;
}

export * from './types.js';
