import { Finding, SecurityCheck, Severity } from './types.js';

interface RiskyPermission {
  field: string;
  label: string;
  severity: Severity;
  why: string;
}

export const RISKY_PERMISSIONS: RiskyPermission[] = [
  {
    field: 'PermissionsModifyAllData',
    label: 'Modify All Data',
    severity: 'critical',
    why: 'can create, edit and delete every record in the org regardless of sharing',
  },
  {
    field: 'PermissionsViewAllData',
    label: 'View All Data',
    severity: 'high',
    why: 'can read and export every record in the org regardless of sharing',
  },
  {
    field: 'PermissionsUseAnyApiClient',
    label: 'Use Any API Client',
    severity: 'high',
    why: 'bypasses connected app API access restrictions, a common data exfiltration path',
  },
  {
    field: 'PermissionsManageUsers',
    label: 'Manage Users',
    severity: 'high',
    why: 'can create users, reset passwords and assign permissions, including to themselves',
  },
  {
    field: 'PermissionsAuthorApex',
    label: 'Author Apex',
    severity: 'medium',
    why: 'can deploy code that runs in system context',
  },
  {
    field: 'PermissionsCustomizeApplication',
    label: 'Customize Application',
    severity: 'medium',
    why: 'can change metadata, automation and security-relevant configuration',
  },
  {
    field: 'PermissionsPasswordNeverExpires',
    label: 'Password Never Expires',
    severity: 'medium',
    why: 'exempts users from password rotation policies',
  },
];

interface AssignmentRow extends Record<string, unknown> {
  AssigneeId: string;
  Assignee?: { Username?: string };
  PermissionSet?: { Label?: string; IsOwnedByProfile?: boolean; Profile?: { Name?: string } | null };
}

function sourceName(row: AssignmentRow): string {
  const ps = row.PermissionSet;
  if (!ps) return 'unknown';
  return ps.IsOwnedByProfile ? `Profile: ${ps.Profile?.Name ?? 'unknown'}` : `Permission Set: ${ps.Label ?? 'unknown'}`;
}

export const privilegedPermissionsCheck: SecurityCheck = {
  id: 'privileged-permissions',
  name: 'Privileged permission holders',
  description: 'Counts active users holding high-risk system permissions through profiles or permission sets.',
  async run(q, ctx) {
    const findings: Finding[] = [];
    for (const perm of RISKY_PERMISSIONS) {
      let rows: AssignmentRow[];
      try {
        rows = await q.query<AssignmentRow>(
          'SELECT AssigneeId, Assignee.Username, PermissionSet.Label, PermissionSet.IsOwnedByProfile, PermissionSet.Profile.Name ' +
            `FROM PermissionSetAssignment WHERE Assignee.IsActive = true AND PermissionSet.${perm.field} = true`
        );
      } catch {
        // Permission field not available in this org or API version; skip it.
        continue;
      }
      const users = new Map<string, string>();
      const sources = new Set<string>();
      for (const r of rows) {
        users.set(r.AssigneeId, r.Assignee?.Username ?? r.AssigneeId);
        sources.add(sourceName(r));
      }
      if (users.size === 0) continue;
      const overLimit = users.size > ctx.maxPrivilegedUsers;
      findings.push({
        checkId: this.id,
        severity: overLimit ? perm.severity : 'info',
        title: `${users.size} active user(s) hold "${perm.label}"`,
        detail:
          `Users with ${perm.label} ${perm.why}. Granted via: ${[...sources].sort().join('; ')}.` +
          (overLimit ? ` This exceeds the threshold of ${ctx.maxPrivilegedUsers}.` : ''),
        recommendation: overLimit
          ? `Remove ${perm.label} from profiles, grant it only through a small, reviewed permission set, and recertify holders quarterly.`
          : 'Holder count is within threshold. Keep recertifying holders periodically.',
        affected: [...users.values()].sort(),
      });
    }
    return findings;
  },
};
