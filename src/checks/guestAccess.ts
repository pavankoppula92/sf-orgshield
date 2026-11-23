import { Finding, SecurityCheck } from './types.js';

interface ObjPermRow extends Record<string, unknown> {
  SobjectType: string;
  Parent?: { Profile?: { Name?: string } | null };
  PermissionsEdit: boolean;
  PermissionsDelete: boolean;
  PermissionsViewAllRecords: boolean;
  PermissionsModifyAllRecords: boolean;
}

export const guestAccessCheck: SecurityCheck = {
  id: 'guest-access',
  name: 'Guest user object access',
  description: 'Flags unauthenticated (guest) profiles with write, delete or view-all access to objects.',
  async run(q) {
    const rows = await q.query<ObjPermRow>(
      'SELECT SobjectType, Parent.Profile.Name, PermissionsEdit, PermissionsDelete, PermissionsViewAllRecords, PermissionsModifyAllRecords ' +
        "FROM ObjectPermissions WHERE Parent.Profile.UserType = 'Guest' " +
        'AND (PermissionsEdit = true OR PermissionsDelete = true OR PermissionsViewAllRecords = true OR PermissionsModifyAllRecords = true)'
    );
    const critical: string[] = [];
    const high: string[] = [];
    for (const r of rows) {
      const label = `${r.Parent?.Profile?.Name ?? 'Guest profile'} → ${r.SobjectType}`;
      if (r.PermissionsViewAllRecords || r.PermissionsModifyAllRecords) {
        const perms = [r.PermissionsViewAllRecords && 'View All', r.PermissionsModifyAllRecords && 'Modify All'].filter(Boolean);
        critical.push(`${label} (${perms.join(', ')})`);
      } else {
        const perms = [r.PermissionsEdit && 'Edit', r.PermissionsDelete && 'Delete'].filter(Boolean);
        high.push(`${label} (${perms.join(', ')})`);
      }
    }
    const findings: Finding[] = [];
    if (critical.length > 0) {
      findings.push({
        checkId: this.id,
        severity: 'critical',
        title: `Guest users can view or modify all records on ${critical.length} object(s)`,
        detail: 'Anyone on the internet who reaches the site can read or change every record of these objects.',
        recommendation: 'Remove View All / Modify All from guest profiles immediately and share records with guest sharing rules instead.',
        affected: critical.sort(),
      });
    }
    if (high.length > 0) {
      findings.push({
        checkId: this.id,
        severity: 'high',
        title: `Guest users have edit or delete access on ${high.length} object(s)`,
        detail: 'Unauthenticated users should rarely be able to change data.',
        recommendation: 'Limit guest profiles to Read and Create, and move writes behind authenticated users or server-side Apex with validation.',
        affected: high.sort(),
      });
    }
    return findings;
  },
};
