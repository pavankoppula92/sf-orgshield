import { SecurityCheck } from './types.js';

interface UserRow extends Record<string, unknown> {
  Username: string;
  LastLoginDate: string | null;
}

export const dormantAdminsCheck: SecurityCheck = {
  id: 'dormant-admins',
  name: 'Dormant privileged users',
  description: 'Finds active users with Modify All Data or View All Data who have not logged in recently.',
  async run(q, ctx) {
    const rows = await q.query<UserRow>(
      'SELECT Username, LastLoginDate FROM User ' +
        `WHERE IsActive = true AND (LastLoginDate < LAST_N_DAYS:${ctx.staleDays} OR LastLoginDate = null) ` +
        'AND Id IN (SELECT AssigneeId FROM PermissionSetAssignment ' +
        'WHERE PermissionSet.PermissionsModifyAllData = true OR PermissionSet.PermissionsViewAllData = true)'
    );
    if (rows.length === 0) return [];
    return [
      {
        checkId: this.id,
        severity: 'high',
        title: `${rows.length} privileged user(s) inactive for ${ctx.staleDays}+ days`,
        detail:
          'Dormant accounts with org-wide data access are a prime takeover target because nobody notices when they are used.',
        recommendation: 'Deactivate or freeze these users, or remove their privileged access until it is needed again.',
        affected: rows.map((r) => `${r.Username} (last login: ${r.LastLoginDate ?? 'never'})`).sort(),
      },
    ];
  },
};
