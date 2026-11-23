import { Finding, SecurityCheck } from './types.js';

interface TokenRow extends Record<string, unknown> {
  AppName: string;
  LastUsedDate: string | null;
  User?: { Username?: string };
}

interface AppRow extends Record<string, unknown> {
  Name: string;
  OptionsAllowAdminApprovedUsersOnly: boolean;
}

export function isStale(lastUsed: string | null, staleDays: number, now: Date = new Date()): boolean {
  if (!lastUsed) return true;
  const ageMs = now.getTime() - new Date(lastUsed).getTime();
  return ageMs > staleDays * 24 * 60 * 60 * 1000;
}

export const connectedAppsCheck: SecurityCheck = {
  id: 'connected-apps',
  name: 'Connected app exposure',
  description: 'Reviews connected apps open to self-authorization and stale OAuth tokens.',
  async run(q, ctx) {
    const findings: Finding[] = [];

    let tokens: TokenRow[] = [];
    try {
      tokens = await q.query<TokenRow>('SELECT AppName, LastUsedDate, User.Username FROM OauthToken');
    } catch {
      tokens = [];
    }
    const appsWithTokens = new Set(tokens.map((t) => t.AppName));

    try {
      const apps = await q.query<AppRow>('SELECT Name, OptionsAllowAdminApprovedUsersOnly FROM ConnectedApplication');
      const open = apps.filter((a) => !a.OptionsAllowAdminApprovedUsersOnly).map((a) => a.Name);
      if (open.length > 0) {
        const inUse = open.filter((n) => appsWithTokens.has(n));
        findings.push({
          checkId: this.id,
          severity: inUse.length > 0 ? 'high' : 'medium',
          title: `${open.length} connected app(s) let any user self-authorize`,
          detail:
            `These apps accept OAuth from any user rather than admin-approved users only. ${inUse.length} of them have active tokens.`,
          recommendation:
            'Set "Permitted Users" to "Admin approved users are pre-authorized" and grant access through permission sets.',
          affected: open.sort(),
        });
      }
    } catch {
      // ConnectedApplication not queryable for this user; token review still runs.
    }

    const stale = tokens.filter((t) => isStale(t.LastUsedDate, ctx.staleDays));
    if (stale.length > 0) {
      const byApp = new Map<string, number>();
      for (const t of stale) byApp.set(t.AppName, (byApp.get(t.AppName) ?? 0) + 1);
      findings.push({
        checkId: this.id,
        severity: 'medium',
        title: `${stale.length} OAuth token(s) unused for ${ctx.staleDays}+ days`,
        detail: 'Long-lived unused refresh tokens keep API access open with no business need.',
        recommendation: 'Revoke stale tokens and set a refresh token expiration policy on each connected app.',
        affected: [...byApp.entries()].sort((a, b) => b[1] - a[1]).map(([app, n]) => `${app}: ${n} token(s)`),
      });
    }

    return findings;
  },
};
