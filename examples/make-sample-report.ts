// Generates examples/sample-report.html from a fake org so the README can show a real report.
// Run: npx tsx examples/make-sample-report.ts
import { writeFileSync } from 'node:fs';
import { DEFAULT_CONTEXT, QueryRunner, runChecks } from '../src/checks/index.js';
import { renderHtml } from '../src/report/html.js';

const old = new Date(Date.now() - 180 * 86400000).toISOString();
const admins = Array.from({ length: 9 }, (_, i) => ({
  AssigneeId: `005${i}`,
  Assignee: { Username: `admin${i + 1}@acme.example` },
  PermissionSet: { Label: 'System Administrator', IsOwnedByProfile: true, Profile: { Name: 'System Administrator' } },
}));

const routes: Array<[RegExp, unknown[]]> = [
  [/FROM User WHERE/, [{ Username: 'former.contractor@acme.example', LastLoginDate: old }]],
  [/PermissionsModifyAllData = true/, admins],
  [/PermissionsViewAllData = true/, admins.slice(0, 3)],
  [/FROM OauthToken/, [{ AppName: 'Legacy Data Export', LastUsedDate: old }, { AppName: 'Legacy Data Export', LastUsedDate: null }]],
  [/FROM ConnectedApplication/, [{ Name: 'Legacy Data Export', OptionsAllowAdminApprovedUsersOnly: false }]],
  [/FROM EntityDefinition/, [{ QualifiedApiName: 'Account', InternalSharingModel: 'ReadWrite', ExternalSharingModel: 'Private' }]],
];

const fake: QueryRunner = {
  async query<T extends Record<string, unknown>>(soql: string) {
    return (routes.find(([re]) => re.test(soql))?.[1] ?? []) as T[];
  },
};

const results = await runChecks(fake, DEFAULT_CONTEXT);
writeFileSync(new URL('./sample-report.html', import.meta.url), renderHtml(results, 'admin@acme.example (sample data)'));
console.log('Wrote examples/sample-report.html');
