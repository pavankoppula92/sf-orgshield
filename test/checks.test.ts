import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_CONTEXT, QueryRunner, runChecks, severityAtLeast } from '../src/checks/index.js';
import { privilegedPermissionsCheck } from '../src/checks/privilegedPermissions.js';
import { connectedAppsCheck, isStale } from '../src/checks/connectedApps.js';
import { guestAccessCheck } from '../src/checks/guestAccess.js';
import { sharingDefaultsCheck, soqlString } from '../src/checks/sharingDefaults.js';
import { computeScore } from '../src/report/score.js';
import { escapeHtml, renderHtml } from '../src/report/html.js';

/** Fake org: returns rows for the first matcher whose pattern appears in the SOQL. */
function fakeOrg(routes: Array<[RegExp, unknown[] | Error]>): QueryRunner {
  return {
    async query<T extends Record<string, unknown>>(soql: string): Promise<T[]> {
      for (const [re, rows] of routes) {
        if (re.test(soql)) {
          if (rows instanceof Error) throw rows;
          return rows as T[];
        }
      }
      return [];
    },
  };
}

function assignments(n: number, label = 'System Administrator') {
  return Array.from({ length: n }, (_, i) => ({
    AssigneeId: `005${i}`,
    Assignee: { Username: `admin${i}@example.com` },
    PermissionSet: { Label: label, IsOwnedByProfile: true, Profile: { Name: label } },
  }));
}

test('privileged permissions: over threshold is critical, under threshold is info', async () => {
  const q = fakeOrg([
    [/PermissionsModifyAllData = true/, assignments(8)],
    [/PermissionsViewAllData = true/, assignments(2)],
  ]);
  const findings = await privilegedPermissionsCheck.run(q, DEFAULT_CONTEXT);
  const mad = findings.find((f) => f.title.includes('Modify All Data'));
  const vad = findings.find((f) => f.title.includes('View All Data'));
  assert.equal(mad?.severity, 'critical');
  assert.equal(mad?.affected?.length, 8);
  assert.equal(vad?.severity, 'info');
});

test('privileged permissions: unknown permission field is skipped, not fatal', async () => {
  const q = fakeOrg([
    [/PermissionsUseAnyApiClient/, new Error("No such column 'PermissionsUseAnyApiClient'")],
    [/PermissionsModifyAllData = true/, assignments(6)],
  ]);
  const findings = await privilegedPermissionsCheck.run(q, DEFAULT_CONTEXT);
  assert.ok(findings.some((f) => f.title.includes('Modify All Data')));
  assert.ok(!findings.some((f) => f.title.includes('Use Any API Client')));
});

test('connected apps: self-authorize apps with tokens are high; stale tokens are counted', async () => {
  const old = new Date(Date.now() - 200 * 86400000).toISOString();
  const recent = new Date().toISOString();
  const q = fakeOrg([
    [
      /FROM OauthToken/,
      [
        { AppName: 'Data Exporter', LastUsedDate: old },
        { AppName: 'Data Exporter', LastUsedDate: null },
        { AppName: 'Mobile', LastUsedDate: recent },
      ],
    ],
    [
      /FROM ConnectedApplication/,
      [
        { Name: 'Data Exporter', OptionsAllowAdminApprovedUsersOnly: false },
        { Name: 'Mobile', OptionsAllowAdminApprovedUsersOnly: true },
      ],
    ],
  ]);
  const findings = await connectedAppsCheck.run(q, DEFAULT_CONTEXT);
  const open = findings.find((f) => f.title.includes('self-authorize'));
  const stale = findings.find((f) => f.title.includes('OAuth token'));
  assert.equal(open?.severity, 'high');
  assert.deepEqual(open?.affected, ['Data Exporter']);
  assert.equal(stale?.title.startsWith('2 '), true);
});

test('isStale treats null as stale and respects the day window', () => {
  const now = new Date('2026-01-31T00:00:00Z');
  assert.equal(isStale(null, 90, now), true);
  assert.equal(isStale('2026-01-30T00:00:00Z', 90, now), false);
  assert.equal(isStale('2025-09-01T00:00:00Z', 90, now), true);
});

test('guest access: view all is critical, edit is high', async () => {
  const q = fakeOrg([
    [
      /FROM ObjectPermissions/,
      [
        { SobjectType: 'Case', Parent: { Profile: { Name: 'Site Guest' } }, PermissionsEdit: false, PermissionsDelete: false, PermissionsViewAllRecords: true, PermissionsModifyAllRecords: false },
        { SobjectType: 'Lead', Parent: { Profile: { Name: 'Site Guest' } }, PermissionsEdit: true, PermissionsDelete: false, PermissionsViewAllRecords: false, PermissionsModifyAllRecords: false },
      ],
    ],
  ]);
  const findings = await guestAccessCheck.run(q, DEFAULT_CONTEXT);
  assert.deepEqual(findings.map((f) => f.severity), ['critical', 'high']);
});

test('sharing defaults: flags public read/write and external sharing', async () => {
  const q = fakeOrg([
    [
      /FROM EntityDefinition/,
      [
        { QualifiedApiName: 'Account', InternalSharingModel: 'ReadWrite', ExternalSharingModel: 'Private' },
        { QualifiedApiName: 'Case', InternalSharingModel: 'Private', ExternalSharingModel: 'Read' },
        { QualifiedApiName: 'Contact', InternalSharingModel: 'ControlledByParent', ExternalSharingModel: 'ControlledByParent' },
      ],
    ],
  ]);
  const findings = await sharingDefaultsCheck.run(q, DEFAULT_CONTEXT);
  assert.equal(findings.length, 2);
  assert.ok(findings[0].affected?.[0].startsWith('Account'));
  assert.ok(findings[1].affected?.[0].startsWith('Case'));
});

test('soqlString escapes quotes', () => {
  assert.equal(soqlString("O'Brien__c"), "'O\\'Brien__c'");
});

test('runChecks marks an erroring check as skipped and keeps going', async () => {
  const q = fakeOrg([
    [/FROM ObjectPermissions/, new Error('INSUFFICIENT_ACCESS')],
    [/PermissionsModifyAllData = true/, assignments(10)],
  ]);
  const results = await runChecks(q, DEFAULT_CONTEXT);
  assert.equal(results.find((r) => r.checkId === 'guest-access')?.status, 'skipped');
  assert.equal(results.find((r) => r.checkId === 'privileged-permissions')?.status, 'failed');
  assert.equal(results.find((r) => r.checkId === 'sharing-defaults')?.status, 'passed');
});

test('score and grade', () => {
  const s = computeScore([
    {
      checkId: 'x',
      name: 'x',
      status: 'failed',
      findings: [
        { checkId: 'x', severity: 'critical', title: '', detail: '', recommendation: '' },
        { checkId: 'x', severity: 'high', title: '', detail: '', recommendation: '' },
        { checkId: 'x', severity: 'info', title: '', detail: '', recommendation: '' },
      ],
    },
  ]);
  assert.equal(s.score, 70);
  assert.equal(s.grade, 'C');
  assert.equal(computeScore([]).grade, 'A');
});

test('severityAtLeast', () => {
  assert.equal(severityAtLeast('critical', 'high'), true);
  assert.equal(severityAtLeast('medium', 'high'), false);
});

test('html report escapes org data', () => {
  assert.equal(escapeHtml('<script>'), '&lt;script&gt;');
  const html = renderHtml(
    [{ checkId: 'x', name: 'X', status: 'failed', findings: [{ checkId: 'x', severity: 'high', title: '<b>t</b>', detail: 'd', recommendation: 'r', affected: ['<img>'] }] }],
    'admin@example.com'
  );
  assert.ok(html.includes('&lt;b&gt;t&lt;/b&gt;'));
  assert.ok(!html.includes('<img>'));
});
