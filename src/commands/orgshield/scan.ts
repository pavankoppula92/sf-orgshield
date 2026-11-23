import { writeFile } from 'node:fs/promises';
import { Flags, SfCommand } from '@salesforce/sf-plugins-core';
import { CheckResult, DEFAULT_CONTEXT, QueryRunner, Severity, runChecks, severityAtLeast } from '../../checks/index.js';
import { renderHtml } from '../../report/html.js';
import { Score, allFindings, computeScore } from '../../report/score.js';

export interface ScanResult {
  org: string;
  score: Score;
  checks: CheckResult[];
}

export default class Scan extends SfCommand<ScanResult> {
  public static readonly summary = 'Audit an org for risky permissions, connected app exposure, guest access and sharing defaults.';
  public static readonly description =
    'Runs read-only SOQL checks against the target org and prints a scored report. Nothing in the org is changed.';
  public static readonly examples = [
    '<%= config.bin %> <%= command.id %> --target-org prod',
    '<%= config.bin %> <%= command.id %> --target-org prod --format html --output-file report.html',
    '<%= config.bin %> <%= command.id %> --target-org prod --fail-on high',
  ];

  public static readonly flags = {
    'target-org': Flags.requiredOrg(),
    'api-version': Flags.orgApiVersion(),
    format: Flags.option({
      summary: 'Report format.',
      options: ['text', 'html'] as const,
      default: 'text',
    })(),
    'output-file': Flags.string({ summary: 'Write the report to this file instead of the terminal.' }),
    'stale-days': Flags.integer({ summary: 'Days of inactivity before a user or token counts as stale.', default: 90, min: 1 }),
    'max-privileged-users': Flags.integer({
      summary: 'Holders of a privileged permission allowed before it is flagged.',
      default: 5,
      min: 0,
    }),
    objects: Flags.string({
      summary: 'Objects whose sharing defaults are reviewed. Repeat or comma-separate.',
      multiple: true,
      delimiter: ',',
    }),
    'fail-on': Flags.option({
      summary: 'Exit with code 1 if any finding is at or above this severity (for CI pipelines).',
      options: ['critical', 'high', 'medium', 'low'] as const,
    })(),
  };

  public async run(): Promise<ScanResult> {
    const { flags } = await this.parse(Scan);
    const org = flags['target-org'];
    const conn = org.getConnection(flags['api-version']);
    const orgLabel = org.getUsername() ?? org.getOrgId();

    const runner: QueryRunner = {
      async query<T extends Record<string, unknown>>(soql: string): Promise<T[]> {
        const res = await conn.autoFetchQuery(soql);
        return res.records as unknown as T[];
      },
    };

    this.spinner.start(`Scanning ${orgLabel}`);
    const checks = await runChecks(runner, {
      staleDays: flags['stale-days'],
      maxPrivilegedUsers: flags['max-privileged-users'],
      sharingObjects: flags.objects && flags.objects.length > 0 ? flags.objects : DEFAULT_CONTEXT.sharingObjects,
    });
    this.spinner.stop();

    const score = computeScore(checks);
    const output = flags.format === 'html' ? renderHtml(checks, orgLabel) : renderText(checks, orgLabel, score);

    if (flags['output-file']) {
      await writeFile(flags['output-file'], output, 'utf8');
      this.log(`Report written to ${flags['output-file']} (score ${score.score}/100, grade ${score.grade})`);
    } else if (!this.jsonEnabled()) {
      this.log(output);
    }

    const failOn = flags['fail-on'] as Severity | undefined;
    if (failOn && allFindings(checks).some((f) => severityAtLeast(f.severity, failOn))) {
      process.exitCode = 1;
    }

    return { org: orgLabel, score, checks };
  }
}

function renderText(checks: CheckResult[], orgLabel: string, score: Score): string {
  const lines: string[] = [];
  lines.push(`OrgShield report for ${orgLabel}`);
  lines.push(`Score: ${score.score}/100  Grade: ${score.grade}`);
  lines.push(
    `Critical ${score.counts.critical} | High ${score.counts.high} | Medium ${score.counts.medium} | Low ${score.counts.low} | Info ${score.counts.info}`
  );
  lines.push('');
  for (const c of checks) {
    lines.push(`[${c.status.toUpperCase()}] ${c.name}${c.skippedReason ? ` (${c.skippedReason})` : ''}`);
  }
  for (const f of allFindings(checks)) {
    lines.push('');
    lines.push(`${f.severity.toUpperCase()}: ${f.title}`);
    lines.push(`  ${f.detail}`);
    lines.push(`  Fix: ${f.recommendation}`);
    if (f.affected && f.affected.length > 0) {
      const shown = f.affected.slice(0, 10);
      for (const a of shown) lines.push(`    - ${a}`);
      if (f.affected.length > shown.length) lines.push(`    ...and ${f.affected.length - shown.length} more`);
    }
  }
  return lines.join('\n');
}
