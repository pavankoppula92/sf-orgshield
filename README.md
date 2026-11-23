# OrgShield

**A Salesforce CLI plugin that audits your org's security posture in one command.**

OrgShield runs read-only checks against a Salesforce org and gives you a scored report (0–100, grade A–F) showing who can access everything, which connected apps are wide open, what guest users can touch, and where sharing defaults leak data. It never changes anything in the org.

```bash
sf plugins install sf-orgshield
sf orgshield scan --target-org prod
```

```
OrgShield report for admin@acme.example
Score: 50/100  Grade: F
Critical 1 | High 2 | Medium 2 | Low 0 | Info 1

CRITICAL: 9 active user(s) hold "Modify All Data"
  Users with Modify All Data can create, edit and delete every record in the org regardless of sharing.
  Fix: Remove Modify All Data from profiles, grant it only through a small, reviewed permission set...
```

See a full [sample HTML report](examples/sample-report.html) generated from demo data.

## Why

Most org breaches don't need a bug. They come from over-permissioned users, forgotten integration tokens and connected apps anyone can authorize. Salesforce Health Check covers session and password settings. OrgShield covers **who actually has access and through which door**, and it runs in CI so regressions get caught before release.

## Checks

| Check | What it looks for | Severity |
|---|---|---|
| `privileged-permissions` | Active users holding Modify All Data, View All Data, Use Any API Client, Manage Users, Author Apex, Customize Application, Password Never Expires, above a threshold you set | critical → medium |
| `dormant-admins` | Users with Modify/View All Data who haven't logged in for N days | high |
| `connected-apps` | Connected apps open to self-authorization (worse when they have live tokens) and OAuth tokens unused for N days | high / medium |
| `guest-access` | Guest (unauthenticated) profiles with Edit, Delete, View All or Modify All on any object | critical / high |
| `sharing-defaults` | Sensitive objects set to Public Read/Write internally, or shared externally by default | medium / high |

A check that can't run, for example because the running user lacks access to an object, is reported as **skipped** with the reason. The rest of the scan still completes.

## Usage

```bash
# Terminal report
sf orgshield scan --target-org prod

# Shareable HTML report
sf orgshield scan --target-org prod --format html --output-file orgshield-report.html

# Machine-readable output
sf orgshield scan --target-org prod --json

# Fail a CI pipeline if anything high or critical is found
sf orgshield scan --target-org staging --fail-on high

# Tune thresholds and objects
sf orgshield scan --target-org prod --stale-days 60 --max-privileged-users 3 --objects Account,Case,Loan__c
```

| Flag | Default | Description |
|---|---|---|
| `--target-org` | required | Org alias or username |
| `--format` | `text` | `text` or `html` |
| `--output-file` | — | Write the report to a file |
| `--stale-days` | `90` | Inactivity window for users and tokens |
| `--max-privileged-users` | `5` | Holders allowed before a privileged permission is flagged |
| `--objects` | Account, Contact, Opportunity, Case, Lead | Objects whose sharing defaults are reviewed |
| `--fail-on` | — | Exit code 1 at or above this severity |

### Use in CI (GitHub Actions)

```yaml
- run: npm install -g @salesforce/cli && sf plugins install sf-orgshield
- run: sf org login sfdx-url --sfdx-url-file auth.txt --alias staging
- run: sf orgshield scan --target-org staging --fail-on high --format html --output-file orgshield.html
- uses: actions/upload-artifact@v4
  with: { name: orgshield-report, path: orgshield.html }
```

## Scoring

The score starts at 100 and loses points per finding: critical −20, high −10, medium −5, low −2, info 0. A = 90+, B = 80+, C = 70+, D = 60+, F below 60.

## Required access

The running user needs **View Setup and Configuration** and read access to `PermissionSetAssignment`, `User`, `OauthToken`, `ConnectedApplication`, `ObjectPermissions` and `EntityDefinition`. A System Administrator or a dedicated read-only audit user both work.

## Use as a library

```ts
import { runChecks, computeScore, DEFAULT_CONTEXT } from 'sf-orgshield';

const results = await runChecks({ query: async (soql) => (await conn.autoFetchQuery(soql)).records }, DEFAULT_CONTEXT);
console.log(computeScore(results));
```

## Development

```bash
npm install
npm run build
npm test          # unit tests run against a fake org, no Salesforce login needed
sf plugins link . # try the command locally
```

Each check is a small module in `src/checks/` that implements `SecurityCheck`. To add a check, create the module, register it in `src/checks/index.ts` and add tests in `test/`.

## Roadmap

- [ ] Profiles and permission sets with "View All" or "Modify All" on sensitive objects
- [ ] Apex classes declared `without sharing` that are exposed to Experience Cloud
- [ ] Login IP range and session security policies on admin profiles
- [ ] SARIF output for GitHub code scanning
- [ ] Trend reports comparing two scans

Contributions are welcome. Open an issue to discuss a new check.

## License

MIT © Pavan Koppula
