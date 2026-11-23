import { Finding, SecurityCheck } from './types.js';

interface EntityRow extends Record<string, unknown> {
  QualifiedApiName: string;
  InternalSharingModel: string;
  ExternalSharingModel: string;
}

const OPEN_INTERNAL = new Set(['ReadWrite', 'ReadWriteTransfer', 'FullAccess']);
const SAFE_EXTERNAL = new Set(['Private', 'None', 'ControlledByParent']);

/** Escape a value for use inside a single-quoted SOQL string. */
export function soqlString(v: string): string {
  return `'${v.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

export const sharingDefaultsCheck: SecurityCheck = {
  id: 'sharing-defaults',
  name: 'Organization-wide sharing defaults',
  description: 'Reviews internal and external OWDs on sensitive objects.',
  async run(q, ctx) {
    if (ctx.sharingObjects.length === 0) return [];
    const list = ctx.sharingObjects.map(soqlString).join(', ');
    const rows = await q.query<EntityRow>(
      `SELECT QualifiedApiName, InternalSharingModel, ExternalSharingModel FROM EntityDefinition WHERE QualifiedApiName IN (${list})`
    );
    const openInternal = rows.filter((r) => OPEN_INTERNAL.has(r.InternalSharingModel));
    const openExternal = rows.filter((r) => r.ExternalSharingModel && !SAFE_EXTERNAL.has(r.ExternalSharingModel));
    const findings: Finding[] = [];
    if (openInternal.length > 0) {
      findings.push({
        checkId: this.id,
        severity: 'medium',
        title: `${openInternal.length} sensitive object(s) are Public Read/Write internally`,
        detail: 'Every internal user can edit every record of these objects, which defeats role-based access.',
        recommendation: 'Move the default to Private or Public Read Only and open access with role hierarchy and sharing rules.',
        affected: openInternal.map((r) => `${r.QualifiedApiName}: ${r.InternalSharingModel}`),
      });
    }
    if (openExternal.length > 0) {
      findings.push({
        checkId: this.id,
        severity: 'high',
        title: `${openExternal.length} sensitive object(s) are shared with external users by default`,
        detail: 'Portal and community users can see records of these objects without an explicit sharing rule.',
        recommendation: 'Set the external default to Private and share with external users through sharing sets or sharing rules.',
        affected: openExternal.map((r) => `${r.QualifiedApiName}: ${r.ExternalSharingModel}`),
      });
    }
    return findings;
  },
};
