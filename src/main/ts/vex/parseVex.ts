import { CycloneDxAnalysis, CycloneDxDocument } from './types';

export class VexParseError extends Error {}

export interface VexCandidate {
  vulnerabilityId: string;
  packageUrl: string;
  analysis?: CycloneDxAnalysis;
  // Best-effort "as of" date for this VEX statement — analysis.lastUpdated, else
  // analysis.firstIssued, else the whole document's metadata.timestamp. undefined
  // when none of the three are present.
  vexReferenceDate?: string;
}

export interface VexParseIssue {
  vulnerabilityId?: string;
  packageUrl?: string;
  reason: string;
}

export interface VexParseResult {
  candidates: VexCandidate[];
  issues: VexParseIssue[];
}

function resolvePackageUrl(ref: string, componentsByBomRef: Map<string, string>): string | undefined {
  if (ref.startsWith('pkg:')) {
    return ref;
  }
  // A bom-ref may be prefixed with a BOM-Link ("urn:cdx:...#bom-ref") — strip it before lookup.
  const bomRef = ref.includes('#') ? ref.slice(ref.lastIndexOf('#') + 1) : ref;
  return componentsByBomRef.get(bomRef);
}

/**
 * Parses a CycloneDX 1.6 VEX document (JSON text) into a flat list of
 * (vulnerabilityId, packageUrl) candidates ready for matching against
 * SonarQube's detected dependency risks.
 *
 * Throws VexParseError for document-level problems that make the whole file
 * unusable. Per-vulnerability problems are collected into `issues` instead of
 * failing the whole import, since one malformed entry shouldn't block the rest.
 */
export function parseVex(rawJsonText: string): VexParseResult {
  let doc: CycloneDxDocument;
  try {
    doc = JSON.parse(rawJsonText);
  } catch {
    throw new VexParseError('File is not valid JSON.');
  }

  if (doc.bomFormat !== 'CycloneDX') {
    throw new VexParseError('Not a CycloneDX document (missing or incorrect bomFormat).');
  }
  if (doc.specVersion !== '1.6') {
    throw new VexParseError('Unsupported CycloneDX specVersion — only 1.6 is supported.');
  }
  if (!Array.isArray(doc.vulnerabilities)) {
    throw new VexParseError('No vulnerabilities[] array found in this VEX document.');
  }

  const componentsByBomRef = new Map<string, string>();
  for (const component of doc.components ?? []) {
    if (component['bom-ref'] && component.purl) {
      componentsByBomRef.set(component['bom-ref'], component.purl);
    }
  }

  const documentTimestamp = doc.metadata?.timestamp;
  const candidates: VexCandidate[] = [];
  const issues: VexParseIssue[] = [];

  for (const vuln of doc.vulnerabilities) {
    if (!vuln.id) {
      issues.push({ packageUrl: undefined, reason: 'missing vulnerability id (CVE)' });
      continue;
    }
    if (!vuln.affects || vuln.affects.length === 0) {
      issues.push({ vulnerabilityId: vuln.id, reason: 'no affected component reference in VEX entry' });
      continue;
    }

    for (const affect of vuln.affects) {
      const packageUrl = affect.ref ? resolvePackageUrl(affect.ref, componentsByBomRef) : undefined;
      if (!packageUrl) {
        issues.push({
          vulnerabilityId: vuln.id,
          reason: `could not resolve component reference "${affect.ref}" to a package URL`,
        });
        continue;
      }
      const vexReferenceDate = vuln.analysis?.lastUpdated ?? vuln.analysis?.firstIssued ?? documentTimestamp;
      candidates.push({ vulnerabilityId: vuln.id, packageUrl, analysis: vuln.analysis, vexReferenceDate });
    }
  }

  return { candidates, issues };
}
