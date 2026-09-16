export interface CycloneDxComponent {
  'bom-ref'?: string;
  purl?: string;
}

export interface CycloneDxAffects {
  ref: string;
}

export interface CycloneDxAnalysis {
  state?: string;
  justification?: string;
  response?: string[];
  detail?: string;
  // Official CycloneDX fields (added in spec v1.5, carried into 1.6) — optional,
  // so still treated as best-effort rather than assumed present.
  lastUpdated?: string;
  firstIssued?: string;
}

export interface CycloneDxVulnerability {
  id?: string;
  affects?: CycloneDxAffects[];
  analysis?: CycloneDxAnalysis;
}

export interface CycloneDxDocument {
  bomFormat?: string;
  specVersion?: string;
  components?: CycloneDxComponent[];
  vulnerabilities?: CycloneDxVulnerability[];
  metadata?: { timestamp?: string };
}
