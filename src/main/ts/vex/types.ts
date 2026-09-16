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
  // Not part of the core CycloneDX 1.6 `analysis` schema, but seen in real-world
  // exports (including SonarQube's own) — treated as optional/best-effort.
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
