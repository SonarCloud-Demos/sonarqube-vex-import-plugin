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
}
