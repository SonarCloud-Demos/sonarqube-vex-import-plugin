import { parseVex, VexParseError } from './parseVex';

function doc(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    vulnerabilities: [],
    ...overrides,
  });
}

describe('parseVex', () => {
  it('rejects invalid JSON', () => {
    expect(() => parseVex('not json')).toThrow(VexParseError);
  });

  it('rejects a non-CycloneDX document', () => {
    expect(() => parseVex(doc({ bomFormat: 'SPDX' }))).toThrow(/CycloneDX/);
  });

  it('rejects an unsupported specVersion', () => {
    expect(() => parseVex(doc({ specVersion: '1.5' }))).toThrow(/specVersion/);
  });

  it('rejects a document with no vulnerabilities array', () => {
    expect(() => parseVex(doc({ vulnerabilities: undefined }))).toThrow(/vulnerabilities/);
  });

  it('parses a direct pkg: ref without needing components[]', () => {
    const result = parseVex(
      doc({
        vulnerabilities: [
          { id: 'CVE-2021-44228', affects: [{ ref: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' }] },
        ],
      })
    );
    expect(result.candidates).toEqual([
      { vulnerabilityId: 'CVE-2021-44228', packageUrl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', analysis: undefined },
    ]);
    expect(result.issues).toEqual([]);
  });

  it('resolves a bom-ref against components[]', () => {
    const result = parseVex(
      doc({
        components: [{ 'bom-ref': 'comp-1', purl: 'pkg:npm/express@4.19.2' }],
        vulnerabilities: [{ id: 'CVE-2024-1234', affects: [{ ref: 'comp-1' }] }],
      })
    );
    expect(result.candidates).toEqual([
      { vulnerabilityId: 'CVE-2024-1234', packageUrl: 'pkg:npm/express@4.19.2', analysis: undefined },
    ]);
  });

  it('resolves a BOM-Link-prefixed bom-ref against components[]', () => {
    const result = parseVex(
      doc({
        components: [{ 'bom-ref': 'comp-1', purl: 'pkg:npm/express@4.19.2' }],
        vulnerabilities: [{ id: 'CVE-2024-1234', affects: [{ ref: 'urn:cdx:some-bom-serial/1#comp-1' }] }],
      })
    );
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0].packageUrl).toBe('pkg:npm/express@4.19.2');
  });

  it('collects a missing-id entry as an issue instead of throwing', () => {
    const result = parseVex(doc({ vulnerabilities: [{ affects: [{ ref: 'pkg:npm/x@1' }] }] }));
    expect(result.candidates).toEqual([]);
    expect(result.issues).toEqual([{ packageUrl: undefined, reason: 'missing vulnerability id (CVE)' }]);
  });

  it('collects a missing-affects entry as an issue', () => {
    const result = parseVex(doc({ vulnerabilities: [{ id: 'CVE-2024-9999', affects: [] }] }));
    expect(result.issues).toEqual([
      { vulnerabilityId: 'CVE-2024-9999', reason: 'no affected component reference in VEX entry' },
    ]);
  });

  it('collects an unresolvable ref as an issue', () => {
    const result = parseVex(doc({ vulnerabilities: [{ id: 'CVE-2024-9999', affects: [{ ref: 'unknown-ref' }] }] }));
    expect(result.issues).toEqual([
      { vulnerabilityId: 'CVE-2024-9999', reason: 'could not resolve component reference "unknown-ref" to a package URL' },
    ]);
  });

  it('produces one candidate per affected component for a multi-affects vulnerability', () => {
    const result = parseVex(
      doc({
        vulnerabilities: [
          {
            id: 'CVE-2024-5555',
            affects: [{ ref: 'pkg:npm/a@1' }, { ref: 'pkg:npm/b@2' }],
          },
        ],
      })
    );
    expect(result.candidates).toHaveLength(2);
    expect(result.candidates.map((c) => c.packageUrl)).toEqual(['pkg:npm/a@1', 'pkg:npm/b@2']);
  });
});
