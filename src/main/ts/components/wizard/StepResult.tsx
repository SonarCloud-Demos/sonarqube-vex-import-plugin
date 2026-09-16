import React from 'react';
import { PlanItem } from '../../vex/assessImport';
import { StatusChangeResult } from '../../api/scaChangeStatus';
import { Badge, thBase, tdStyle } from '../shared/tableUtils';

const cardStyle: React.CSSProperties = {
  background: '#fff',
  border: '1px solid #e0e0e0',
  borderRadius: '4px',
  padding: '20px 24px',
  marginBottom: '16px',
};

const buttonStyle: React.CSSProperties = {
  padding: '8px 20px',
  fontSize: '13px',
  fontWeight: 600,
  borderRadius: '4px',
  border: 'none',
  cursor: 'pointer',
  background: '#4b9fd5',
  color: '#fff',
};

export interface StepResultProps {
  finalImportable: PlanItem[];
  results: StatusChangeResult[];
  onStartOver: () => void;
}

export function StepResult({ finalImportable, results, onStartOver }: Readonly<StepResultProps>) {
  const resultsByKey = new Map(results.map((r) => [r.issueReleaseKey, r]));
  const succeeded = results.filter((r) => r.ok).length;
  const failed = results.length - succeeded;

  const missing = finalImportable.filter((item) => !resultsByKey.has(item.issueReleaseKey));

  return (
    <div>
      <div style={cardStyle}>
        <p style={{ fontSize: '13px', color: '#444' }}>
          <Badge label={`${succeeded} applied`} color="#2da44e" />{' '}
          {failed > 0 && <Badge label={`${failed} failed`} color="#d02f3a" />}
        </p>

        {missing.length > 0 && (
          <p style={{ fontSize: '12px', color: '#dc2626', marginTop: '8px' }}>
            {missing.length} item{missing.length === 1 ? '' : 's'} assessed as importable did not get a result
            back from the apply step - this shouldn't happen and may indicate a stale assessment; consider
            starting over.
          </p>
        )}

        <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '12px' }}>
          <thead>
            <tr>
              <th style={thBase}>CVE</th>
              <th style={thBase}>Package</th>
              <th style={thBase}>New status</th>
              <th style={thBase}>Result</th>
            </tr>
          </thead>
          <tbody>
            {finalImportable.map((item) => {
              const result = resultsByKey.get(item.issueReleaseKey);
              return (
                <tr key={item.issueReleaseKey}>
                  <td style={tdStyle}>{item.vulnerabilityId}</td>
                  <td style={tdStyle}>{item.packageUrl}</td>
                  <td style={tdStyle}>{item.transitionKey}</td>
                  <td style={tdStyle}>
                    {!result && <Badge label="No result" color="#6b7280" />}
                    {result?.ok && <Badge label="Applied" color="#2da44e" />}
                    {result && !result.ok && (
                      <span style={{ color: '#dc2626' }}>
                        <Badge label="Failed" color="#d02f3a" /> {result.error}
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <button style={buttonStyle} onClick={onStartOver}>
        Start over
      </button>
    </div>
  );
}
