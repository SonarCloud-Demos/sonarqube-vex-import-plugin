import React from 'react';
import { AssessmentResult } from '../../vex/assessImport';
import { thBase, tdStyle } from '../shared/tableUtils';

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
  marginRight: '8px',
};

const primaryButtonStyle: React.CSSProperties = { ...buttonStyle, background: '#4b9fd5', color: '#fff' };
const secondaryButtonStyle: React.CSSProperties = { ...buttonStyle, background: '#eee', color: '#333' };

function disabledStyle(style: React.CSSProperties, disabled: boolean): React.CSSProperties {
  return disabled ? { ...style, opacity: 0.5, cursor: 'not-allowed' } : style;
}

export interface StepAssessmentProps {
  loading: boolean;
  error: string | null;
  assessment: AssessmentResult | null;
  onBack: () => void;
  onNext: () => void;
}

export function StepAssessment({ loading, error, assessment, onBack, onNext }: Readonly<StepAssessmentProps>) {
  if (loading) {
    return <p style={{ padding: '16px', color: '#666' }}>Fetching detected dependency risks…</p>;
  }
  if (error) {
    return (
      <div>
        <div style={{ padding: '12px 16px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '4px', color: '#dc2626', fontSize: '13px', marginBottom: '16px' }}>
          Error: {error}
        </div>
        <button style={secondaryButtonStyle} onClick={onBack}>
          Back
        </button>
      </div>
    );
  }
  if (!assessment) {
    return null;
  }

  const { importable, blocked } = assessment;

  return (
    <div>
      <div style={cardStyle}>
        <h2 style={{ fontSize: '14px', fontWeight: 700, marginBottom: '10px' }}>
          Importable changes ({importable.length})
        </h2>
        {importable.length === 0 ? (
          <p style={{ fontSize: '13px', color: '#666' }}>Nothing from this VEX file can be imported.</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={thBase}>CVE</th>
                <th style={thBase}>Package</th>
                <th style={thBase}>Current status</th>
                <th style={thBase}>New status</th>
                <th style={thBase}>Comment</th>
              </tr>
            </thead>
            <tbody>
              {importable.map((item) => (
                <tr key={`${item.issueReleaseKey}`}>
                  <td style={tdStyle}>{item.vulnerabilityId}</td>
                  <td style={tdStyle}>{item.packageUrl}</td>
                  <td style={tdStyle}>{item.currentStatus}</td>
                  <td style={tdStyle}>{item.transitionKey}</td>
                  <td style={tdStyle}>{item.comment}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div style={cardStyle}>
        <h2 style={{ fontSize: '14px', fontWeight: 700, marginBottom: '10px' }}>
          Not importable ({blocked.length})
        </h2>
        {blocked.length === 0 ? (
          <p style={{ fontSize: '13px', color: '#666' }}>Every VEX entry could be matched and imported.</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={thBase}>CVE</th>
                <th style={thBase}>Package</th>
                <th style={thBase}>Reason</th>
              </tr>
            </thead>
            <tbody>
              {blocked.map((item, idx) => (
                <tr key={`${item.vulnerabilityId ?? 'unknown'}-${item.packageUrl ?? 'unknown'}-${idx}`}>
                  <td style={tdStyle}>{item.vulnerabilityId ?? '—'}</td>
                  <td style={tdStyle}>{item.packageUrl ?? '—'}</td>
                  <td style={tdStyle}>{item.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <button style={secondaryButtonStyle} onClick={onBack}>
        Back
      </button>
      <button style={disabledStyle(primaryButtonStyle, importable.length === 0)} onClick={onNext} disabled={importable.length === 0}>
        Next
      </button>
    </div>
  );
}
