import React from 'react';
import { ConflictItem } from '../../vex/assessImport';
import { thBase, tdStyle, formatDate } from '../shared/tableUtils';

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

const bulkButtonStyle = (active: boolean): React.CSSProperties => ({
  padding: '5px 12px',
  fontSize: '12px',
  fontWeight: 600,
  borderRadius: '4px',
  border: `1px solid ${active ? '#236a97' : '#ccc'}`,
  background: active ? '#236a97' : '#fff',
  color: active ? '#fff' : '#333',
  cursor: 'pointer',
  marginRight: '8px',
});

const radioLabelStyle: React.CSSProperties = { display: 'block', fontSize: '12px', cursor: 'pointer', whiteSpace: 'nowrap' };

// tdStyle alone doesn't constrain wrapping - with table-layout: fixed and the
// colgroup widths above, this keeps long free text (comments, PURLs) wrapping
// normally at word boundaries instead of overflowing or forcing the column
// narrower than intended.
const wrapCellStyle: React.CSSProperties = { ...tdStyle, wordBreak: 'break-word', overflowWrap: 'break-word' };

export type ConflictResolution = 'keep' | 'apply';

export interface StepConflictsProps {
  conflicts: ConflictItem[];
  resolutions: Map<string, ConflictResolution>;
  onResolutionsChange: (next: Map<string, ConflictResolution>) => void;
  onBack: () => void;
  onNext: () => void;
}

function resolutionFor(resolutions: Map<string, ConflictResolution>, key: string): ConflictResolution {
  return resolutions.get(key) ?? 'keep';
}

export function StepConflicts({ conflicts, resolutions, onResolutionsChange, onBack, onNext }: Readonly<StepConflictsProps>) {
  function setAll(value: ConflictResolution) {
    onResolutionsChange(new Map(conflicts.map((c) => [c.item.issueReleaseKey, value])));
  }

  function setOne(key: string, value: ConflictResolution) {
    const next = new Map(resolutions);
    next.set(key, value);
    onResolutionsChange(next);
  }

  const applyCount = conflicts.filter((c) => resolutionFor(resolutions, c.item.issueReleaseKey) === 'apply').length;
  const keepCount = conflicts.length - applyCount;

  return (
    <div>
      <div style={cardStyle}>
        <h2 style={{ fontSize: '14px', fontWeight: 700, marginBottom: '6px' }}>
          Resolve conflicts ({conflicts.length})
        </h2>
        <p style={{ fontSize: '13px', color: '#666', marginBottom: '12px' }}>
          SonarQube's current status was changed manually more recently than this VEX file's own reference date (or
          the file has no date to compare). Choose whether to keep SonarQube's current status or apply the VEX's
          proposed status anyway - for all of them at once, or row by row. Unresolved rows default to{' '}
          <strong>keep SonarQube</strong>.
        </p>

        <div style={{ marginBottom: '8px' }}>
          <button
            style={bulkButtonStyle(keepCount === conflicts.length)}
            aria-pressed={keepCount === conflicts.length}
            onClick={() => setAll('keep')}
          >
            Keep SonarQube for all
          </button>
          <button
            style={bulkButtonStyle(applyCount === conflicts.length)}
            aria-pressed={applyCount === conflicts.length}
            onClick={() => setAll('apply')}
          >
            Apply VEX to all
          </button>
        </div>
        <p style={{ fontSize: '13px', color: '#444', marginBottom: '12px' }} data-testid="conflicts-summary" aria-live="polite">
          <strong>{applyCount}</strong> will get the VEX status, <strong>{keepCount}</strong> will keep SonarQube's
          status.
        </p>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', minWidth: '1300px', tableLayout: 'fixed', borderCollapse: 'collapse' }}>
            <colgroup>
              <col style={{ width: '90px' }} />
              <col style={{ width: '160px' }} />
              <col style={{ width: '170px' }} />
              <col style={{ width: '100px' }} />
              <col style={{ width: '100px' }} />
              <col style={{ width: '140px' }} />
              <col style={{ width: '260px' }} />
              <col style={{ width: '110px' }} />
              <col style={{ width: '260px' }} />
            </colgroup>
            <thead>
              <tr>
                <th style={thBase}>CVE</th>
                <th style={thBase}>Decision</th>
                <th style={thBase}>Package</th>
                <th style={thBase}>SonarQube: current status</th>
                <th style={thBase}>VEX: proposed status</th>
                <th style={thBase}>SonarQube: last changed</th>
                <th style={thBase}>SonarQube: comment</th>
                <th style={thBase}>VEX: reference date</th>
                <th style={thBase}>VEX: comment</th>
              </tr>
            </thead>
            <tbody>
              {conflicts.map((c) => {
                const key = c.item.issueReleaseKey;
                const resolution = resolutionFor(resolutions, key);
                return (
                  <tr key={key}>
                    <td style={wrapCellStyle}>{c.item.vulnerabilityId}</td>
                    <td style={tdStyle}>
                      <label style={radioLabelStyle}>
                        <input
                          type="radio"
                          name={`resolution-${key}`}
                          value="keep"
                          checked={resolution === 'keep'}
                          onChange={() => setOne(key, 'keep')}
                        />{' '}
                        Keep SonarQube
                      </label>
                      <label style={radioLabelStyle}>
                        <input
                          type="radio"
                          name={`resolution-${key}`}
                          value="apply"
                          checked={resolution === 'apply'}
                          onChange={() => setOne(key, 'apply')}
                        />{' '}
                        Apply VEX
                      </label>
                    </td>
                    <td style={wrapCellStyle}>{c.item.packageUrl}</td>
                    <td style={wrapCellStyle}>{c.item.currentStatus}</td>
                    <td style={wrapCellStyle}>{c.item.transitionKey}</td>
                    <td style={wrapCellStyle}>
                      {formatDate(c.sonarLastChangeDate)}
                      {c.sonarLastChangeUser ? ` by ${c.sonarLastChangeUser}` : ''}
                    </td>
                    <td style={wrapCellStyle}>{c.sonarLastChangeComment ?? '-'}</td>
                    <td style={wrapCellStyle}>{formatDate(c.vexReferenceDate)}</td>
                    <td style={wrapCellStyle}>{c.item.comment}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <button style={secondaryButtonStyle} onClick={onBack}>
        Back
      </button>
      <button style={primaryButtonStyle} onClick={onNext}>
        Next
      </button>
    </div>
  );
}
