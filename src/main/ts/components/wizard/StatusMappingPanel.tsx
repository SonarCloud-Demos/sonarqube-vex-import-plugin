import React, { useState } from 'react';
import {
  DEFAULT_MAPPING,
  isDefaultMapping,
  MAPPING_TARGETS,
  MappingTarget,
  STATE_LABELS,
  StatusMapping,
  TARGET_LABELS,
  UNDECIDED_STATE_KEYS,
  VEX_STATE_KEYS,
  withUndecided,
} from '../../vex/transitionMapping';
import { thBase, tdStyle } from '../shared/tableUtils';

export interface StatusMappingPanelProps {
  mapping: StatusMapping;
  onMappingChange: (mapping: StatusMapping) => void;
}

type UndecidedChoice = 'SKIP' | 'OPEN' | 'CUSTOM';

function undecidedChoice(mapping: StatusMapping): UndecidedChoice {
  const targets = new Set(UNDECIDED_STATE_KEYS.map((key) => mapping[key]));
  if (targets.size === 1) {
    const only = [...targets][0];
    if (only === 'SKIP' || only === 'OPEN') return only;
  }
  return 'CUSTOM';
}

const radioLabelStyle: React.CSSProperties = { display: 'block', fontSize: '13px', marginBottom: '4px', cursor: 'pointer' };
const linkButtonStyle: React.CSSProperties = {
  background: 'none',
  border: 'none',
  padding: 0,
  color: '#236a97',
  fontSize: '13px',
  cursor: 'pointer',
  textDecoration: 'underline',
};

export function StatusMappingPanel({ mapping, onMappingChange }: Readonly<StatusMappingPanelProps>) {
  const [showTable, setShowTable] = useState(false);
  const choice = undecidedChoice(mapping);

  return (
    <div data-testid="status-mapping-panel">
      <div style={{ fontSize: '13px', fontWeight: 600, marginBottom: '6px' }}>
        Undecided statements (<code>in_triage</code>, missing or unrecognized <code>analysis.state</code>)
      </div>
      <label style={radioLabelStyle}>
        <input
          type="radio"
          name="vex-undecided"
          value="SKIP"
          checked={choice === 'SKIP'}
          onChange={() => onMappingChange(withUndecided(mapping, 'SKIP'))}
        />{' '}
        Don't import them (listed as not importable)
      </label>
      <label style={radioLabelStyle}>
        <input
          type="radio"
          name="vex-undecided"
          value="OPEN"
          checked={choice === 'OPEN'}
          onChange={() => onMappingChange(withUndecided(mapping, 'OPEN'))}
        />{' '}
        Import them as Open (reopens the risk if needed, with the VEX detail as comment)
      </label>
      {choice === 'CUSTOM' && (
        <p style={{ fontSize: '12px', color: '#666', margin: '4px 0 0' }}>Custom - see the full mapping below.</p>
      )}

      <div style={{ marginTop: '10px', fontSize: '13px' }}>
        <button type="button" style={linkButtonStyle} onClick={() => setShowTable(!showTable)} aria-expanded={showTable}>
          {showTable ? 'Hide' : 'Adjust'} the full status mapping
        </button>
        {!isDefaultMapping(mapping) && (
          <>
            {' · '}
            <button type="button" style={linkButtonStyle} onClick={() => onMappingChange({ ...DEFAULT_MAPPING })}>
              Reset to default
            </button>
          </>
        )}
      </div>

      {showTable && (
        <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '8px' }}>
          <thead>
            <tr>
              <th style={thBase}>VEX analysis</th>
              <th style={thBase}>SonarQube status</th>
              <th style={thBase}>Default</th>
            </tr>
          </thead>
          <tbody>
            {VEX_STATE_KEYS.map((key) => (
              <tr key={key}>
                <td style={tdStyle}>
                  <code>{STATE_LABELS[key]}</code>
                </td>
                <td style={tdStyle}>
                  <select
                    aria-label={`Status for ${STATE_LABELS[key]}`}
                    value={mapping[key]}
                    onChange={(e) => onMappingChange({ ...mapping, [key]: e.target.value as MappingTarget })}
                    style={{ padding: '4px 8px', fontSize: '13px', borderRadius: '4px', border: '1px solid #ccc' }}
                  >
                    {MAPPING_TARGETS.map((target) => (
                      <option key={target} value={target}>
                        {TARGET_LABELS[target]}
                      </option>
                    ))}
                  </select>
                </td>
                <td style={{ ...tdStyle, color: '#666' }}>{TARGET_LABELS[DEFAULT_MAPPING[key]]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
