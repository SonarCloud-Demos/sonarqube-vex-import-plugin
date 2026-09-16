import React, { useState } from 'react';
import { PlanItem } from '../../vex/assessImport';

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

const primaryButtonStyle: React.CSSProperties = { ...buttonStyle, background: '#166534', color: '#fff' };
const secondaryButtonStyle: React.CSSProperties = { ...buttonStyle, background: '#eee', color: '#333' };

function disabledStyle(style: React.CSSProperties, disabled: boolean): React.CSSProperties {
  return disabled ? { ...style, opacity: 0.5, cursor: 'not-allowed' } : style;
}

const textareaStyle: React.CSSProperties = {
  width: '100%',
  boxSizing: 'border-box',
  padding: '8px 10px',
  fontSize: '13px',
  fontFamily: 'inherit',
  border: '1px solid #ccc',
  borderRadius: '4px',
  resize: 'vertical',
  minHeight: '60px',
};

export interface StepApproveProps {
  finalImportable: PlanItem[];
  userComment: string;
  onUserCommentChange: (value: string) => void;
  applyLoading: boolean;
  applyError: string | null;
  onBack: () => void;
  onApply: () => void;
}

export function StepApprove({
  finalImportable,
  userComment,
  onUserCommentChange,
  applyLoading,
  applyError,
  onBack,
  onApply,
}: Readonly<StepApproveProps>) {
  const [confirmed, setConfirmed] = useState(false);
  const count = finalImportable.length;

  return (
    <div>
      <div style={cardStyle}>
        <p style={{ fontSize: '13px', color: '#444' }}>
          This will change the status of <strong>{count}</strong> dependency risk{count === 1 ? '' : 's'} on
          SonarQube, as shown in the previous step.
        </p>

        <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, margin: '12px 0 6px' }}>
          Additional comment (optional)
        </label>
        <p style={{ fontSize: '12px', color: '#666', margin: '0 0 6px' }}>
          Appended to every imported item's comment, in addition to the justification imported from the VEX
          file.
        </p>
        <textarea
          style={textareaStyle}
          value={userComment}
          disabled={applyLoading}
          onChange={(e) => onUserCommentChange(e.target.value)}
          placeholder="e.g. Imported as part of the Q3 supplier VEX review"
        />

        <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', marginTop: '16px' }}>
          <input type="checkbox" checked={confirmed} disabled={applyLoading} onChange={(e) => setConfirmed(e.target.checked)} />
          I've reviewed the assessment and want to apply these {count} change{count === 1 ? '' : 's'}.
        </label>

        {applyError && <p style={{ fontSize: '13px', color: '#dc2626', marginTop: '8px' }}>Error: {applyError}</p>}
      </div>

      <button style={disabledStyle(secondaryButtonStyle, applyLoading)} onClick={onBack} disabled={applyLoading}>
        Back
      </button>
      <button style={disabledStyle(primaryButtonStyle, !confirmed || applyLoading)} onClick={onApply} disabled={!confirmed || applyLoading}>
        {applyLoading ? 'Applying…' : 'Apply changes'}
      </button>
    </div>
  );
}
