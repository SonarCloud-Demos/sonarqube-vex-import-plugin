import React, { useEffect, useRef, useState } from 'react';
import { BranchInfo, fetchLongLivedBranches } from '../../api/projectBranches';

const cardStyle: React.CSSProperties = {
  background: '#fff',
  border: '1px solid #e0e0e0',
  borderRadius: '4px',
  padding: '20px 24px',
  marginBottom: '16px',
};

const dropZoneStyle = (dragging: boolean): React.CSSProperties => ({
  border: `2px dashed ${dragging ? '#4b9fd5' : '#ccc'}`,
  borderRadius: '4px',
  padding: '32px',
  textAlign: 'center',
  color: '#666',
  fontSize: '13px',
  background: dragging ? '#eef6fc' : '#fafafa',
  marginBottom: '16px',
});

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

export interface StepSelectFileProps {
  projectKey: string;
  branchLikeName?: string;
  vexFile: File | null;
  selectedBranch: BranchInfo | null;
  parseError: string | null;
  canProceed: boolean;
  onFileSelected: (file: File, rawText: string) => void;
  onBranchSelected: (branch: BranchInfo) => void;
  onBack: () => void;
  onNext: () => void;
}

export function StepSelectFile({
  projectKey,
  branchLikeName,
  vexFile,
  selectedBranch,
  parseError,
  canProceed,
  onFileSelected,
  onBranchSelected,
  onBack,
  onNext,
}: Readonly<StepSelectFileProps>) {
  const [branches, setBranches] = useState<BranchInfo[]>([]);
  const [branchesLoading, setBranchesLoading] = useState(true);
  const [branchesError, setBranchesError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let cancelled = false;
    setBranchesLoading(true);
    fetchLongLivedBranches(projectKey)
      .then((result) => {
        if (cancelled) return;
        setBranches(result);
        const preferred = result.find((b) => b.name === branchLikeName) ?? result.find((b) => b.isMain) ?? result[0];
        if (preferred) onBranchSelected(preferred);
      })
      .catch((e) => !cancelled && setBranchesError(e instanceof Error ? e.message : String(e)))
      .finally(() => !cancelled && setBranchesLoading(false));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectKey]);

  function readFile(file: File) {
    file.text().then((text) => onFileSelected(file, text));
  }

  function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) readFile(file);
  }

  function handleFileInputChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) readFile(file);
  }

  return (
    <div>
      <div style={cardStyle}>
        <label htmlFor="vex-branch-select" style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '6px' }}>
          Target branch
        </label>
        {branchesLoading && <p style={{ fontSize: '13px', color: '#666' }}>Loading branches...</p>}
        {branchesError && <p style={{ fontSize: '13px', color: '#dc2626' }}>Error: {branchesError}</p>}
        {!branchesLoading && !branchesError && (
          <select
            id="vex-branch-select"
            value={selectedBranch?.name ?? ''}
            onChange={(e) => {
              const branch = branches.find((b) => b.name === e.target.value);
              if (branch) onBranchSelected(branch);
            }}
            style={{ padding: '6px 10px', fontSize: '13px', borderRadius: '4px', border: '1px solid #ccc', marginBottom: '16px', minWidth: '240px' }}
          >
            {branches.map((b) => (
              <option key={b.name} value={b.name}>
                {b.name}
                {b.isMain ? ' (main)' : ''}
              </option>
            ))}
          </select>
        )}

        <label htmlFor="vex-file-input" style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '6px' }}>
          VEX file (CycloneDX 1.6 JSON)
        </label>
        <div
          style={dropZoneStyle(dragging)}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
        >
          {vexFile ? (
            <p>
              Selected: <strong>{vexFile.name}</strong>
            </p>
          ) : (
            <p>Drag and drop a VEX file here, or</p>
          )}
          <button style={secondaryButtonStyle} onClick={() => fileInputRef.current?.click()}>
            Choose file
          </button>
          <input
            id="vex-file-input"
            ref={fileInputRef}
            type="file"
            accept=".json,application/json"
            onChange={handleFileInputChange}
            style={{ display: 'none' }}
          />
        </div>

        {parseError && <p style={{ fontSize: '13px', color: '#dc2626' }}>Error: {parseError}</p>}
      </div>

      <button style={secondaryButtonStyle} onClick={onBack}>
        Back
      </button>
      <button style={disabledStyle(primaryButtonStyle, !canProceed)} onClick={onNext} disabled={!canProceed}>
        Next
      </button>
    </div>
  );
}
