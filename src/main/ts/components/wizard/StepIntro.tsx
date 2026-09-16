import React from 'react';

const cardStyle: React.CSSProperties = {
  background: '#fff',
  border: '1px solid #e0e0e0',
  borderRadius: '4px',
  padding: '20px 24px',
  marginBottom: '16px',
  fontSize: '13px',
  color: '#444',
  lineHeight: '1.6',
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

export interface StepIntroProps {
  onNext: () => void;
}

export function StepIntro({ onNext }: Readonly<StepIntroProps>) {
  return (
    <div>
      <div style={cardStyle}>
        <p>
          This wizard imports a <strong>VEX (Vulnerability Exploitability eXchange)</strong> file, in
          CycloneDX 1.6 format, and updates the status of matching SonarQube dependency risks
          (Open, Confirmed, Accepted, Safe, Fixed) to reflect it.
        </p>
        <p>
          <strong>Only dependencies SonarQube actually detected</strong> on the selected project branch can
          be affected. A VEX entry for a component SonarQube hasn't found — or one requesting a status
          transition that isn't valid from the risk's current state — will be listed as not importable in
          the assessment step, with the reason why.
        </p>
        <p>
          The steps are: explain the workflow (this page), select a VEX file and target branch, review an
          assessment of what will and won't change, resolve any conflicts, approve and apply, then see the
          result.
        </p>
        <p>
          If a matched entry's SonarQube status was already changed manually more recently than the VEX
          file's own date — or the file has no date to compare — it's treated as a <strong>conflict</strong>{' '}
          needing your explicit decision, not applied automatically. Most VEX files don't carry that date
          information at all, so if a project has seen much manual triage, expect a fair number of these; a
          dedicated step lets you resolve them individually or all at once.
        </p>
        <p style={{ marginBottom: 0 }}>
          Prefer to run this from a script or CI pipeline instead? Download the companion command-line
          tool, which performs the same import against SonarQube's API:{' '}
          <a href="/static/veximport/vex-import.py" download>
            vex-import.py
          </a>
          .
        </p>
      </div>
      <button style={buttonStyle} onClick={onNext}>
        Next
      </button>
    </div>
  );
}
