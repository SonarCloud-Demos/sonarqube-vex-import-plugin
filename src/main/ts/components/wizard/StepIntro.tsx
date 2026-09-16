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

const calloutStyle: React.CSSProperties = {
  ...cardStyle,
  background: '#fffbeb',
  border: '1px solid #fde68a',
  color: '#78350f',
};

const headingStyle: React.CSSProperties = {
  fontSize: '14px',
  fontWeight: 700,
  color: '#1a1a1a',
  marginBottom: '8px',
};

const calloutHeadingStyle: React.CSSProperties = {
  ...headingStyle,
  color: '#92400e',
};

const listStyle: React.CSSProperties = {
  margin: '0 0 0 20px',
  padding: 0,
};

const tableStyle: React.CSSProperties = {
  width: '100%',
  borderCollapse: 'collapse',
  fontSize: '12px',
};

const thStyle: React.CSSProperties = {
  textAlign: 'left',
  padding: '6px 10px',
  background: '#f3f4f4',
  borderBottom: '2px solid #ddd',
};

const tdStyle: React.CSSProperties = {
  padding: '6px 10px',
  borderBottom: '1px solid #eee',
  verticalAlign: 'top',
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
        <div style={headingStyle}>What this does</div>
        <p>
          This wizard imports a <strong>VEX (Vulnerability Exploitability eXchange)</strong> file, in
          CycloneDX 1.6 format, and updates the status of matching SonarQube dependency risks (Open,
          Confirmed, Accepted, Safe, Fixed) to reflect it.
        </p>
        <p>
          <strong>Only dependencies SonarQube actually detected</strong> on the selected project branch can
          be affected. A VEX entry for a component SonarQube hasn't found - or one requesting a status
          transition that isn't valid from the risk's current state - will be listed as not importable in
          the assessment step, with the reason why.
        </p>
        <p>
          Along with the status, each entry's <code>analysis.detail</code> (or, if absent,{' '}
          <code>analysis.state</code> and <code>analysis.justification</code>) is written into the status
          change's <strong>comment</strong> - SonarQube has no separate structured field for a VEX
          justification, so this is the only place it ends up. <code>analysis.response</code> also
          decides, for an <code>exploitable</code> entry, whether it becomes Accepted (
          <code>will_not_fix</code> is present) or Confirmed.
        </p>
        <p style={{ marginBottom: 0 }}>
          If the VEX file's <code>metadata.authors</code> or <code>metadata.supplier</code> identify who
          issued it, that contact info is appended to the comment too, as{' '}
          <code>(VEX contact: ...)</code> - so a reviewer looking at the change later knows who to ask
          about the justification, not just what SonarQube itself recorded.
        </p>
      </div>

      <div style={cardStyle}>
        <div style={headingStyle}>Field mapping</div>
        <table style={tableStyle}>
          <thead>
            <tr>
              <th style={thStyle}>CycloneDX field</th>
              <th style={thStyle}>Ends up as</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={tdStyle}>
                <code>vulnerabilities[].id</code> + <code>affects[].ref</code> (resolved via{' '}
                <code>components[].purl</code>)
              </td>
              <td style={tdStyle}>Used only to match a detected risk - never written anywhere</td>
            </tr>
            <tr>
              <td style={tdStyle}>
                <code>analysis.state</code>, <code>analysis.response</code>
              </td>
              <td style={tdStyle}>Status transition (Safe / Fixed / Accepted / Confirmed - see below)</td>
            </tr>
            <tr>
              <td style={tdStyle}>
                <code>analysis.detail</code> or <code>analysis.justification</code>
              </td>
              <td style={tdStyle}>Status-change comment</td>
            </tr>
            <tr>
              <td style={tdStyle}>
                <code>metadata.authors</code>, <code>metadata.supplier</code>
              </td>
              <td style={tdStyle}>
                Appended to the comment as <code>(VEX contact: ...)</code>
              </td>
            </tr>
            <tr>
              <td style={tdStyle}>
                <code>analysis.lastUpdated</code>, <code>analysis.firstIssued</code>,{' '}
                <code>metadata.timestamp</code>
              </td>
              <td style={tdStyle}>VEX reference date - conflict check only, never written to SonarQube</td>
            </tr>
          </tbody>
        </table>
        <table style={{ ...tableStyle, marginTop: '12px' }}>
          <thead>
            <tr>
              <th style={thStyle}>
                <code>analysis.state</code>
              </th>
              <th style={thStyle}>condition</th>
              <th style={thStyle}>SonarQube status</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={tdStyle}>
                <code>not_affected</code>, <code>false_positive</code>
              </td>
              <td style={tdStyle}>-</td>
              <td style={tdStyle}>Safe</td>
            </tr>
            <tr>
              <td style={tdStyle}>
                <code>resolved</code>, <code>resolved_with_pedigree</code>
              </td>
              <td style={tdStyle}>-</td>
              <td style={tdStyle}>Fixed</td>
            </tr>
            <tr>
              <td style={tdStyle}>
                <code>exploitable</code>
              </td>
              <td style={tdStyle}>
                <code>response[]</code> includes <code>will_not_fix</code>
              </td>
              <td style={tdStyle}>Accepted</td>
            </tr>
            <tr>
              <td style={tdStyle}>
                <code>exploitable</code>
              </td>
              <td style={tdStyle}>otherwise</td>
              <td style={tdStyle}>Confirmed</td>
            </tr>
            <tr>
              <td style={tdStyle}>
                <code>in_triage</code>, missing, or unrecognized
              </td>
              <td style={tdStyle}>-</td>
              <td style={tdStyle}>not importable</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div style={cardStyle}>
        <div style={headingStyle}>The steps</div>
        <ol style={listStyle}>
          <li>Explain the workflow (this page).</li>
          <li>Select a VEX file and the target branch.</li>
          <li>Review an assessment of what will and won't change.</li>
          <li>Resolve any conflicts (only shown if there are any - see below).</li>
          <li>Approve and apply.</li>
          <li>See the result.</li>
        </ol>
      </div>

      <div style={calloutStyle}>
        <div style={calloutHeadingStyle}>About dates, and why some entries need your decision</div>
        <p>
          CycloneDX lets a VEX entry carry a date for its own analysis (<code>analysis.lastUpdated</code>,
          or <code>analysis.firstIssued</code> as a fallback) - in principle, "this is our assessment as of
          this date." This wizard reads that date, but <strong>SonarQube itself has no way to store it</strong>:
          neither the underlying status-change API SonarQube offers, nor any other mechanism, accepts a
          caller-supplied date. Every status change is timestamped with the server's clock at the moment
          it's applied - a VEX file's own date can never be written back into SonarQube as a real,
          backdated field. It only ever shows up as plain text inside the change's comment.
        </p>
        <p style={{ marginBottom: 0 }}>
          Because of that, this wizard checks dates <strong>before</strong> writing anything, on your
          behalf: if a matched risk's status was already changed manually in SonarQube more recently than
          the VEX entry's own date - or the entry has no date at all to compare - it's treated as a{' '}
          <strong>conflict</strong> and is <em>not</em> applied automatically. You decide, per entry or all
          at once, whether to keep SonarQube's existing status or apply the VEX's anyway. Most VEX files
          don't carry a date at all, so on a project with much manual triage history, expect to see a fair
          number of these.
        </p>
      </div>

      <div style={calloutStyle}>
        <div style={calloutHeadingStyle}>There is no undo</div>
        <p style={{ marginBottom: 0 }}>
          Once applied, a status change is just another SonarQube status change - there's no "restore
          previous status" API, and importing on a different branch is <em>not</em> a safety net: a status
          change made on another branch does not carry back onto a matching risk that already existed on
          your main branch when that branch merges. If you want to preview an import's effect before
          committing to it on your real branch, run it once against a throwaway, never-merged branch -
          analyzed independently first, since a new branch doesn't inherit main's detected risks for free -
          then apply for real once you're confident in the result.
        </p>
      </div>

      <div style={cardStyle}>
        <div style={headingStyle}>Prefer a script or CI pipeline?</div>
        <p style={{ marginBottom: 0 }}>
          Download the companion command-line tool, which performs the same import - including the same
          conflict checks - directly against SonarQube's API:{' '}
          <a href="/static/veximport/vex-import.py" download>
            vex-import.py
          </a>.
        </p>
      </div>

      <button style={buttonStyle} onClick={onNext}>
        Next
      </button>
    </div>
  );
}
