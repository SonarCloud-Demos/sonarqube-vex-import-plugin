import React from 'react';
import { render, screen, within } from '@testing-library/react';
import { AssessmentResult } from '../../vex/assessImport';
import { formatDate } from '../shared/tableUtils';
import { StepAssessment } from './StepAssessment';

const LOG4J = 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1';

function renderStep(assessment: AssessmentResult, mappingDescription = 'default') {
  return render(
    <StepAssessment
      loading={false}
      error={null}
      assessment={assessment}
      mappingDescription={mappingDescription}
      onBack={jest.fn()}
      onNext={jest.fn()}
    />
  );
}

describe('StepAssessment', () => {
  it('lists every entry that needs a decision, not only their count', () => {
    renderStep(
      {
        importable: [],
        blocked: [],
        unchanged: [
          { vulnerabilityId: 'CVE-2021-45046', packageUrl: LOG4J, currentStatus: 'OPEN' },
          { vulnerabilityId: 'CVE-2021-45105', packageUrl: LOG4J, currentStatus: 'OPEN' },
        ],
        conflicts: [
          {
            item: {
              issueReleaseKey: 'key-1',
              vulnerabilityId: 'CVE-2021-44228',
              packageUrl: LOG4J,
              currentStatus: 'ACCEPT',
              transitionKey: 'REOPEN',
              comment: 'Supplier analysis pending.',
            },
            vexReferenceDate: '2020-01-01T00:00:00Z',
            sonarLastChangeDate: '2026-11-27T08:54:08.698Z',
            sonarLastChangeUser: 'jenkins',
          },
        ],
      },
      'in_triage → Open, missing analysis.state → Open, unrecognized analysis.state → Open'
    );

    const conflicts = screen.getByTestId('conflicts-card');
    expect(within(conflicts).getByText(/Needs a decision \(1\)/)).toBeInTheDocument();
    const row = within(conflicts).getByText('CVE-2021-44228').closest('tr') as HTMLElement;
    expect(within(row).getByText(LOG4J)).toBeInTheDocument();
    expect(within(row).getByText('ACCEPT')).toBeInTheDocument();
    expect(within(row).getByText('REOPEN')).toBeInTheDocument();
    expect(within(row).getByText(`${formatDate('2026-11-27T08:54:08.698Z')} by jenkins`)).toBeInTheDocument();
    expect(within(row).getByText(formatDate('2020-01-01T00:00:00Z'))).toBeInTheDocument();

    expect(screen.getByText(/Already Open, no change needed \(2\)/)).toBeInTheDocument();
    expect(screen.getByTestId('mapping-description')).toHaveTextContent('Status mapping: custom (in_triage → Open');
    expect(screen.getByText('No VEX entry was rejected.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled();
  });

  it('shows "(none)" when the VEX file carries no reference date', () => {
    renderStep({
      importable: [],
      blocked: [],
      unchanged: [],
      conflicts: [
        {
          item: {
            issueReleaseKey: 'key-1',
            vulnerabilityId: 'CVE-2021-44228',
            packageUrl: LOG4J,
            currentStatus: 'ACCEPT',
            transitionKey: 'REOPEN',
            comment: 'VEX import: state=in_triage',
          },
          sonarLastChangeDate: '2026-11-27T08:54:08.698Z',
        },
      ],
    });
    const row = within(screen.getByTestId('conflicts-card')).getByText('CVE-2021-44228').closest('tr') as HTMLElement;
    expect(within(row).getByText('(none)')).toBeInTheDocument();
    expect(within(row).getByText(formatDate('2026-11-27T08:54:08.698Z'))).toBeInTheDocument();
  });

  it('has no conflicts card when nothing needs a decision', () => {
    renderStep({
      importable: [],
      blocked: [{ vulnerabilityId: 'CVE-2021-44228', packageUrl: LOG4J, reason: "VEX analysis.state 'in_triage' is not actionable" }],
      conflicts: [],
      unchanged: [],
    });
    expect(screen.queryByTestId('conflicts-card')).not.toBeInTheDocument();
    expect(screen.getByTestId('mapping-description')).toHaveTextContent('Status mapping: default');
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
  });
});
