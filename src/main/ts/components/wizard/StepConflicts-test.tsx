import React, { useState } from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { ConflictItem } from '../../vex/assessImport';
import { ConflictResolution, StepConflicts } from './StepConflicts';

function conflict(key: string, cve: string): ConflictItem {
  return {
    item: {
      issueReleaseKey: key,
      vulnerabilityId: cve,
      packageUrl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
      currentStatus: 'ACCEPT',
      transitionKey: 'REOPEN',
      comment: 'VEX import: state=in_triage',
    },
    sonarLastChangeDate: '2026-11-27T08:54:08.698Z',
    sonarLastChangeUser: 'jenkins',
  };
}

function Harness({ onChange }: Readonly<{ onChange?: (m: Map<string, ConflictResolution>) => void }>) {
  const [resolutions, setResolutions] = useState<Map<string, ConflictResolution>>(new Map());
  return (
    <StepConflicts
      conflicts={[conflict('k1', 'CVE-1'), conflict('k2', 'CVE-2')]}
      resolutions={resolutions}
      onResolutionsChange={(next) => {
        setResolutions(next);
        onChange?.(next);
      }}
      onBack={jest.fn()}
      onNext={jest.fn()}
    />
  );
}

function row(cve: string): HTMLElement {
  return screen.getByText(cve).closest('tr') as HTMLElement;
}

describe('StepConflicts', () => {
  it('defaults every row to keep SonarQube, visibly', () => {
    render(<Harness />);
    expect(within(row('CVE-1')).getByRole('radio', { name: 'Keep SonarQube' })).toBeChecked();
    expect(within(row('CVE-2')).getByRole('radio', { name: 'Keep SonarQube' })).toBeChecked();
    expect(screen.getByTestId('conflicts-summary')).toHaveTextContent("0 will get the VEX status, 2 will keep SonarQube's status.");
    expect(screen.getByRole('button', { name: 'Keep SonarQube for all' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: 'Apply VEX to all' })).toHaveAttribute('aria-pressed', 'false');
  });

  it('shows the decision column right after the CVE', () => {
    render(<Harness />);
    const headers = screen.getAllByRole('columnheader').map((h) => h.textContent);
    expect(headers.slice(0, 2)).toEqual(['CVE', 'Decision']);
  });

  it('"Apply VEX to all" visibly selects Apply VEX on every row', () => {
    const onChange = jest.fn();
    render(<Harness onChange={onChange} />);
    fireEvent.click(screen.getByRole('button', { name: 'Apply VEX to all' }));
    expect(within(row('CVE-1')).getByRole('radio', { name: 'Apply VEX' })).toBeChecked();
    expect(within(row('CVE-2')).getByRole('radio', { name: 'Apply VEX' })).toBeChecked();
    expect(screen.getByRole('button', { name: 'Apply VEX to all' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByTestId('conflicts-summary')).toHaveTextContent("2 will get the VEX status, 0 will keep SonarQube's status.");
    expect(onChange.mock.calls[0][0]).toEqual(new Map([['k1', 'apply'], ['k2', 'apply']]));
  });

  it('lets one row differ, and then no bulk button is pressed', () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole('button', { name: 'Apply VEX to all' }));
    fireEvent.click(within(row('CVE-2')).getByRole('radio', { name: 'Keep SonarQube' }));
    expect(screen.getByTestId('conflicts-summary')).toHaveTextContent("1 will get the VEX status, 1 will keep SonarQube's status.");
    expect(screen.getByRole('button', { name: 'Apply VEX to all' })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: 'Keep SonarQube for all' })).toHaveAttribute('aria-pressed', 'false');
  });
});
