import React, { useState } from 'react';
import { render, screen } from '@testing-library/react';
import { BranchInfo } from '../../api/projectBranches';
import { DEFAULT_MAPPING } from '../../vex/transitionMapping';
import { RequestedBranch } from '../../utils/requestedBranch';
import { StepSelectFile } from './StepSelectFile';

jest.mock('../../api/projectBranches', () => ({
  fetchLongLivedBranches: jest.fn(async () => [
    { name: 'main', isMain: true, excludedFromPurge: true },
    { name: 'release-1.0', isMain: false, excludedFromPurge: true },
  ]),
}));

function Harness({ requested }: { requested: RequestedBranch }) {
  const [selected, setSelected] = useState<BranchInfo | null>(null);
  return (
    <StepSelectFile
      projectKey="vex-import-smoke-test"
      requested={requested}
      vexFile={null}
      selectedBranch={selected}
      parseError={null}
      mapping={{ ...DEFAULT_MAPPING }}
      onMappingChange={jest.fn()}
      canProceed={false}
      onFileSelected={jest.fn()}
      onBranchSelected={setSelected}
      onBack={jest.fn()}
      onNext={jest.fn()}
    />
  );
}

describe('StepSelectFile target branch', () => {
  it('pre-selects the branch being browsed', async () => {
    render(<Harness requested={{ branch: 'release-1.0' }} />);
    expect(await screen.findByDisplayValue('release-1.0')).toBeInTheDocument();
    expect(screen.queryByTestId('branch-notice')).not.toBeInTheDocument();
  });

  it('falls back to main, and says so, when browsing a pull request', async () => {
    render(<Harness requested={{ pullRequest: '42' }} />);
    expect(await screen.findByDisplayValue('main (main)')).toBeInTheDocument();
    expect(screen.getByTestId('branch-notice')).toHaveTextContent("You're browsing pull request 42.");
  });
});
