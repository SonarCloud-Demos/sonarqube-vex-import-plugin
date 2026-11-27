import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { DEFAULT_MAPPING, StatusMapping } from '../../vex/transitionMapping';
import { StatusMappingPanel } from './StatusMappingPanel';

function Harness({ onChange }: Readonly<{ onChange: (mapping: StatusMapping) => void }>) {
  const [mapping, setMapping] = useState<StatusMapping>({ ...DEFAULT_MAPPING });
  return (
    <StatusMappingPanel
      mapping={mapping}
      onMappingChange={(next) => {
        setMapping(next);
        onChange(next);
      }}
    />
  );
}

describe('StatusMappingPanel', () => {
  it('starts on "don\'t import" for undecided statements', () => {
    render(<Harness onChange={jest.fn()} />);
    expect(screen.getByRole('radio', { name: /Don't import them/ })).toBeChecked();
    expect(screen.queryByText('Reset to default')).not.toBeInTheDocument();
  });

  it('switches every undecided row to Open with one click', () => {
    const onChange = jest.fn();
    render(<Harness onChange={onChange} />);
    fireEvent.click(screen.getByRole('radio', { name: /Import them as Open/ }));
    const last: StatusMapping = onChange.mock.calls[onChange.mock.calls.length - 1][0];
    expect(last.in_triage).toBe('OPEN');
    expect(last.missing).toBe('OPEN');
    expect(last.unrecognized).toBe('OPEN');
    expect(last.not_affected).toBe('SAFE');
    expect(screen.getByText('Reset to default')).toBeInTheDocument();
  });

  it('lets one row be adjusted in the full table, and shows a custom undecided choice', () => {
    const onChange = jest.fn();
    render(<Harness onChange={onChange} />);
    fireEvent.click(screen.getByRole('button', { name: /Adjust the full status mapping/ }));
    fireEvent.change(screen.getByLabelText('Status for in_triage'), { target: { value: 'OPEN' } });
    expect(onChange.mock.calls[0][0]).toMatchObject({ in_triage: 'OPEN', missing: 'SKIP', unrecognized: 'SKIP' });
    expect(screen.getByText(/Custom - see the full mapping below/)).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /Don't import them/ })).not.toBeChecked();
    expect(screen.getByRole('radio', { name: /Import them as Open/ })).not.toBeChecked();
  });

  it('resets to the default mapping', () => {
    const onChange = jest.fn();
    render(<Harness onChange={onChange} />);
    fireEvent.click(screen.getByRole('radio', { name: /Import them as Open/ }));
    fireEvent.click(screen.getByText('Reset to default'));
    expect(onChange.mock.calls[onChange.mock.calls.length - 1][0]).toEqual(DEFAULT_MAPPING);
    expect(screen.getByRole('radio', { name: /Don't import them/ })).toBeChecked();
  });
});
