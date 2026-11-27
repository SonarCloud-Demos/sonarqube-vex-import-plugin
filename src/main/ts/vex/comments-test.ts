import { joinComments } from './comments';

describe('joinComments', () => {
  it('puts the user comment on the next line', () => {
    expect(joinComments('VEX import: state=in_triage', 'VEX Import user Testing')).toBe(
      'VEX import: state=in_triage\nVEX Import user Testing'
    );
  });

  it('trims the user comment', () => {
    expect(joinComments('safe', '  checked by the security team \n')).toBe('safe\nchecked by the security team');
  });

  it('keeps the VEX comment alone when the user comment is empty or blank', () => {
    expect(joinComments('safe', '')).toBe('safe');
    expect(joinComments('safe', '   ')).toBe('safe');
  });
});
