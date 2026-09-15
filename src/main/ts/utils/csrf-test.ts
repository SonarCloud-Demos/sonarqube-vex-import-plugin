import { getCsrfToken } from './csrf';

describe('getCsrfToken', () => {
  const originalCookie = document.cookie;

  afterEach(() => {
    document.cookie = 'XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  });

  afterAll(() => {
    document.cookie = originalCookie;
  });

  it('returns empty string when no cookie is present', () => {
    expect(getCsrfToken()).toBe('');
  });

  it('extracts and decodes the XSRF-TOKEN cookie', () => {
    document.cookie = 'XSRF-TOKEN=abc%3Ddef';
    expect(getCsrfToken()).toBe('abc=def');
  });

  it('finds the token among other cookies', () => {
    document.cookie = 'foo=bar';
    document.cookie = 'XSRF-TOKEN=my-token';
    document.cookie = 'baz=qux';
    expect(getCsrfToken()).toBe('my-token');
  });
});
