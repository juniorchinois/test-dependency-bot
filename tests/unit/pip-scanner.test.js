// tests/unit/pip-scanner.test.js
const { scanPip } = require('../../src/scanners/pip-scanner');
const nock = require('nock');

describe('Pip Scanner', () => {
  let getCache, setCache;

  beforeEach(() => {
    getCache = jest.fn().mockReturnValue(null);
    setCache = jest.fn();
  });

  afterEach(() => {
    nock.cleanAll();
  });

  test('detects vulnerable requests version', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, {
        vulns: [{
          id: 'CVE-2023-1234',
          severity: [{ type: 'CVSS_V3', score: '7.5' }],
          summary: 'Security vulnerability in requests',
          affected: [{
            ranges: [{
              events: [
                { introduced: '0.0.0' },
                { fixed: '2.28.0' }
              ]
            }]
          }],
          references: [{ url: 'https://example.com/advisory' }]
        }]
      });

    const requirementsContent = `requests==2.25.0\nflask==2.0.0`;

    const findings = await scanPip(requirementsContent, getCache, setCache);

    expect(findings.length).toBe(1);
    expect(findings[0].package).toBe('requests');
    expect(findings[0].vulnerabilities[0].severity).toBe('HIGH');
    expect(findings[0].recommendedFix).toBe('2.28.0');
  });

  test('handles packages with no vulnerabilities', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, { vulns: [] });

    const requirementsContent = `django==4.0.0\nflask==2.0.0`;

    const findings = await scanPip(requirementsContent, getCache, setCache);
    expect(findings.length).toBe(0);
  });

  test('parses requirements.txt with comments and blank lines', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, { vulns: [] });

    const requirementsContent = `# This is a comment

requests==2.25.0

# Another comment
flask==2.0.0

`;

    const findings = await scanPip(requirementsContent, getCache, setCache);
    expect(findings.length).toBe(0);
  });

  test('parses requirements.txt with different formats', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, { vulns: [] });

    const requirementsContent = `requests==2.25.0
django>=3.0.0
flask<=2.0.0
pytest>5.0.0
numpy~=1.21.0`;

    const findings = await scanPip(requirementsContent, getCache, setCache);
    expect(findings.length).toBe(0);
  });

  test('uses cache when available', async () => {
    const cachedResult = {
      vulnerabilities: [{
        id: 'CVE-2023-1234',
        severity: 'HIGH',
        summary: 'Security vulnerability'
      }],
      fixedVersion: '2.28.0',
      timestamp: Date.now()
    };
    getCache = jest.fn().mockReturnValue(cachedResult);

    const requirementsContent = `requests==2.25.0`;

    const findings = await scanPip(requirementsContent, getCache, setCache);
    expect(findings.length).toBe(1);
    expect(setCache).not.toHaveBeenCalled();
  });

  test('handles invalid requirements.txt gracefully', async () => {
    const requirementsContent = `invalid format without version
    = without package`;

    const findings = await scanPip(requirementsContent, getCache, setCache);
    expect(findings.length).toBe(0);
  });

  test('respects maxDependencies config', async () => {
    nock('https://api.osv.dev')
      .persist()
      .post('/v1/query')
      .reply(200, { vulns: [] });

    let content = '';
    for (let i = 0; i < 150; i++) {
      content += `package${i}==1.0.0\n`;
    }

    const findings = await scanPip(content, getCache, setCache);
    expect(findings.length).toBe(0);
  }, 15000);

  test('handles API errors gracefully', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(500, { error: 'Internal Server Error' });

    const requirementsContent = `requests==2.25.0`;

    const findings = await scanPip(requirementsContent, getCache, setCache);
    expect(findings.length).toBe(0);
  });

  test('handles environment markers in requirements.txt', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, { vulns: [] });

    const requirementsContent = `requests==2.25.0; python_version >= "3.6"
flask==2.0.0; platform_system != "Windows"`;

    const findings = await scanPip(requirementsContent, getCache, setCache);
    expect(findings.length).toBe(0);
  });
});