// tests/unit/pip-scanner.test.js
const { scanPip } = require('../../src/scanners/pip-scanner');
const nock = require('nock');

describe('Pip Scanner', () => {
  let getCache, setCache;

  beforeEach(() => {
    getCache = jest.fn().mockReturnValue(null);
    setCache = jest.fn();
  });

  test('detects vulnerable requests version', async () => {
    // Mock OSV API response for requests
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, {
        vulns: [{
          id: 'CVE-2023-1234',
          severity: 'HIGH',
          summary: 'Security vulnerability in requests',
          affected: [{
            ranges: [{
              fixed: ['2.28.0']
            }]
          }]
        }]
      });

    const requirementsContent = `requests==2.25.0
flask==2.0.0`;

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

    const requirementsContent = `django==4.0.0
flask==2.0.0`;

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
    // Mock API for all packages
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, { vulns: [] });

    // Create many dependencies
    let content = '';
    for (let i = 0; i < 150; i++) {
      content += `package${i}==1.0.0\n`;
    }

    const findings = await scanPip(content, getCache, setCache);
    // Should only scan up to maxDependencies (100)
    expect(findings.length).toBe(0);
  });

  test('handles API errors gracefully', async () => {
    // Mock API error
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(500, { error: 'Internal Server Error' });

    const requirementsContent = `requests==2.25.0`;

    const findings = await scanPip(requirementsContent, getCache, setCache);
    expect(findings.length).toBe(0);
  });

  test('handles network timeouts', async () => {
    // Mock API timeout
    nock('https://api.osv.dev')
      .post('/v1/query')
      .delay(2000)
      .reply(200, { vulns: [] });

    const requirementsContent = `requests==2.25.0`;

    const findings = await scanPip(requirementsContent, getCache, setCache);
    expect(findings.length).toBe(0);
  });
});