const { scanNPM } = require('../../src/scanners/npm-scanner');
const nock = require('nock');

describe('NPM Scanner', () => {
  let getCache, setCache;

  beforeEach(() => {
    getCache = jest.fn().mockReturnValue(null);
    setCache = jest.fn();
  });

  test('detects vulnerable lodash version', async () => {
    // Mock OSV API response
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, {
        vulns: [{
          id: 'CVE-2020-8203',
          severity: 'CRITICAL',
          summary: 'Prototype Pollution in lodash',
          affected: [{
            ranges: [{
              fixed: ['4.17.21']
            }]
          }]
        }]
      });

    const packageJson = `{
      "dependencies": {
        "lodash": "4.17.20"
      }
    }`;

    const findings = await scanNPM(packageJson, getCache, setCache);
    
    expect(findings.length).toBe(1);
    expect(findings[0].package).toBe('lodash');
    expect(findings[0].vulnerabilities[0].severity).toBe('CRITICAL');
    expect(findings[0].recommendedFix).toBe('4.17.21');
  });

  test('handles packages with no vulnerabilities', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, { vulns: [] });

    const packageJson = `{
      "dependencies": {
        "express": "4.18.2"
      }
    }`;

    const findings = await scanNPM(packageJson, getCache, setCache);
    expect(findings.length).toBe(0);
  });

  test('uses cache when available', async () => {
    const cachedResult = {
      vulnerabilities: [{
        id: 'CVE-2020-8203',
        severity: 'CRITICAL',
        summary: 'Prototype Pollution'
      }],
      timestamp: Date.now()
    };
    getCache = jest.fn().mockReturnValue(cachedResult);

    const packageJson = `{
      "dependencies": {
        "lodash": "4.17.20"
      }
    }`;

    const findings = await scanNPM(packageJson, getCache, setCache);
    expect(findings.length).toBe(1);
    expect(setCache).not.toHaveBeenCalled();
  });
});