// tests/unit/npm-scanner.test.js
const { scanNPM } = require('../../src/scanners/npm-scanner');
const nock = require('nock');

describe('NPM Scanner', () => {
  let getCache, setCache;

  beforeEach(() => {
    getCache = jest.fn().mockReturnValue(null);
    setCache = jest.fn();
  });

  afterEach(() => {
    nock.cleanAll();
  });

  test('detects vulnerable lodash version', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, {
        vulns: [
          {
            id: 'GHSA-6p69-7h8v-2x3v',
            summary: 'Prototype pollution in lodash',
            severity: [
              {
                type: 'CVSS_V3',
                score: '9.8'
              }
            ],
            affected: [
              {
                ranges: [
                  {
                    events: [
                      { introduced: '0.0.0' },
                      { fixed: '4.17.21' }
                    ]
                  }
                ]
              }
            ],
            references: [
              { url: 'https://github.com/advisories/GHSA-6p69-7h8v-2x3v' }
            ],
            aliases: ['CVE-2020-8203']
          }
        ]
      });

    const packageJson = JSON.stringify({
      dependencies: {
        lodash: '4.17.20'
      }
    });

    const findings = await scanNPM(packageJson, getCache, setCache);

    expect(findings.length).toBe(1);
    expect(findings[0].package).toBe('lodash');
    expect(findings[0].vulnerabilities[0].severity).toBe('CRITICAL');
    expect(findings[0].recommendedFix).toBe('4.17.21');
    expect(setCache).toHaveBeenCalled();
  });

  test('handles packages with no vulnerabilities', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, { vulns: [] });

    const packageJson = JSON.stringify({
      dependencies: {
        'safe-package': '1.0.0'
      }
    });

    const findings = await scanNPM(packageJson, getCache, setCache);
    expect(findings.length).toBe(0);
  });

  test('uses cache when available', async () => {
    const cachedResult = {
      vulnerabilities: [
        {
          id: 'CVE-2020-8203',
          severity: 'HIGH',
          summary: 'Security vulnerability'
        }
      ],
      fixedVersion: '4.17.21',
      timestamp: Date.now()
    };
    getCache = jest.fn().mockReturnValue(cachedResult);

    const packageJson = JSON.stringify({
      dependencies: {
        lodash: '4.17.20'
      }
    });

    const findings = await scanNPM(packageJson, getCache, setCache);
    expect(findings.length).toBe(1);
    expect(setCache).not.toHaveBeenCalled();
  });

  test('handles invalid package.json gracefully', async () => {
    const packageJson = 'invalid json';
    const findings = await scanNPM(packageJson, getCache, setCache);
    expect(findings.length).toBe(0);
  });

  test('respects maxDependencies config', async () => {
    nock('https://api.osv.dev')
      .persist()
      .post('/v1/query')
      .reply(200, { vulns: [] });

    const deps = {};
    for (let i = 0; i < 150; i++) {
      deps[`package${i}`] = '1.0.0';
    }

    const packageJson = JSON.stringify({
      dependencies: deps
    });

    const findings = await scanNPM(packageJson, getCache, setCache);
    expect(findings.length).toBe(0);
  });

  test('handles API errors gracefully', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(500, { error: 'Internal Server Error' });

    const packageJson = JSON.stringify({
      dependencies: {
        'error-package': '1.0.0'
      }
    });

    const findings = await scanNPM(packageJson, getCache, setCache);
    expect(findings.length).toBe(0);
  });

  test('handles network timeouts', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .delay(2000)
      .reply(200, { vulns: [] });

    const packageJson = JSON.stringify({
      dependencies: {
        'timeout-package': '1.0.0'
      }
    });

    const findings = await scanNPM(packageJson, getCache, setCache);
    expect(findings.length).toBe(0);
  });

  test('parses devDependencies', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, {
        vulns: [
          {
            id: 'CVE-2021-1234',
            summary: 'Vulnerability in dev dependency',
            severity: [{ type: 'CVSS_V3', score: '7.5' }],
            affected: [{ ranges: [{ events: [{ introduced: '0.0.0' }] }] }]
          }
        ]
      });

    const packageJson = JSON.stringify({
      devDependencies: {
        'dev-package': '1.0.0'
      }
    });

    const findings = await scanNPM(packageJson, getCache, setCache);
    expect(findings.length).toBe(1);
  });

  test('handles peerDependencies', async () => {
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, {
        vulns: [
          {
            id: 'CVE-2021-1235',
            summary: 'Vulnerability in peer dependency',
            severity: [{ type: 'CVSS_V3', score: '7.5' }],
            affected: [{ ranges: [{ events: [{ introduced: '0.0.0' }] }] }]
          }
        ]
      });

    const packageJson = JSON.stringify({
      peerDependencies: {
        'peer-package': '1.0.0'
      }
    });

    const findings = await scanNPM(packageJson, getCache, setCache);
    expect(findings.length).toBe(1);
  });
});