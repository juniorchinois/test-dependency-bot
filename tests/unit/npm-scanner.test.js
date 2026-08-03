// tests/unit/npm-scanner.test.js
const { scanNPM } = require('../../src/scanners/npm-scanner');
const nock = require('nock');

describe('NPM Scanner', () => {
  let getCache, setCache;

  beforeEach(() => {
    getCache = jest.fn().mockReturnValue(null);
    setCache = jest.fn();
    
    // Mock OSV API
    nock('https://api.osv.dev')
      .post('/v1/query')
      .reply(200, {
        vulns: [
          {
            id: 'GHSA-6p69-7h8v-2x3v',
            summary: 'Prototype pollution in lodash',
            severity: 'CRITICAL',
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
            references: ['https://github.com/advisories/GHSA-6p69-7h8v-2x3v']
          }
        ]
      });
  });

  afterEach(() => {
    nock.cleanAll();
  });

  test('detects vulnerable lodash version', async () => {
    const packageJson = JSON.stringify({
      dependencies: {
        lodash: '4.17.20'
      }
    });

    const findings = await scanNPM(packageJson, getCache, setCache);
    
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].package).toBe('lodash');
    expect(findings[0].vulnerabilities[0].severity).toBe('CRITICAL');
  });
});