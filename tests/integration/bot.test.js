// tests/integration/bot.test.js
const { Probot, createProbot } = require('probot');
const nock = require('nock');

// Mock dependencies
jest.mock('../../src/utils/cache');
jest.mock('../../src/utils/logger');
jest.mock('../../src/scanners/npm-scanner', () => ({ scanNPM: jest.fn() }));
jest.mock('../../src/scanners/pip-scanner', () => ({ scanPip: jest.fn() }));

const botApp = require('../../src/app');
const { getCached, setCached } = require('../../src/utils/cache');
const { scanNPM } = jest.requireMock('../../src/scanners/npm-scanner');
const { scanPip } = jest.requireMock('../../src/scanners/pip-scanner');

describe('Bot Integration Tests', () => {
  let probot;
  let mockGitHub;

  beforeEach(async () => {
    jest.clearAllMocks();

    // Create a new probot instance
    probot = createProbot({
      id: 123,
      privateKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxTlXmx8x5n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x
8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x
-----END RSA PRIVATE KEY-----`,
      secret: 'test-secret'
    });

    await probot.load(botApp);

    // Setup GitHub mock
    mockGitHub = {
      pulls: {
        listFiles: jest.fn().mockResolvedValue({
          data: [
            { filename: 'package.json' }
          ]
        }),
        get: jest.fn().mockResolvedValue({
          data: {
            head: { sha: 'abc123', ref: 'feature-branch', repo: { fork: false } },
            base: { sha: 'main' },
            title: 'Test PR'
          }
        })
      },
      repos: {
        getContent: jest.fn().mockResolvedValue({
          data: {
            content: Buffer.from(JSON.stringify({
              dependencies: {
                'lodash': '4.17.20'
              }
            })).toString('base64')
          }
        })
      },
      issues: {
        createComment: jest.fn().mockResolvedValue({ data: { id: 1 } }),
        listComments: jest.fn().mockResolvedValue({ data: [] }),
        updateComment: jest.fn().mockResolvedValue({ data: { id: 1 } }),
        deleteComment: jest.fn().mockResolvedValue({})
      },
      checks: {
        create: jest.fn().mockResolvedValue({ data: { id: 1 } })
      },
      git: {
        getCommit: jest.fn().mockResolvedValue({
          data: { message: 'Test commit' }
        })
      },
      hook: {
        before: jest.fn()
      }
    };

    // Setup GitHub API mock for Probot context.octokit
    if (probot.state?.octokit?.auth) {
      probot.state.octokit.auth = jest.fn().mockResolvedValue(mockGitHub);
    }
    probot.auth = jest.fn().mockResolvedValue(mockGitHub);
  });

  test('handles PR with vulnerable dependencies', async () => {
    scanNPM.mockResolvedValue([
      {
        package: 'lodash',
        currentVersion: '4.17.20',
        vulnerabilities: [
          {
            id: 'CVE-2020-8203',
            severity: 'CRITICAL',
            summary: 'Prototype Pollution',
            fixedVersion: '4.17.21'
          }
        ],
        recommendedFix: '4.17.21'
      }
    ]);

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => { });

    const event = {
      name: 'pull_request',
      payload: {
        action: 'opened',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR',
          repo: { fork: false }
        },
        repository: {
          owner: { login: 'test-owner' },
          name: 'test-repo',
          full_name: 'test-owner/test-repo',
          default_branch: 'main'
        }
      }
    };

    await probot.receive(event);

    expect(scanNPM).toHaveBeenCalled();
    expect(mockGitHub.issues.createComment).toHaveBeenCalled();
    expect(mockGitHub.checks.create).toHaveBeenCalled();
  });

  test('handles PR with no vulnerabilities', async () => {
    scanNPM.mockResolvedValue([]);

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => { });

    const event = {
      name: 'pull_request',
      payload: {
        action: 'opened',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR',
          repo: { fork: false }
        },
        repository: {
          owner: { login: 'test-owner' },
          name: 'test-repo',
          full_name: 'test-owner/test-repo',
          default_branch: 'main'
        }
      }
    };

    await probot.receive(event);

    expect(mockGitHub.issues.createComment).not.toHaveBeenCalled();
    expect(mockGitHub.checks.create).toHaveBeenCalled();
  });

  test('handles PR with multiple manifest files', async () => {
    mockGitHub.pulls.listFiles.mockResolvedValue({
      data: [
        { filename: 'package.json' },
        { filename: 'requirements.txt' }
      ]
    });

    scanNPM.mockResolvedValue([
      {
        package: 'lodash',
        currentVersion: '4.17.20',
        vulnerabilities: [{
          id: 'CVE-2020-8203',
          severity: 'CRITICAL',
          summary: 'Prototype Pollution',
          fixedVersion: '4.17.21'
        }],
        recommendedFix: '4.17.21'
      }
    ]);

    scanPip.mockResolvedValue([
      {
        package: 'requests',
        currentVersion: '2.25.0',
        vulnerabilities: [{
          id: 'CVE-2023-1234',
          severity: 'HIGH',
          summary: 'Security vulnerability',
          fixedVersion: '2.28.0'
        }],
        recommendedFix: '2.28.0'
      }
    ]);

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => { });

    const event = {
      name: 'pull_request',
      payload: {
        action: 'opened',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR',
          repo: { fork: false }
        },
        repository: {
          owner: { login: 'test-owner' },
          name: 'test-repo',
          full_name: 'test-owner/test-repo',
          default_branch: 'main'
        }
      }
    };

    await probot.receive(event);

    expect(scanNPM).toHaveBeenCalled();
    expect(scanPip).toHaveBeenCalled();
    expect(mockGitHub.issues.createComment).toHaveBeenCalled();
  });

  test('handles PR update (synchronize)', async () => {
    scanNPM.mockResolvedValue([
      {
        package: 'lodash',
        currentVersion: '4.17.20',
        vulnerabilities: [{
          id: 'CVE-2020-8203',
          severity: 'CRITICAL',
          summary: 'Prototype Pollution',
          fixedVersion: '4.17.21'
        }],
        recommendedFix: '4.17.21'
      }
    ]);

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => { });

    const event = {
      id: 'evt-2',
      name: 'pull_request',
      payload: {
        action: 'synchronize',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR',
          repo: { fork: false }
        },
        repository: {
          owner: { login: 'test-owner' },
          name: 'test-repo',
          full_name: 'test-owner/test-repo',
          default_branch: 'main'
        }
      }
    };

    await probot.receive(event);

    expect(scanNPM).toHaveBeenCalled();
    expect(mockGitHub.issues.createComment).toHaveBeenCalled();
  });

  test('handles manual scan via /scan comment', async () => {
    scanNPM.mockResolvedValue([
      {
        package: 'lodash',
        currentVersion: '4.17.20',
        vulnerabilities: [{
          id: 'CVE-2020-8203',
          severity: 'CRITICAL',
          summary: 'Prototype Pollution',
          fixedVersion: '4.17.21'
        }],
        recommendedFix: '4.17.21'
      }
    ]);

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => { });

    // Mock PR get
    mockGitHub.pulls.get = jest.fn().mockResolvedValue({
      data: {
        head: { sha: 'abc123', ref: 'feature-branch', repo: { fork: false } },
        base: { sha: 'main' },
        title: 'Test PR'
      }
    });

    const event = {
      id: 'evt-3',
      name: 'issue_comment',
      payload: {
        action: 'created',
        comment: {
          body: '/scan',
          user: { login: 'test-user' }
        },
        issue: {
          number: 1,
          pull_request: {
            head: { sha: 'abc123' },
            base: { sha: 'main' }
          }
        },
        repository: {
          owner: { login: 'test-owner' },
          name: 'test-repo',
          full_name: 'test-owner/test-repo',
          default_branch: 'main'
        }
      }
    };

    await probot.receive(event);

    expect(scanNPM).toHaveBeenCalled();
    expect(mockGitHub.issues.createComment).toHaveBeenCalled();
  });

  test('handles scanner errors gracefully', async () => {
    scanNPM.mockRejectedValue(new Error('Scanner error'));

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => { });

    const event = {
      name: 'pull_request',
      payload: {
        action: 'opened',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR',
          repo: { fork: false }
        },
        repository: {
          owner: { login: 'test-owner' },
          name: 'test-repo',
          full_name: 'test-owner/test-repo',
          default_branch: 'main'
        }
      }
    };

    await probot.receive(event);

    expect(mockGitHub.issues.createComment).toHaveBeenCalled();
    expect(mockGitHub.checks.create).toHaveBeenCalled();
  });

  test('respects severity threshold', async () => {
    scanNPM.mockResolvedValue([
      {
        package: 'test-package',
        currentVersion: '1.0.0',
        vulnerabilities: [{
          id: 'TEST-001',
          severity: 'LOW',
          summary: 'Low severity issue'
        }]
      }
    ]);

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => { });

    const event = {
      name: 'pull_request',
      payload: {
        action: 'opened',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR',
          repo: { fork: false }
        },
        repository: {
          owner: { login: 'test-owner' },
          name: 'test-repo',
          full_name: 'test-owner/test-repo',
          default_branch: 'main'
        }
      }
    };

    await probot.receive(event);

    expect(mockGitHub.issues.createComment).not.toHaveBeenCalled();
    expect(mockGitHub.checks.create).toHaveBeenCalled();
  });

  test('skips fork PRs when configured', async () => {
    scanNPM.mockResolvedValue([]);

    const event = {
      id: 'evt-6',
      name: 'pull_request',
      payload: {
        action: 'opened',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR',
          repo: { fork: true }
        },
        repository: {
          owner: { login: 'test-owner' },
          name: 'test-repo',
          full_name: 'test-owner/test-repo',
          default_branch: 'main'
        }
      }
    };

    await probot.receive(event);

    expect(scanNPM).not.toHaveBeenCalled();
    expect(mockGitHub.issues.createComment).not.toHaveBeenCalled();
  });
});