// tests/integration/bot.test.js
const { Probot, createProbot } = require('probot');
const nock = require('nock');
const botApp = require('../../src/app');

// Mock dependencies
jest.mock('../../src/utils/cache');
jest.mock('../../src/utils/logger');

const { getCached, setCached } = require('../../src/utils/cache');
const { scanNPM } = require('../../src/scanners/npm-scanner');
const { scanPip } = require('../../src/scanners/pip-scanner');

describe('Bot Integration Tests', () => {
  let probot;
  let mockGitHub;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Create a new probot instance
    probot = createProbot({
  id: 123,
  privateKey: `-----BEGIN RSA PRIVATE KEY-----
test-key
-----END RSA PRIVATE KEY-----`,
  secret: 'test-secret'
});

    // Load the bot app
    probot.load(botApp);

    // Setup GitHub mock
    mockGitHub = {
      pulls: {
        listFiles: jest.fn().mockResolvedValue({
          data: [
            { filename: 'package.json' }
          ]
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
      }
    };

    // Setup GitHub API mock
    probot.auth = jest.fn().mockResolvedValue({
      octokit: {
        pulls: mockGitHub.pulls,
        repos: mockGitHub.repos,
        issues: mockGitHub.issues,
        checks: mockGitHub.checks
      }
    });
  });

  test('handles PR with vulnerable dependencies', async () => {
    // Mock scanner to return vulnerabilities
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
        ]
      }
    ]);

    // Mock cache
    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => {});

    // Trigger webhook
    const event = {
      name: 'pull_request',
      payload: {
        action: 'opened',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR'
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

    // Verify scanner was called
    expect(scanNPM).toHaveBeenCalled();
    expect(mockGitHub.issues.createComment).toHaveBeenCalled();
    expect(mockGitHub.checks.create).toHaveBeenCalled();
  });

  test('handles PR with no vulnerabilities', async () => {
    // Mock scanner to return no vulnerabilities
    scanNPM.mockResolvedValue([]);

    // Mock cache
    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => {});

    // Trigger webhook
    const event = {
      name: 'pull_request',
      payload: {
        action: 'opened',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR'
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

    // Verify no comment was created
    expect(mockGitHub.issues.createComment).not.toHaveBeenCalled();
    expect(mockGitHub.checks.create).toHaveBeenCalled();
  });

  test('handles PR with multiple manifest files', async () => {
    // Mock multiple files
    mockGitHub.pulls.listFiles.mockResolvedValue({
      data: [
        { filename: 'package.json' },
        { filename: 'requirements.txt' }
      ]
    });

    // Mock scanners
    scanNPM.mockResolvedValue([
      {
        package: 'lodash',
        currentVersion: '4.17.20',
        vulnerabilities: [{
          id: 'CVE-2020-8203',
          severity: 'CRITICAL',
          summary: 'Prototype Pollution'
        }]
      }
    ]);

    scanPip.mockResolvedValue([
      {
        package: 'requests',
        currentVersion: '2.25.0',
        vulnerabilities: [{
          id: 'CVE-2023-1234',
          severity: 'HIGH',
          summary: 'Security vulnerability'
        }]
      }
    ]);

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => {});

    const event = {
      name: 'pull_request',
      payload: {
        action: 'opened',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR'
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

    // Verify both scanners were called
    expect(scanNPM).toHaveBeenCalled();
    expect(scanPip).toHaveBeenCalled();
    expect(mockGitHub.issues.createComment).toHaveBeenCalled();
  });

  test('handles PR update (synchronize)', async () => {
    // Mock scanner
    scanNPM.mockResolvedValue([
      {
        package: 'lodash',
        currentVersion: '4.17.20',
        vulnerabilities: [{
          id: 'CVE-2020-8203',
          severity: 'CRITICAL',
          summary: 'Prototype Pollution'
        }]
      }
    ]);

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => {});

    const event = {
      name: 'pull_request',
      payload: {
        action: 'synchronize',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR'
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
    // Mock scanner
    scanNPM.mockResolvedValue([
      {
        package: 'lodash',
        currentVersion: '4.17.20',
        vulnerabilities: [{
          id: 'CVE-2020-8203',
          severity: 'CRITICAL',
          summary: 'Prototype Pollution'
        }]
      }
    ]);

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => {});

    const event = {
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
    // Mock scanner to throw error
    scanNPM.mockRejectedValue(new Error('Scanner error'));

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => {});

    const event = {
      name: 'pull_request',
      payload: {
        action: 'opened',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR'
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

    // Should still create comment with error
    expect(mockGitHub.issues.createComment).toHaveBeenCalled();
    expect(mockGitHub.checks.create).toHaveBeenCalled();
  });

  test('handles rate limiting', async () => {
    // Mock rate limit error
    const rateLimitError = new Error('Rate limit exceeded');
    rateLimitError.status = 403;
    rateLimitError.headers = {
      'x-ratelimit-remaining': '0',
      'x-ratelimit-reset': '1234567890'
    };

    // Mock scanner to throw rate limit
    scanNPM.mockRejectedValue(rateLimitError);

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => {});

    const event = {
      name: 'pull_request',
      payload: {
        action: 'opened',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR'
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

    // Should handle gracefully
    expect(mockGitHub.issues.createComment).toHaveBeenCalled();
    expect(mockGitHub.checks.create).toHaveBeenCalled();
  });

  test('respects severity threshold', async () => {
    // Mock scanner with low severity vulnerabilities
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

    // Set high threshold
    process.env.SEVERITY_THRESHOLD = 'HIGH';

    getCached.mockReturnValue(null);
    setCached.mockImplementation(() => {});

    const event = {
      name: 'pull_request',
      payload: {
        action: 'opened',
        pull_request: {
          number: 1,
          head: { sha: 'abc123', ref: 'feature-branch' },
          base: { sha: 'main' },
          title: 'Test PR'
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

    // Should not create comment for LOW severity when threshold is HIGH
    expect(mockGitHub.issues.createComment).not.toHaveBeenCalled();
    expect(mockGitHub.checks.create).toHaveBeenCalled();
  });
});