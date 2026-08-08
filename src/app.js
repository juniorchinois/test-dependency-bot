// src/app.js - Complete implementation
const { logger } = require('./utils/logger');
const config = require('./config');
const npmScanner = require('./scanners/npm-scanner');
const pipScanner = require('./scanners/pip-scanner');
const { getCached, setCached, initialize: initCache, shutdown: shutdownCache, getCacheStats } = require('./utils/cache');
const { formatComment, formatErrorComment } = require('./utils/github');
const crypto = require('crypto');

function botApp(app, options = {}) {
  initCache();
  logger.info('🤖 Dependency Vulnerability Bot starting...');
  logger.info(`📊 Configuration: ${JSON.stringify({
    severityThreshold: config.severityThreshold,
    cacheTTL: config.cacheTTL / 1000 + 's',
    maxDependencies: config.maxDependencies,
    ecosystems: config.ecosystems,
    skipForks: config.skipForks
  }, null, 2)}`);

  // Health check endpoint
  const healthRouter = typeof options.getRouter === 'function'
    ? options.getRouter('/health')
    : (typeof app.route === 'function' ? app.route('/health') : null);

  if (healthRouter && typeof healthRouter.get === 'function') {
    healthRouter.get((req, res) => {
      const stats = getCacheStats();
      res.json({
        status: 'healthy',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        cache: stats,
        version: require('../package.json').version
      });
    });
  } else {
    logger.warn('Health endpoint not registered: runtime does not expose app.route or getRouter.');
  }

  // Register event handlers
  app.on('pull_request.opened', handlePullRequest);
  app.on('pull_request.synchronize', handlePullRequest);
  app.on('pull_request.reopened', handlePullRequest);
  app.on('issue_comment.created', handleComment);
  app.on('push', handlePush);

  async function handlePullRequest(context) {
    const { pull_request, repository } = context.payload;
    const owner = repository.owner.login;
    const repo = repository.name;
    const prNumber = pull_request.number;

    const startTime = Date.now();
    logger.info(`📥 Processing PR #${prNumber} in ${owner}/${repo}`);

    try {
      // Skip fork PRs if configured
      if (config.skipForks && pull_request.head.repo?.fork) {
        logger.info(`⏭️ Skipping fork PR #${prNumber}`);
        return;
      }

      // Verify webhook signature (Probot handles this, but we add extra logging)
      logger.debug(`🔐 Webhook verified for PR #${prNumber}`);

      // Get changed files
      const files = await context.octokit.pulls.listFiles({
        owner: owner,
        repo: repo,
        pull_number: prNumber,
        per_page: 100
      });

      logger.debug(`📄 Found ${files.data.length} changed files`);

      const manifestFiles = [];
      const fileContents = {};

      // Detect manifest files
      for (const file of files.data) {
        const filename = file.filename;
        if (filename === 'package.json' && config.ecosystems.npm) {
          manifestFiles.push({ path: filename, type: 'npm' });
        } else if (filename === 'requirements.txt' && config.ecosystems.pip) {
          manifestFiles.push({ path: filename, type: 'pip' });
        } else if (filename === 'yarn.lock' && config.ecosystems.yarn) {
          manifestFiles.push({ path: filename, type: 'yarn' });
        } else if (filename === 'poetry.lock' && config.ecosystems.poetry) {
          manifestFiles.push({ path: filename, type: 'poetry' });
        } else if (filename === 'pyproject.toml' && config.ecosystems.poetry) {
          manifestFiles.push({ path: filename, type: 'poetry' });
        }
      }

      if (manifestFiles.length === 0) {
        logger.info(`📝 No dependency files changed in PR #${prNumber}`);
        await createCheckRun(context, 'dependency-vulnerability-scan', 'success', [], 'No dependency files found to scan');
        return;
      }

      logger.info(`🔍 Found ${manifestFiles.length} manifest files to scan`);

      const allFindings = [];
      const scanErrors = [];

      // Scan each manifest file
      for (const manifest of manifestFiles) {
        try {
          logger.debug(`📖 Fetching content for ${manifest.path}`);
          const content = await getFileContent(context, manifest.path);
          fileContents[manifest.path] = content;

          let findings = [];
          if (manifest.type === 'npm' || manifest.type === 'yarn') {
            findings = await npmScanner.scanNPM(content, getCached, setCached);
          } else if (manifest.type === 'pip' || manifest.type === 'poetry') {
            findings = await pipScanner.scanPip(content, getCached, setCached);
          }

          logger.debug(`📊 ${manifest.path}: Found ${findings.length} vulnerabilities`);
          allFindings.push(...findings);
        } catch (error) {
          const errorMsg = `Error scanning ${manifest.path}: ${error.message}`;
          logger.error(errorMsg);
          scanErrors.push({ file: manifest.path, error: error.message });
        }
      }

      // Filter findings by severity threshold
      const filteredFindings = filterBySeverity(allFindings, config.severityThreshold);

      // Remove ignored packages
      const finalFindings = filteredFindings.filter(
        f => !config.ignoredPackages.includes(f.package)
      );

      // Sort findings by severity
      const sortedFindings = sortFindingsBySeverity(finalFindings);

      // Log scan results
      const scanDuration = Date.now() - startTime;
      logger.info(`⏱️ Scan completed in ${scanDuration}ms`);

      // Create or update comment
      if (sortedFindings.length > 0) {
        logger.info(`⚠️ Found ${sortedFindings.length} vulnerabilities in PR #${prNumber}`);
        const comment = formatComment(sortedFindings, prNumber);
        await createOrUpdateComment(context, comment);

        // Create check run with detailed results
        await createCheckRun(
          context,
          'dependency-vulnerability-scan',
          'failure',
          sortedFindings,
          `Found ${sortedFindings.length} vulnerabilities in ${manifestFiles.length} manifest files`
        );

        // Log vulnerability summary
        const criticalCount = sortedFindings.filter(f => f.vulnerabilities.some(v => v.severity === 'CRITICAL')).length;
        const highCount = sortedFindings.filter(f => f.vulnerabilities.some(v => v.severity === 'HIGH')).length;
        const mediumCount = sortedFindings.filter(f => f.vulnerabilities.some(v => v.severity === 'MEDIUM')).length;
        logger.info(`📊 Vulnerability summary: CRITICAL=${criticalCount}, HIGH=${highCount}, MEDIUM=${mediumCount}`);

      } else {
        if (config.removeOldComments) {
          await removeOldComments(context);
        }
        logger.info(`✅ No vulnerabilities found in PR #${prNumber}`);
        await createCheckRun(
          context,
          'dependency-vulnerability-scan',
          'success',
          [],
          'No vulnerabilities found! ✅'
        );
      }

      // If there were scan errors, add a warning
      if (scanErrors.length > 0) {
        const warningComment = `⚠️ **Scan Warnings**\n\nSome files could not be scanned:\n${scanErrors.map(e => `- ${e.file}: ${e.error}`).join('\n')}`;
        await context.octokit.issues.createComment({
          owner: owner,
          repo: repo,
          issue_number: prNumber,
          body: warningComment
        });
      }

    } catch (error) {
      logger.error(`❌ Error processing PR #${prNumber}:`, error);

      // Determine error type for better messaging
      let errorMessage = error.message;
      let userFriendlyMessage = 'An error occurred while scanning dependencies.';

      if (error.status === 403 && error.headers?.['x-ratelimit-remaining'] === '0') {
        const resetTime = new Date(parseInt(error.headers['x-ratelimit-reset']) * 1000);
        userFriendlyMessage = `GitHub API rate limit exceeded. Resets at ${resetTime.toLocaleString()}.`;
      } else if (error.status === 404) {
        userFriendlyMessage = 'Required file not found. Please check your repository structure.';
      } else if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
        userFriendlyMessage = 'Connection timeout. Please try again later.';
      } else if (error.code === 'ENOTFOUND') {
        userFriendlyMessage = 'Network error. Please check your internet connection.';
      }

      const errorComment = formatErrorComment(userFriendlyMessage);
      try {
        await context.octokit.issues.createComment({
          owner: owner,
          repo: repo,
          issue_number: prNumber,
          body: errorComment
        });
      } catch (commentError) {
        logger.error('Failed to create error comment:', commentError);
      }

      await createCheckRun(
        context,
        'dependency-vulnerability-scan',
        'failure',
        [],
        userFriendlyMessage
      );
    }
  }

  async function handleComment(context) {
    const { comment, issue, repository } = context.payload;
    const triggerWords = ['/scan', '/depscan', '/check', '/vulnerability', '@dependency-bot scan'];

    // Check if the comment triggers a scan
    const shouldScan = triggerWords.some(word =>
      comment.body.toLowerCase().includes(word.toLowerCase())
    );

    if (shouldScan) {
      const prNumber = issue.number;
      const owner = repository.owner.login;
      const repo = repository.name;

      logger.info(`🔍 Manual scan triggered for PR #${prNumber} by @${comment.user.login}`);

      try {
        // Get PR details
        const pr = await context.octokit.pulls.get({
          owner: owner,
          repo: repo,
          pull_number: prNumber
        });

        // Create a synthetic PR context
        const prContext = {
          ...context,
          payload: {
            ...context.payload,
            pull_request: {
              number: prNumber,
              head: {
                sha: pr.data.head.sha,
                ref: pr.data.head.ref,
                repo: pr.data.head.repo
              },
              base: {
                sha: pr.data.base.sha,
                ref: pr.data.base.ref
              },
              title: pr.data.title,
              head: pr.data.head,
              base: pr.data.base
            },
            repository: repository
          }
        };

        await handlePullRequest(prContext);

        // Add a response comment
        await context.octokit.issues.createComment({
          owner: owner,
          repo: repo,
          issue_number: prNumber,
          body: `🔄 Scan triggered by @${comment.user.login}. Results will appear shortly.`
        });

      } catch (error) {
        logger.error(`Error handling manual scan for PR #${prNumber}:`, error);
        await context.octokit.issues.createComment({
          owner: owner,
          repo: repo,
          issue_number: prNumber,
          body: `❌ Failed to trigger scan: ${error.message}`
        });
      }
    }
  }

  async function handlePush(context) {
    const { repository, ref } = context.payload;
    const defaultBranch = `refs/heads/${repository.default_branch}`;

    if (ref !== defaultBranch) {
      logger.debug(`Skipping push to non-default branch: ${ref}`);
      return;
    }

    logger.info(`📥 Processing push to ${repository.full_name}`);

    try {
      // Get the commit
      const commit = await context.octokit.git.getCommit({
        owner: repository.owner.login,
        repo: repository.name,
        commit_sha: context.payload.after
      });

      logger.info(`📦 Commit: ${commit.data.message.substring(0, 50)}...`);

      // Optional: Trigger scan on push to main branch
      // Could scan the entire repo or update cache

    } catch (error) {
      logger.error('Error handling push:', error);
    }
  }

  async function getFileContent(context, filename) {
    const { repository, pull_request } = context.payload;

    try {
      const response = await context.octokit.repos.getContent({
        owner: repository.owner.login,
        repo: repository.name,
        path: filename,
        ref: pull_request.head.sha
      });

      if (response.data.encoding === 'base64') {
        return Buffer.from(response.data.content, 'base64').toString('utf-8');
      }

      return response.data.content;
    } catch (error) {
      if (error.status === 404) {
        throw new Error(`File ${filename} not found in PR`);
      }
      throw error;
    }
  }

  async function createOrUpdateComment(context, comment) {
    const { pull_request, repository } = context.payload;
    const owner = repository.owner.login;
    const repo = repository.name;
    const prNumber = pull_request.number;

    try {
      const comments = await context.octokit.issues.listComments({
        owner: owner,
        repo: repo,
        issue_number: prNumber
      });

      // Find existing bot comment
      const botComment = comments.data.find(c => {
        const isBot = c.user.type === 'Bot' ||
          c.user.login === 'github-actions[bot]' ||
          c.user.login === 'dependency-bot[bot]';
        const isRelevant = c.body.includes('## 🔒 Dependency Vulnerability Scan') ||
          c.body.includes('Dependency Vulnerability Scan');
        return isBot && isRelevant;
      });

      if (botComment && !config.alwaysCreateNewComment) {
        await context.octokit.issues.updateComment({
          owner: owner,
          repo: repo,
          comment_id: botComment.id,
          body: comment
        });
        logger.info(`📝 Updated existing comment on PR #${prNumber}`);
      } else {
        await context.octokit.issues.createComment({
          owner: owner,
          repo: repo,
          issue_number: prNumber,
          body: comment
        });
        logger.info(`📝 Created new comment on PR #${prNumber}`);
      }
    } catch (error) {
      logger.error('Error creating/updating comment:', error);
      throw error;
    }
  }

  async function removeOldComments(context) {
    const { pull_request, repository } = context.payload;
    const owner = repository.owner.login;
    const repo = repository.name;
    const prNumber = pull_request.number;

    try {
      const comments = await context.octokit.issues.listComments({
        owner: owner,
        repo: repo,
        issue_number: prNumber
      });

      const botComments = comments.data.filter(c => {
        const isBot = c.user.type === 'Bot' ||
          c.user.login === 'github-actions[bot]' ||
          c.user.login === 'dependency-bot[bot]';
        const isRelevant = c.body.includes('## 🔒 Dependency Vulnerability Scan') ||
          c.body.includes('Dependency Vulnerability Scan');
        return isBot && isRelevant;
      });

      for (const comment of botComments) {
        await context.octokit.issues.deleteComment({
          owner: owner,
          repo: repo,
          comment_id: comment.id
        });
      }
      logger.info(`🗑️ Removed ${botComments.length} old comments from PR #${prNumber}`);
    } catch (error) {
      logger.error('Error removing old comments:', error);
    }
  }

  async function createCheckRun(context, name, conclusion, findings, summaryMessage = null) {
    const { pull_request, repository } = context.payload;
    const owner = repository.owner.login;
    const repo = repository.name;
    const prNumber = pull_request.number;

    try {
      let summary = summaryMessage || 'Dependency vulnerability scan completed.';
      let text = '';

      if (findings && findings.length > 0) {
        // Calculate severity counts
        const critical = findings.filter(f =>
          f.vulnerabilities.some(v => v.severity === 'CRITICAL')
        );
        const high = findings.filter(f =>
          f.vulnerabilities.some(v => v.severity === 'HIGH')
        );
        const medium = findings.filter(f =>
          f.vulnerabilities.some(v => v.severity === 'MEDIUM')
        );
        const low = findings.filter(f =>
          f.vulnerabilities.some(v => v.severity === 'LOW')
        );

        summary = `Found ${findings.length} vulnerable dependencies.`;
        text = `## Vulnerability Summary\n\n`;
        text += `| Severity | Count |\n`;
        text += `|----------|-------|\n`;
        if (critical.length > 0) text += `| 🚨 Critical | ${critical.length} |\n`;
        if (high.length > 0) text += `| ⚠️ High | ${high.length} |\n`;
        if (medium.length > 0) text += `| 📊 Medium | ${medium.length} |\n`;
        if (low.length > 0) text += `| ℹ️ Low | ${low.length} |\n`;
        text += `\n## Affected Packages\n\n`;

        for (const finding of findings.slice(0, 10)) {
          text += `- **${finding.package}**@${finding.currentVersion}\n`;
          for (const vuln of finding.vulnerabilities.slice(0, 3)) {
            text += `  - ${vuln.id}: ${vuln.severity}\n`;
          }
          if (finding.vulnerabilities.length > 3) {
            text += `  - ... and ${finding.vulnerabilities.length - 3} more\n`;
          }
          if (finding.recommendedFix) {
            text += `  - ✅ Fix: Update to ${finding.recommendedFix}\n`;
          }
        }
        if (findings.length > 10) {
          text += `\n... and ${findings.length - 10} more vulnerabilities.`;
        }
      } else if (conclusion === 'failure' && summaryMessage) {
        summary = 'Scan failed.';
        text = summaryMessage;
      } else if (conclusion === 'success') {
        summary = 'No vulnerabilities found! ✅';
        text = 'All dependencies are clean!';
      }

      await context.octokit.checks.create({
        owner: owner,
        repo: repo,
        name: name,
        head_sha: pull_request.head.sha,
        status: 'completed',
        conclusion: conclusion,
        output: {
          title: summary,
          summary: summary,
          text: text.substring(0, 65535) // GitHub limit
        }
      });
      logger.info(`✅ Check run created: ${name} - ${conclusion}`);
    } catch (error) {
      logger.error('Error creating check run:', error);
    }
  }

  function filterBySeverity(findings, threshold) {
    const severityOrder = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'UNKNOWN': 1 };
    const thresholdLevel = severityOrder[threshold] || 0;

    return findings.filter(finding => {
      return finding.vulnerabilities.some(v => {
        const level = severityOrder[v.severity] || 0;
        return level >= thresholdLevel;
      });
    });
  }

  function sortFindingsBySeverity(findings) {
    const severityOrder = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'UNKNOWN': 1 };

    return [...findings].sort((a, b) => {
      const maxSeverityA = Math.max(...a.vulnerabilities.map(v => severityOrder[v.severity] || 0));
      const maxSeverityB = Math.max(...b.vulnerabilities.map(v => severityOrder[v.severity] || 0));
      return maxSeverityB - maxSeverityA;
    });
  }
}

module.exports = botApp;