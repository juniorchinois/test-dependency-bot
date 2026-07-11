const { Probot } = require('probot');
const { logger } = require('./utils/logger');
const config = require('./config');
const { scanNPM } = require('./scanners/npm-scanner');
const { scanPip } = require('./scanners/pip-scanner');
const { getCached, setCached } = require('./utils/cache');
const { formatComment, formatErrorComment } = require('./utils/github');

// Bot application
function botApp(app) {
  logger.info('🤖 Dependency Vulnerability Bot starting...');

  // Event handlers
  app.on('pull_request.opened', handlePullRequest);
  app.on('pull_request.synchronize', handlePullRequest);
  app.on('pull_request.reopened', handlePullRequest);
  
  // Optional: Handle PR review comments
  app.on('issue_comment.created', handleComment);

  // Handle push events to scan main branch
  app.on('push', handlePush);

  async function handlePullRequest(context) {
    const { pull_request, repository } = context.payload;
    const { owner, name: repo } = repository;
    
    logger.info(`📥 Processing PR #${pull_request.number} in ${owner.login}/${repo}`);

    try {
      // Check if PR is from a fork
      if (config.skipForks && pull_request.head.repo.fork) {
        logger.info(`⏭️ Skipping fork PR #${pull_request.number}`);
        return;
      }

      // Get changed files
      const files = await context.octokit.pulls.listFiles({
        owner: owner.login,
        repo,
        pull_number: pull_request.number,
        per_page: 100
      });

      const findings = [];
      const manifestFiles = [];

      // Identify manifest files
      for (const file of files.data) {
        if (file.filename === 'package.json' && config.ecosystems.npm) {
          manifestFiles.push({ path: file.filename, type: 'npm' });
        }
        if (file.filename === 'requirements.txt' && config.ecosystems.pip) {
          manifestFiles.push({ path: file.filename, type: 'pip' });
        }
        if (file.filename === 'yarn.lock' && config.ecosystems.yarn) {
          manifestFiles.push({ path: file.filename, type: 'yarn' });
        }
        if (file.filename === 'poetry.lock' && config.ecosystems.poetry) {
          manifestFiles.push({ path: file.filename, type: 'poetry' });
        }
      }

      if (manifestFiles.length === 0) {
        logger.info(`📝 No dependency files changed in PR #${pull_request.number}`);
        return;
      }

      // Scan each manifest file
      for (const manifest of manifestFiles) {
        try {
          const content = await getFileContent(context, manifest.path);
          
          let vulns = [];
          if (manifest.type === 'npm' || manifest.type === 'yarn') {
            vulns = await scanNPM(content, getCached, setCached);
          } else if (manifest.type === 'pip' || manifest.type === 'poetry') {
            vulns = await scanPip(content, getCached, setCached);
          }
          
          findings.push(...vulns);
          
        } catch (error) {
          logger.error(`Error scanning ${manifest.path}:`, error);
        }
      }

      // Filter findings by severity threshold
      const filteredFindings = filterBySeverity(findings, config.severityThreshold);
      
      // Remove ignored packages
      const finalFindings = filteredFindings.filter(
        f => !config.ignoredPackages.includes(f.package)
      );

      // Comment on PR if vulnerabilities found
      if (finalFindings.length > 0) {
        const comment = formatComment(finalFindings, pull_request.number);
        await createOrUpdateComment(context, comment);
        logger.info(`✅ Commented on PR #${pull_request.number} with ${finalFindings.length} vulnerabilities`);
        
        // Add check run status
        await createCheckRun(context, 'dependency-vulnerability-scan', 'failure', finalFindings);
      } else {
        // Optional: Remove old comments if no vulnerabilities
        if (config.removeOldComments) {
          await removeOldComments(context);
        }
        logger.info(`✅ No vulnerabilities found in PR #${pull_request.number}`);
        
        // Add success check run
        await createCheckRun(context, 'dependency-vulnerability-scan', 'success', []);
      }

    } catch (error) {
      logger.error(`❌ Error processing PR #${pull_request.number}:`, error);
      
      // Comment with error message
      const errorComment = formatErrorComment(error.message);
      await context.octokit.issues.createComment({
        owner: owner.login,
        repo,
        issue_number: pull_request.number,
        body: errorComment
      });
      
      // Create error check run
      await createCheckRun(context, 'dependency-vulnerability-scan', 'failure', [], error.message);
    }
  }

  async function handleComment(context) {
    const { comment, issue, repository } = context.payload;
    
    // Check if comment is a command
    if (comment.body.startsWith('/scan')) {
      const prNumber = issue.number;
      const { owner, name: repo } = repository;
      
      logger.info(`🔍 Manual scan triggered for PR #${prNumber}`);
      
      // Create a new PR event context and process
      const prContext = {
        ...context,
        payload: {
          ...context.payload,
          pull_request: {
            number: prNumber,
            head: { sha: issue.pull_request?.head?.sha || 'HEAD' },
            base: { sha: issue.pull_request?.base?.sha || 'main' }
          },
          repository
        }
      };
      
      await handlePullRequest(prContext);
    }
  }

  async function handlePush(context) {
    const { repository, ref } = context.payload;
    
    // Only scan main/default branch
    if (ref !== `refs/heads/${repository.default_branch}`) {
      return;
    }

    logger.info(`📥 Scanning push to ${repository.full_name}`);
    
    // Could add automatic scanning of main branch here
    // For now, just log
    logger.info(`✅ Push scanned: ${repository.full_name}`);
  }

  async function getFileContent(context, filename) {
    const { repository, pull_request } = context.payload;
    try {
      const { data } = await context.octokit.repos.getContent({
        owner: repository.owner.login,
        repo: repository.name,
        path: filename,
        ref: pull_request.head.sha
      });
      
      return Buffer.from(data.content, 'base64').toString('utf-8');
    } catch (error) {
      if (error.status === 404) {
        throw new Error(`File ${filename} not found in PR`);
      }
      throw error;
    }
  }

  async function createOrUpdateComment(context, comment) {
    const { pull_request, repository } = context.payload;
    const { owner, name: repo } = repository;

    // Find existing bot comments
    const comments = await context.octokit.issues.listComments({
      owner: owner.login,
      repo,
      issue_number: pull_request.number
    });

    const botComments = comments.data.filter(
      c => c.user.login === 'github-actions[bot]' || 
           c.user.login === 'dependency-bot[bot]' ||
           c.user.login === (process.env.GITHUB_APP_NAME || 'dependency-bot')
    );

    const botComment = botComments.find(c => 
      c.body.includes('## 🔒 Dependency Vulnerability Scan')
    );

    if (botComment && !config.alwaysCreateNewComment) {
      // Update existing comment
      await context.octokit.issues.updateComment({
        owner: owner.login,
        repo,
        comment_id: botComment.id,
        body: comment
      });
      logger.info(`📝 Updated existing comment on PR #${pull_request.number}`);
    } else {
      // Create new comment
      await context.octokit.issues.createComment({
        owner: owner.login,
        repo,
        issue_number: pull_request.number,
        body: comment
      });
      logger.info(`📝 Created new comment on PR #${pull_request.number}`);
    }
  }

  async function removeOldComments(context) {
    const { pull_request, repository } = context.payload;
    const { owner, name: repo } = repository;

    const comments = await context.octokit.issues.listComments({
      owner: owner.login,
      repo,
      issue_number: pull_request.number
    });

    const botComments = comments.data.filter(
      c => (c.user.login === 'github-actions[bot]' || 
            c.user.login === 'dependency-bot[bot]') && 
           c.body.includes('## 🔒 Dependency Vulnerability Scan')
    );

    for (const comment of botComments) {
      await context.octokit.issues.deleteComment({
        owner: owner.login,
        repo,
        comment_id: comment.id
      });
    }
  }

  async function createCheckRun(context, name, conclusion, findings, errorMessage = null) {
    const { pull_request, repository } = context.payload;
    const { owner, name: repo } = repository;

    try {
      let summary = 'Dependency vulnerability scan completed.';
      let text = '';
      
      if (findings && findings.length > 0) {
        const critical = findings.filter(f => 
          f.vulnerabilities.some(v => v.severity === 'CRITICAL')
        );
        const high = findings.filter(f => 
          f.vulnerabilities.some(v => v.severity === 'HIGH')
        );
        
        summary = `Found ${findings.length} vulnerable dependencies.`;
        text = `Critical: ${critical.length}, High: ${high.length}`;
        
        // Add detailed findings
        for (const finding of findings.slice(0, 5)) {
          text += `\n- ${finding.package}@${finding.currentVersion}`;
          for (const vuln of finding.vulnerabilities) {
            text += `\n  - ${vuln.id}: ${vuln.severity}`;
          }
        }
        
        if (findings.length > 5) {
          text += `\n- ... and ${findings.length - 5} more`;
        }
      } else if (conclusion === 'failure' && errorMessage) {
        summary = 'Scan failed.';
        text = errorMessage;
      } else {
        summary = 'No vulnerabilities found! ✅';
      }

      // Get the SHA from the PR head
      const sha = pull_request.head.sha;

      await context.octokit.checks.create({
        owner: owner.login,
        repo,
        name: name,
        head_sha: sha,
        status: 'completed',
        conclusion: conclusion,
        output: {
          title: summary,
          summary: summary,
          text: text
        }
      });
      
      logger.info(`✅ Check run created: ${name} - ${conclusion}`);
    } catch (error) {
      logger.error('Error creating check run:', error);
    }
  }

  function filterBySeverity(findings, threshold) {
    const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
    const thresholdLevel = severityOrder[threshold] || 0;
    
    return findings.filter(finding => {
      return finding.vulnerabilities.some(v => {
        const level = severityOrder[v.severity] || 0;
        return level >= thresholdLevel;
      });
    });
  }
}

// Export for Probot
module.exports = botApp;

// Export individual functions for testing
// module.exports.handlePullRequest = handlePullRequest;
// module.exports.handleComment = handleComment;