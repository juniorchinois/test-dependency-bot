// src/utils/github.js
const config = require('../config');

function formatComment(findings, prNumber) {
  // Categorize findings by severity
  const critical = findings.filter(f => f.vulnerabilities.some(v => v.severity === 'CRITICAL'));
  const high = findings.filter(f => f.vulnerabilities.some(v => v.severity === 'HIGH'));
  const medium = findings.filter(f => f.vulnerabilities.some(v => v.severity === 'MEDIUM'));
  const low = findings.filter(f => f.vulnerabilities.some(v => v.severity === 'LOW'));

  let comment = `## 🔒 Dependency Vulnerability Scan\n\n`;
  comment += `**Pull Request**: [#${prNumber}](https://github.com/your-repo/pull/${prNumber})\n`;
  comment += `**Scan Date**: ${new Date().toLocaleString()}\n`;
  comment += `**Threshold**: ${config.severityThreshold}\n\n`;

  if (findings.length === 0) {
    comment += `✅ **No known vulnerabilities found!** Great job! 🎉\n\n`;
    return comment;
  }

  // Critical vulnerabilities
  if (critical.length > 0) {
    comment += `### 🚨 Critical Vulnerabilities Found!\n\n`;
    comment += `| Package | Version | Vulnerability | Fix |\n`;
    comment += `|---------|---------|---------------|-----|\n`;
    for (const finding of critical) {
      const vuln = finding.vulnerabilities.find(v => v.severity === 'CRITICAL');
      if (vuln) {
        comment += `| ${finding.package} | \`${finding.currentVersion}\` | \`${vuln.id}\` | ${vuln.fixedVersion ? `\`${vuln.fixedVersion}\`` : '❌ No fix' } |\n`;
      }
    }
    comment += `\n`;
    comment += formatVulnerabilityDetails(critical);
  }

  // High vulnerabilities
  if (high.length > 0) {
    comment += `### ⚠️ High Severity Vulnerabilities\n\n`;
    comment += `| Package | Version | Vulnerability | Fix |\n`;
    comment += `|---------|---------|---------------|-----|\n`;
    for (const finding of high) {
      const vuln = finding.vulnerabilities.find(v => v.severity === 'HIGH');
      if (vuln) {
        comment += `| ${finding.package} | \`${finding.currentVersion}\` | \`${vuln.id}\` | ${vuln.fixedVersion ? `\`${vuln.fixedVersion}\`` : '❌ No fix' } |\n`;
      }
    }
    comment += `\n`;
    comment += formatVulnerabilityDetails(high);
  }

  // Medium vulnerabilities
  if (medium.length > 0) {
    comment += `### 📊 Medium Severity Vulnerabilities\n\n`;
    comment += `| Package | Version | Vulnerability | Fix |\n`;
    comment += `|---------|---------|---------------|-----|\n`;
    for (const finding of medium) {
      const vuln = finding.vulnerabilities.find(v => v.severity === 'MEDIUM');
      if (vuln) {
        comment += `| ${finding.package} | \`${finding.currentVersion}\` | \`${vuln.id}\` | ${vuln.fixedVersion ? `\`${vuln.fixedVersion}\`` : '❌ No fix' } |\n`;
      }
    }
    comment += `\n`;
    comment += formatVulnerabilityDetails(medium);
  }

  // Low vulnerabilities
  if (low.length > 0) {
    comment += `### ℹ️ Low Severity Vulnerabilities\n\n`;
    comment += `| Package | Version | Vulnerability | Fix |\n`;
    comment += `|---------|---------|---------------|-----|\n`;
    for (const finding of low) {
      const vuln = finding.vulnerabilities.find(v => v.severity === 'LOW');
      if (vuln) {
        comment += `| ${finding.package} | \`${finding.currentVersion}\` | \`${vuln.id}\` | ${vuln.fixedVersion ? `\`${vuln.fixedVersion}\`` : '❌ No fix' } |\n`;
      }
    }
    comment += `\n`;
    comment += formatVulnerabilityDetails(low);
  }

  // Summary
  comment += `---\n`;
  comment += `### 📈 Summary\n\n`;
  comment += `- **Total vulnerable dependencies**: ${findings.length}\n`;
  if (critical.length > 0) comment += `- 🚨 **Critical**: ${critical.length}\n`;
  if (high.length > 0) comment += `- ⚠️ **High**: ${high.length}\n`;
  if (medium.length > 0) comment += `- 📊 **Medium**: ${medium.length}\n`;
  if (low.length > 0) comment += `- ℹ️ **Low**: ${low.length}\n`;

  // Recommended fixes
  if (findings.length > 0) {
    comment += `\n### 🔧 Recommended Actions\n\n`;
    comment += `1. **Update dependencies** to the latest secure versions:\n`;
    comment += `\`\`\`bash\n`;
    
    const uniquePackages = [...new Set(findings.map(f => f.package))];
    for (const pkg of uniquePackages) {
      const finding = findings.find(f => f.package === pkg);
      if (finding.recommendedFix) {
        comment += `npm install ${pkg}@${finding.recommendedFix}\n`;
      } else {
        comment += `# ${pkg} has no known fix, investigate manually\n`;
      }
    }
    comment += `\`\`\`\n`;
    
    comment += `2. **Run audit** to check for other issues:\n`;
    comment += `\`\`\`bash\n`;
    comment += `npm audit fix\n`;
    comment += `\`\`\`\n`;
    
    comment += `3. **Review advisories** for more information:\n`;
    for (const finding of findings.slice(0, 3)) {
      const vuln = finding.vulnerabilities[0];
      if (vuln.references && vuln.references.length > 0) {
        comment += `- [${vuln.id}](${vuln.references[0]})\n`;
      }
    }
    if (findings.length > 3) {
      comment += `- ... and ${findings.length - 3} more advisories\n`;
    }
  }

  comment += `\n---\n`;
  comment += `💡 **Tip**: Run \`depscan\` locally to scan dependencies before pushing.\n`;
  comment += `📚 **Resources**: [OSV Database](https://osv.dev/) | [npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit)\n`;
  comment += `\n---\n`;
  comment += `*🤖 This comment was automatically generated by the Dependency Vulnerability Bot*`;

  return comment;
}

function formatVulnerabilityDetails(findings) {
  let details = '';
  for (const finding of findings) {
    details += `**📦 ${finding.package}** (current: \`${finding.currentVersion}\`)\n`;
    if (finding.recommendedFix) {
      details += `  ✅ **Fix**: Update to \`${finding.recommendedFix}\`\n`;
    }
    for (const vuln of finding.vulnerabilities) {
      details += `  - \`${vuln.id}\`\n`;
      details += `    📝 ${vuln.summary}\n`;
      if (vuln.cve) details += `    🔗 CVE: ${vuln.cve}\n`;
      if (vuln.cvssScore) details += `    📊 CVSS Score: ${vuln.cvssScore}\n`;
      if (vuln.fixedVersion) details += `    ✅ Fixed in: \`${vuln.fixedVersion}\`\n`;
      if (vuln.references && vuln.references.length > 0) {
        const refs = vuln.references.slice(0, 2).join(', ');
        details += `    📚 References: ${refs}\n`;
      }
      details += `    ⚡ Severity: **${vuln.severity}**\n`;
    }
    details += '\n';
  }
  return details;
}

function formatErrorComment(errorMessage) {
  return `## ❌ Error Scanning Dependencies

**Error**: ${errorMessage}

This could be due to:
- Invalid package.json or requirements.txt format
- Network issues connecting to vulnerability databases
- Rate limiting from API services
- Missing required files

**Next Steps**:
1. Check your dependency files for syntax errors
2. Try running the scan again later
3. Ensure the repository contains valid manifest files
4. Contact the bot maintainer if the issue persists

**Manual Scan**:
You can trigger a manual scan by commenting \`/scan\` on this PR.

*🤖 This comment was automatically generated by the Dependency Vulnerability Bot*`;
}

function generateMarkdownTable(findings) {
  if (findings.length === 0) {
    return 'No vulnerabilities found.';
  }
  
  let table = '| Package | Current Version | Severity | Vulnerability | Fixed Version |\n';
  table += '|---------|----------------|----------|---------------|---------------|\n';
  
  for (const finding of findings) {
    for (const vuln of finding.vulnerabilities) {
      const summary = vuln.summary.length > 50 ? vuln.summary.slice(0, 47) + '...' : vuln.summary;
      table += `| ${finding.package} | ${finding.currentVersion} | ${vuln.severity} | ${vuln.id} | ${vuln.fixedVersion || 'N/A'} |\n`;
    }
  }
  return table;
}

function getSeverityEmoji(severity) {
  const emojis = {
    'CRITICAL': '🚨',
    'HIGH': '⚠️',
    'MEDIUM': '📊',
    'LOW': 'ℹ️',
    'UNKNOWN': '❓'
  };
  return emojis[severity] || '❓';
}

function getSeverityColor(severity) {
  const colors = {
    'CRITICAL': '#ff0000',
    'HIGH': '#ff6b6b',
    'MEDIUM': '#ffd93d',
    'LOW': '#6bcb77',
    'UNKNOWN': '#grey'
  };
  return colors[severity] || '#grey';
}

module.exports = { 
  formatComment, 
  formatErrorComment, 
  formatVulnerabilityDetails,
  generateMarkdownTable,
  getSeverityEmoji,
  getSeverityColor
};