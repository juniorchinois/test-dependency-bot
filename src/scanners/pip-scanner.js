// src/scanners/pip-scanner.js
const axios = require('axios');
const semver = require('semver');
const { logger } = require('../utils/logger');
const config = require('../config');

class PipScanner {
  constructor() {
    this.apiClient = axios.create({
      timeout: config.apiTimeout || 30000,
      headers: {
        'User-Agent': 'Dependency-Vulnerability-Bot/1.0',
        'Content-Type': 'application/json'
      }
    });
    this.severityOrder = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'UNKNOWN': 1 };
    this.retryDelay = config.retryDelay || 1000;
    this.maxRetries = config.maxRetries || 3;
  }

  async scan(requirementsContent, getCache, setCache) {
    const findings = [];
    const startTime = Date.now();

    try {
      const dependencies = this.parseRequirements(requirementsContent);
      if (dependencies.length === 0) {
        logger.info('📦 No dependencies found in requirements.txt');
        return [];
      }

      // Filter ignored packages
      const filteredDeps = dependencies.filter(
        dep => !config.ignoredPackages.includes(dep.name)
      );

      const depsToScan = filteredDeps.slice(0, config.maxDependencies || 100);
      logger.info(`🔍 Scanning ${depsToScan.length} pip dependencies`);

      // Process in batches
      const batchSize = 10;
      const totalBatches = Math.ceil(depsToScan.length / batchSize);

      for (let i = 0; i < depsToScan.length; i += batchSize) {
        const batch = depsToScan.slice(i, i + batchSize);
        const batchNumber = Math.floor(i / batchSize) + 1;

        logger.debug(`📦 Processing batch ${batchNumber}/${totalBatches} (${batch.length} packages)`);

        const batchPromises = batch.map(async (dep) => {
          try {
            return await this.scanDependency(dep, getCache, setCache);
          } catch (error) {
            logger.error(`Error scanning ${dep.name}:`, error.message);
            return null;
          }
        });

        const results = await Promise.allSettled(batchPromises);

        for (const result of results) {
          if (result.status === 'fulfilled' && result.value) {
            findings.push(result.value);
          }
        }

        // Rate limiting between batches
        if (i + batchSize < depsToScan.length) {
          await this.delay(500);
        }
      }

      const uniqueFindings = this.deduplicateFindings(findings);
      const duration = Date.now() - startTime;
      logger.info(`✅ pip scan completed in ${duration}ms, found ${uniqueFindings.length} vulnerabilities`);

      return uniqueFindings;
    } catch (error) {
      logger.error('Error scanning requirements.txt:', error);
      return [];
    }
  }

  async scanDependency(dep, getCache, setCache) {
    const cacheKey = `pip:${dep.name}:${dep.version || 'latest'}`;
    const cached = getCache(cacheKey);

    // Check cache
    if (cached && cached.timestamp > Date.now() - (config.cacheTTL || 86400000)) {
      if (cached.vulnerabilities?.length > 0) {
        logger.debug(`💾 Cache hit for ${dep.name}@${dep.version} (${cached.vulnerabilities.length} vulns)`);
        return {
          package: dep.name,
          currentVersion: dep.version || 'latest',
          vulnerabilities: cached.vulnerabilities,
          recommendedFix: cached.fixedVersion || null,
          severity: cached.severity || null
        };
      }
      return null;
    }

    // Query OSV API
    try {
      const result = await this.checkOSV(dep.name, dep.version);

      // Cache result
      const cacheResult = {
        vulnerabilities: result?.vulnerabilities || [],
        fixedVersion: result?.fixedVersion || null,
        severity: result?.severity || null,
        timestamp: Date.now()
      };
      setCache(cacheKey, cacheResult);

      if (result?.vulnerabilities?.length > 0) {
        return {
          package: dep.name,
          currentVersion: dep.version || 'latest',
          vulnerabilities: result.vulnerabilities,
          recommendedFix: result.fixedVersion || null,
          severity: result.severity || null
        };
      }
      return null;
    } catch (error) {
      logger.error(`Error checking ${dep.name}@${dep.version}:`, error.message);
      // Cache empty result to avoid repeated failures
      setCache(cacheKey, {
        vulnerabilities: [],
        fixedVersion: null,
        severity: null,
        timestamp: Date.now(),
        error: error.message
      });
      return null;
    }
  }

  parseRequirements(content) {
    const lines = content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));

    const dependencies = [];
    const versionPatterns = [
      /^([a-zA-Z0-9\-_.]+)\s*==\s*([0-9.]+)/,
      /^([a-zA-Z0-9\-_.]+)\s*>=\s*([0-9.]+)/,
      /^([a-zA-Z0-9\-_.]+)\s*<=\s*([0-9.]+)/,
      /^([a-zA-Z0-9\-_.]+)\s*~=\s*([0-9.]+)/,
      /^([a-zA-Z0-9\-_.]+)\s*>\s*([0-9.]+)/,
      /^([a-zA-Z0-9\-_.]+)\s*<\s*([0-9.]+)/,
      /^([a-zA-Z0-9\-_.]+)\s*!=\s*([0-9.]+)/,
      /^([a-zA-Z0-9\-_.]+)\s*@\s*([^\s]+)/ // URL-based dependencies
    ];

    for (const line of lines) {
      let matched = false;

      // Skip lines with invalid characters
      if (line.includes(';') && !line.includes('#')) {
        // Handle environment markers
        const cleanLine = line.split(';')[0].trim();
        if (cleanLine) {
          const result = this.parseRequirementLine(cleanLine, versionPatterns);
          if (result) dependencies.push(result);
          matched = true;
        }
        continue;
      }

      const result = this.parseRequirementLine(line, versionPatterns);
      if (result) {
        dependencies.push(result);
        matched = true;
      }

      if (!matched) {
        // Try to extract just the package name
        const nameMatch = line.match(/^([a-zA-Z0-9\-_.]+)/);
        if (nameMatch) {
          dependencies.push({
            name: nameMatch[1],
            version: null,
            original: line
          });
        }
      }
    }
    return dependencies;
  }

  parseRequirementLine(line, patterns) {
    for (const pattern of patterns) {
      const match = line.match(pattern);
      if (match) {
        return {
          name: match[1],
          version: match[2],
          original: line
        };
      }
    }
    return null;
  }

  async checkOSV(name, version) {
    let lastError = null;

    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      try {
        const requestBody = {
          package: {
            name: name,
            ecosystem: 'PyPI'
          }
        };
        if (version) {
          requestBody.version = version;
        }

        const response = await this.apiClient.post(
          config.osvApiUrl || 'https://api.osv.dev/v1/query',
          requestBody,
          {
            timeout: 15000,
            validateStatus: (status) => status < 500
          }
        );

        if (response.status === 429) {
          // Rate limited - wait and retry
          const waitTime = parseInt(response.headers['retry-after']) * 1000 || 5000;
          logger.warn(`⏳ Rate limited for ${name}, waiting ${waitTime}ms`);
          await this.delay(waitTime);
          continue;
        }

        if (response.status === 404) {
          return { vulnerabilities: [], fixedVersion: null, severity: null };
        }

        if (response.status !== 200) {
          throw new Error(`OSV API returned ${response.status}: ${JSON.stringify(response.data)}`);
        }

        const vulns = response.data.vulns || [];
        const formattedVulns = [];
        let bestFix = null;
        let highestSeverity = 'UNKNOWN';
        let highestSeverityScore = 0;

        for (const v of vulns) {
          const severity = this.extractSeverity(v);
          const fixedVersion = this.extractFixedVersion(v);
          const cvssScore = this.extractCVSSScore(v);
          const cve = this.extractCVE(v);

          // Track highest severity
          const severityScore = this.severityOrder[severity] || 0;
          if (severityScore > highestSeverityScore) {
            highestSeverityScore = severityScore;
            highestSeverity = severity;
          }

          // Track best fix
          if (fixedVersion) {
            if (!bestFix) {
              bestFix = fixedVersion;
            } else {
              // Choose the most recent/safe version
              const currentBest = semver.valid(bestFix);
              const newFix = semver.valid(fixedVersion);
              if (currentBest && newFix && semver.gt(newFix, currentBest)) {
                bestFix = fixedVersion;
              }
            }
          }

          formattedVulns.push({
            id: v.id || 'UNKNOWN',
            severity: severity,
            summary: v.summary || v.details || 'No description available',
            cve: cve,
            fixedVersion: fixedVersion,
            cvssScore: cvssScore,
            source: 'osv',
            references: v.references?.map(r => r.url) || [],
            published: v.published || null,
            modified: v.modified || null,
            aliases: v.aliases || []
          });
        }

        return {
          vulnerabilities: formattedVulns,
          fixedVersion: bestFix,
          severity: highestSeverity,
          timestamp: Date.now()
        };

      } catch (error) {
        lastError = error;
        if (attempt < this.maxRetries) {
          const delay = this.retryDelay * Math.pow(2, attempt - 1);
          logger.warn(`⚠️ Retry ${attempt}/${this.maxRetries} for ${name} after ${delay}ms`);
          await this.delay(delay);
        }
      }
    }

    throw lastError || new Error(`Failed to check ${name} after ${this.maxRetries} attempts`);
  }

  extractSeverity(vuln) {
    if (!vuln) return 'UNKNOWN';

    // Check for CVSS scores in severity array
    if (Array.isArray(vuln.severity)) {
      for (const s of vuln.severity) {
        if (s.type && (s.type.includes('CVSS') || s.type.includes('cvss'))) {
          const score = parseFloat(s.score);
          if (!isNaN(score)) {
            if (score >= 9.0) return 'CRITICAL';
            if (score >= 7.0) return 'HIGH';
            if (score >= 4.0) return 'MEDIUM';
            if (score > 0) return 'LOW';
          }
        }
      }
    }

    // Check database_specific
    if (vuln.database_specific) {
      if (vuln.database_specific.severity) {
        const mapped = this.mapSeverity(vuln.database_specific.severity);
        if (mapped !== 'UNKNOWN') return mapped;
      }
      if (vuln.database_specific.cvss) {
        const cvss = vuln.database_specific.cvss;
        const score = cvss.score || cvss.cvss_score || cvss.baseScore;
        if (score) {
          const numScore = parseFloat(score);
          if (!isNaN(numScore)) {
            if (numScore >= 9.0) return 'CRITICAL';
            if (numScore >= 7.0) return 'HIGH';
            if (numScore >= 4.0) return 'MEDIUM';
            if (numScore > 0) return 'LOW';
          }
        }
      }
    }

    // Check aliases for severity patterns
    if (vuln.aliases) {
      for (const alias of vuln.aliases) {
        const upper = alias.toUpperCase();
        if (upper.includes('CRITICAL')) return 'CRITICAL';
        if (upper.includes('HIGH')) return 'HIGH';
        if (upper.includes('MEDIUM') || upper.includes('MODERATE')) return 'MEDIUM';
        if (upper.includes('LOW')) return 'LOW';
      }
    }

    return 'UNKNOWN';
  }

  extractCVSSScore(vuln) {
    if (!vuln) return null;

    if (Array.isArray(vuln.severity)) {
      for (const s of vuln.severity) {
        if (s.type && (s.type.includes('CVSS') || s.type.includes('cvss'))) {
          const score = parseFloat(s.score);
          if (!isNaN(score)) return score;
        }
      }
    }

    if (vuln.database_specific?.cvss) {
      const cvss = vuln.database_specific.cvss;
      const score = cvss.score || cvss.cvss_score || cvss.baseScore;
      const numScore = parseFloat(score);
      if (!isNaN(numScore)) return numScore;
    }

    return null;
  }

  extractCVE(vuln) {
    if (!vuln) return null;

    if (vuln.aliases) {
      const cve = vuln.aliases.find(a => a.startsWith('CVE-'));
      if (cve) return cve;
    }
    if (vuln.id && vuln.id.startsWith('CVE-')) return vuln.id;
    if (vuln.cve) return vuln.cve;
    return null;
  }

  extractFixedVersion(vuln) {
    if (!vuln || !vuln.affected) return null;

    for (const affected of vuln.affected) {
      if (!affected.ranges) continue;
      for (const range of affected.ranges) {
        if (!range.events) continue;
        for (const event of range.events) {
          if (event.fixed) {
            return event.fixed;
          }
        }
      }
    }
    return null;
  }

  mapSeverity(severity) {
    if (!severity) return 'UNKNOWN';
    const map = {
      'critical': 'CRITICAL',
      'high': 'HIGH',
      'medium': 'MEDIUM',
      'moderate': 'MEDIUM',
      'low': 'LOW',
      'none': 'LOW',
      'info': 'LOW'
    };
    return map[String(severity).toLowerCase()] || 'UNKNOWN';
  }

  deduplicateFindings(findings) {
    const unique = new Map();

    for (const finding of findings) {
      if (!unique.has(finding.package)) {
        unique.set(finding.package, {
          ...finding,
          vulnerabilities: [...finding.vulnerabilities]
        });
      } else {
        const existing = unique.get(finding.package);
        // Merge vulnerabilities
        const mergedVulns = [...existing.vulnerabilities, ...finding.vulnerabilities];
        // Deduplicate by ID
        const uniqueVulns = mergedVulns.filter((v, index, self) =>
          index === self.findIndex(t => t.id === v.id)
        );
        existing.vulnerabilities = uniqueVulns;
        // Keep the best fix
        if (finding.recommendedFix && existing.recommendedFix) {
          const v1 = semver.valid(existing.recommendedFix);
          const v2 = semver.valid(finding.recommendedFix);
          if (v1 && v2 && semver.gt(v2, v1)) {
            existing.recommendedFix = finding.recommendedFix;
          }
        } else if (finding.recommendedFix) {
          existing.recommendedFix = finding.recommendedFix;
        }
        // Update severity if needed
        if (finding.severity) {
          const currentScore = this.severityOrder[existing.severity] || 0;
          const newScore = this.severityOrder[finding.severity] || 0;
          if (newScore > currentScore) {
            existing.severity = finding.severity;
          }
        }
      }
    }

    return Array.from(unique.values());
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = { scanPip: (...args) => new PipScanner().scan(...args) };