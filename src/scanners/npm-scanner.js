// src/scanners/npm-scanner.js
const axios = require('axios');
const semver = require('semver');
const { logger } = require('../utils/logger');
const config = require('../config');

class NPMScanner {
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

  async scan(packageJsonContent, getCache, setCache) {
    const findings = [];
    const startTime = Date.now();

    try {
      const packageJson = JSON.parse(packageJsonContent);
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies,
        ...(packageJson.peerDependencies || {})
      };

      const maxDependencies = Number.isFinite(config.maxDependencies) && config.maxDependencies > 0
        ? config.maxDependencies
        : 100;

      const depsToScan = Object.entries(allDeps)
        .filter(([name]) => !config.ignoredPackages.includes(name))
        .slice(0, maxDependencies);

      if (depsToScan.length === 0) {
        logger.info('📦 No dependencies found in package.json');
        return [];
      }

      logger.info(`🔍 Scanning ${depsToScan.length} npm dependencies`);

      // Process in batches for better performance
      const batchSize = 10;
      const totalBatches = Math.ceil(depsToScan.length / batchSize);

      for (let i = 0; i < depsToScan.length; i += batchSize) {
        const batch = depsToScan.slice(i, i + batchSize);
        const batchNumber = Math.floor(i / batchSize) + 1;

        logger.debug(`📦 Processing batch ${batchNumber}/${totalBatches} (${batch.length} packages)`);

        const batchPromises = batch.map(async ([name, version]) => {
          try {
            return await this.scanDependency(name, version, getCache, setCache);
          } catch (error) {
            logger.error(`Error scanning ${name}:`, error.message);
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
      logger.info(`✅ npm scan completed in ${duration}ms, found ${uniqueFindings.length} vulnerabilities`);

      return uniqueFindings;
    } catch (error) {
      logger.error('Error scanning package.json:', error);
      return [];
    }
  }

  async scanDependency(name, version, getCache, setCache) {
    const cleanVersion = this.cleanVersion(version);
    if (!cleanVersion) {
      logger.debug(`⚠️ Could not parse version for ${name}: ${version}`);
      return null;
    }

    const cacheKey = `npm:${name}:${cleanVersion}`;
    const cached = getCache(cacheKey);

    // Check cache
    if (cached && cached.timestamp > Date.now() - (config.cacheTTL || 86400000)) {
      if (cached.vulnerabilities?.length > 0) {
        logger.debug(`💾 Cache hit for ${name}@${cleanVersion} (${cached.vulnerabilities.length} vulns)`);
        return {
          package: name,
          currentVersion: version,
          vulnerabilities: cached.vulnerabilities,
          recommendedFix: cached.fixedVersion || null,
          severity: cached.severity || null
        };
      }
      return null;
    }

    // Query OSV API
    try {
      const result = await this.checkOSV(name, cleanVersion);

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
          package: name,
          currentVersion: version,
          vulnerabilities: result.vulnerabilities,
          recommendedFix: result.fixedVersion || null,
          severity: result.severity || null
        };
      }
      return null;
    } catch (error) {
      logger.error(`Error checking ${name}@${cleanVersion}:`, error.message);
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

  async checkOSV(name, version) {
    let lastError = null;

    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      try {
        const response = await this.apiClient.post(
          config.osvApiUrl || 'https://api.osv.dev/v1/query',
          {
            package: {
              name: name,
              ecosystem: 'npm'
            },
            version: version
          },
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

          // Track best fix (highest severity with fix)
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
      // Check for CVSS in database_specific
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

  cleanVersion(version) {
    if (!version) return null;
    try {
      // Remove npm-specific prefixes
      const clean = version.replace(/^[~^]/, '');
      // Handle ranges
      if (clean.includes('||') || clean.includes(' - ')) {
        // For complex ranges, try to extract the first valid version
        const parts = clean.split(/[,\s]+/);
        for (const part of parts) {
          const parsed = semver.valid(part) || semver.coerce(part);
          if (parsed) return parsed.toString();
        }
        return null;
      }
      const parsed = semver.valid(clean) || semver.coerce(clean);
      return parsed ? parsed.toString() : null;
    } catch (error) {
      return null;
    }
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

module.exports = { scanNPM: (...args) => new NPMScanner().scan(...args) };