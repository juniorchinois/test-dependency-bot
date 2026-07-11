const axios = require('axios');
const semver = require('semver');
const { logger } = require('../utils/logger');
const config = require('../config');

class NPMScanner {
  constructor() {
    this.apiClient = axios.create({
      timeout: config.apiTimeout,
      headers: {
        'User-Agent': 'Dependency-Vulnerability-Bot/1.0'
      }
    });
  }

  async scan(packageJsonContent, getCache, setCache) {
    const findings = [];
    
    try {
      const packageJson = JSON.parse(packageJsonContent);
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies
      };

      // Limit number of dependencies to scan
      const depsToScan = Object.entries(allDeps)
        .slice(0, config.maxDependencies);

      logger.info(`🔍 Scanning ${depsToScan.length} npm dependencies`);

      for (const [name, version] of depsToScan) {
        try {
          const cleanVersion = this.cleanVersion(version);
          if (!cleanVersion) {
            logger.warn(`⚠️ Invalid version for ${name}: ${version}`);
            continue;
          }

          const vulnerability = await this.checkVulnerability(
            name, 
            cleanVersion, 
            getCache, 
            setCache
          );

          if (vulnerability) {
            findings.push({
              package: name,
              currentVersion: version,
              vulnerabilities: vulnerability.vulnerabilities,
              recommendedFix: vulnerability.fixedVersion
            });
          }

          // Add delay to avoid rate limiting
          await this.delay(100);

        } catch (error) {
          logger.error(`Error scanning ${name}:`, error.message);
        }
      }

      return findings;

    } catch (error) {
      logger.error('Error parsing package.json:', error);
      return [];
    }
  }

  async checkVulnerability(name, version, getCache, setCache) {
    const cacheKey = `npm:${name}:${version}`;
    
    // Check cache first
    const cached = getCache(cacheKey);
    if (cached && cached.timestamp > Date.now() - config.cacheTTL) {
      logger.debug(`Cache hit for ${name}@${version}`);
      return cached.vulnerabilities.length > 0 ? cached : null;
    }

    try {
      // Try OSV API first
      const osvResult = await this.checkOSV(name, version);
      
      // If no vulnerabilities found in OSV, try npm audit
      let npmResult = null;
      if (!osvResult || osvResult.vulnerabilities.length === 0) {
        npmResult = await this.checkNPMAudit(name, version);
      }

      const result = {
        vulnerabilities: osvResult?.vulnerabilities || npmResult?.vulnerabilities || [],
        fixedVersion: osvResult?.fixedVersion || npmResult?.fixedVersion || null,
        timestamp: Date.now()
      };

      // Cache the result
      setCache(cacheKey, result);

      return result.vulnerabilities.length > 0 ? result : null;

    } catch (error) {
      logger.error(`Error checking ${name}@${version}:`, error.message);
      return null;
    }
  }

  async checkOSV(name, version) {
    try {
      const response = await this.apiClient.post(config.osvApiUrl, {
        package: {
          name: name,
          ecosystem: 'npm'
        },
        version: version
      });

      const vulns = response.data.vulns || [];
      const formattedVulns = vulns.map(v => ({
        id: v.id || v.cve,
        severity: this.mapSeverity(v.severity),
        summary: v.summary || 'No description available',
        cve: v.cve || null,
        fixedVersion: this.extractFixedVersion(v),
        source: 'osv',
        publishedDate: v.published || null,
        references: v.references || []
      }));

      // Find the latest fixed version
      const fixedVersion = this.findLatestFixedVersion(vulns);

      return {
        vulnerabilities: formattedVulns,
        fixedVersion: fixedVersion
      };

    } catch (error) {
      if (error.response?.status === 404) {
        return { vulnerabilities: [], fixedVersion: null };
      }
      throw error;
    }
  }

  async checkNPMAudit(name, version) {
    try {
      const response = await this.apiClient.get(
        `${config.npmRegistryUrl}/-/npm/v1/security/audits/quick`,
        {
          data: {
            name: name,
            version: version
          }
        }
      );

      // Parse npm audit response
      const vulnerabilities = [];
      if (response.data.actions?.length > 0) {
        for (const action of response.data.actions) {
          if (action.resolves?.length > 0) {
            for (const resolve of action.resolves) {
              vulnerabilities.push({
                id: resolve.id || 'UNKNOWN',
                severity: this.mapSeverity(resolve.severity),
                summary: resolve.title || 'Vulnerability detected',
                cve: resolve.cve || null,
                fixedVersion: resolve.patch?.versions?.[0] || null,
                source: 'npm-audit',
                publishedDate: resolve.published_at || null
              });
            }
          }
        }
      }

      // Extract fixed version
      const fixedVersion = vulnerabilities.length > 0 
        ? vulnerabilities[0].fixedVersion 
        : null;

      return { vulnerabilities, fixedVersion };

    } catch (error) {
      if (error.response?.status === 404) {
        return { vulnerabilities: [], fixedVersion: null };
      }
      throw error;
    }
  }

  cleanVersion(version) {
    if (!version) return null;
    const clean = semver.valid(version) || semver.coerce(version);
    return clean ? clean.toString() : null;
  }

  mapSeverity(severity) {
    const severityMap = {
      'critical': 'CRITICAL',
      'high': 'HIGH',
      'medium': 'MEDIUM',
      'low': 'LOW',
      'moderate': 'MEDIUM',
      'info': 'LOW'
    };
    return severityMap[severity?.toLowerCase()] || 'UNKNOWN';
  }

  extractFixedVersion(vuln) {
    const ranges = vuln?.affected?.[0]?.ranges || [];
    for (const range of ranges) {
      if (range.fixed && range.fixed.length > 0) {
        return range.fixed[0];
      }
    }
    return null;
  }

  findLatestFixedVersion(vulns) {
    const fixedVersions = vulns
      .map(v => this.extractFixedVersion(v))
      .filter(v => v !== null);
    
    if (fixedVersions.length === 0) return null;
    
    // Sort by semver and return the highest
    const sorted = fixedVersions.sort((a, b) => semver.rcompare(a, b));
    return sorted[0];
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = { scanNPM: (...args) => new NPMScanner().scan(...args) };