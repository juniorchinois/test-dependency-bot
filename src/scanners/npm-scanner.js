const axios = require('axios');
const semver = require('semver');
const { logger } = require('../utils/logger');
const config = require('../config');

class NPMScanner {
  constructor() {
    this.apiClient = axios.create({
      timeout: 60000, // 60 seconds
      headers: {
        'User-Agent': 'Dependency-Vulnerability-Bot/1.0',
        'Content-Type': 'application/json'
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

      const depsToScan = Object.entries(allDeps)
        .slice(0, config.maxDependencies || 100);

      logger.info(`🔍 Scanning ${depsToScan.length} npm dependencies`);

      // Try npm audit API directly (more reliable than OSV)
      for (const [name, version] of depsToScan) {
        const cleanVersion = this.cleanVersion(version);
        if (!cleanVersion) continue;

        const cacheKey = `npm:${name}:${cleanVersion}`;
        const cached = getCache(cacheKey);
        
        if (cached && cached.timestamp > Date.now() - (config.cacheTTL || 86400000)) {
          if (cached.vulnerabilities && cached.vulnerabilities.length > 0) {
            findings.push({
              package: name,
              currentVersion: version,
              vulnerabilities: cached.vulnerabilities,
              recommendedFix: cached.fixedVersion || null
            });
          }
          continue;
        }

        // Try npm audit API
        try {
          const result = await this.checkNpmAudit(name, cleanVersion);
          if (result && result.vulnerabilities && result.vulnerabilities.length > 0) {
            findings.push({
              package: name,
              currentVersion: version,
              vulnerabilities: result.vulnerabilities,
              recommendedFix: result.fixedVersion || null
            });
          }
          setCache(cacheKey, result || { vulnerabilities: [], fixedVersion: null, timestamp: Date.now() });
        } catch (error) {
          logger.debug(`npm audit failed for ${name}: ${error.message}`);
          // Try OSV as fallback
          try {
            const result = await this.checkOSV(name, cleanVersion);
            if (result && result.vulnerabilities && result.vulnerabilities.length > 0) {
              findings.push({
                package: name,
                currentVersion: version,
                vulnerabilities: result.vulnerabilities,
                recommendedFix: result.fixedVersion || null
              });
            }
            setCache(cacheKey, result || { vulnerabilities: [], fixedVersion: null, timestamp: Date.now() });
          } catch (e) {
            logger.debug(`OSV also failed for ${name}`);
          }
        }

        await this.delay(100);
      }

      return findings;
    } catch (error) {
      logger.error('Error scanning package.json:', error);
      return [];
    }
  }

  async checkNpmAudit(name, version) {
    try {
      // Use npm registry audit endpoint
      const response = await this.apiClient.post(
        'https://registry.npmjs.org/-/npm/v1/security/audits',
        {
          name: name,
          version: version
        }
      );

      const vulnerabilities = [];
      if (response.data && response.data.actions) {
        for (const action of response.data.actions) {
          if (action.resolves) {
            for (const resolve of action.resolves) {
              vulnerabilities.push({
                id: resolve.id || 'UNKNOWN',
                severity: this.mapSeverity(resolve.severity),
                summary: resolve.title || 'Vulnerability detected',
                cve: resolve.cve || null,
                fixedVersion: resolve.patch?.versions?.[0] || null,
                source: 'npm-audit',
                references: resolve.references || []
              });
            }
          }
        }
      }

      const fixedVersion = vulnerabilities.length > 0
        ? vulnerabilities[0].fixedVersion
        : null;

      return { vulnerabilities, fixedVersion, timestamp: Date.now() };
    } catch (error) {
      if (error.response?.status === 404) {
        return { vulnerabilities: [], fixedVersion: null, timestamp: Date.now() };
      }
      throw error;
    }
  }

  async checkOSV(name, version) {
    try {
      const response = await this.apiClient.post(
        'https://api.osv.dev/v1/query',
        {
          package: {
            name: name,
            ecosystem: 'npm'
          },
          version: version
        }
      );

      return this.formatOSVResponse(response.data);
    } catch (error) {
      if (error.response?.status === 404) {
        return { vulnerabilities: [], fixedVersion: null, timestamp: Date.now() };
      }
      throw error;
    }
  }

  formatOSVResponse(data) {
    const vulns = data.vulns || [];
    
    const formattedVulns = vulns.map(v => ({
      id: v.id || v.cve || 'UNKNOWN',
      severity: this.mapSeverity(v.severity),
      summary: v.summary || 'No description available',
      cve: v.cve || null,
      fixedVersion: this.extractFixedVersion(v),
      source: 'osv',
      publishedDate: v.published || null,
      references: v.references || []
    }));

    const fixedVersion = this.findLatestFixedVersion(vulns);

    return {
      vulnerabilities: formattedVulns,
      fixedVersion: fixedVersion,
      timestamp: Date.now()
    };
  }

  cleanVersion(version) {
    if (!version) return null;
    const clean = semver.valid(version) || semver.coerce(version);
    return clean ? clean.toString() : null;
  }

  mapSeverity(severity) {
    if (!severity) return 'UNKNOWN';

    const severityMap = {
      'critical': 'CRITICAL',
      'high': 'HIGH',
      'medium': 'MEDIUM',
      'moderate': 'MEDIUM',
      'low': 'LOW',
      'info': 'LOW'
    };

    const key = severity.toString().toLowerCase();
    return severityMap[key] || 'UNKNOWN';
  }

  extractFixedVersion(vuln) {
    const affected = vuln?.affected || [];
    for (const item of affected) {
      const ranges = item?.ranges || [];
      for (const range of ranges) {
        const events = range?.events || [];
        for (const event of events) {
          if (event.fixed) {
            return event.fixed;
          }
        }
      }
    }
    return null;
  }

  findLatestFixedVersion(vulns) {
    const fixedVersions = vulns
      .map(v => this.extractFixedVersion(v))
      .filter(v => v !== null);

    if (fixedVersions.length === 0) return null;

    const sorted = fixedVersions.sort((a, b) => semver.rcompare(a, b));
    return sorted[0];
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = { scanNPM: (...args) => new NPMScanner().scan(...args) };